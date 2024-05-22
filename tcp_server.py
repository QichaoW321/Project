import os
import socket
import struct
import time
from fcntl import ioctl
from scapy.all import *

# Constants
SERVER_IP = "192.168.31.168"
SERVER_PORT = 8080

# TCP states
LISTEN = 0
SYN_RCVD = 1
ESTABLISHED = 2
FIN_WAIT_1 = 3
FIN_WAIT_2 = 4
TIME_WAIT = 5
CLOSED = 6

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10
PSH = 0x08  # Added PSH flag for sending data

# TCP packet
class TCPPacket:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, seq, ack, flags, window, payload):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.payload = payload
        self.retransmit_timer = None

    def __str__(self):
        return f"TCPPacket(src={self.src_ip}:{self.src_port}, dst={self.dst_ip}:{self.dst_port}, seq={self.seq}, ack={self.ack}, flags={self.flags})"

# TCP server
class TCPServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.state = LISTEN
        self.seq = 0
        self.ack = 0
        self.send_buffer = []
        self.retransmission_queue = []

    def start(self):
        try:
            # Create raw socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.bind((self.ip, 0))

            # Block RST packets from the kernel
            block_rst_cmd = f"sudo /sbin/pfctl -e -f /dev/stdin <<EOF\nblock out proto tcp from any to any flags R/R\nEOF"
            os.system(block_rst_cmd)

            print(f"[*] TCP server started on {self.ip}:{self.port}")

            while True:
                packet = self.recv_packet()
                self.handle_packet(packet)

        except socket.error as e:
            print(f"Socket error: {e}")
            self.send_error_response("Socket error")

        except Exception as e:
            print(f"Error: {e}")
            self.send_error_response("Internal server error")

    def recv_packet(self):
        try:
            packet = self.sock.recvfrom(65535)[0]
            ip_header = packet[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            ihl = iph[0] & 0xF
            ip_header_length = ihl * 4
            tcp_header = packet[ip_header_length:ip_header_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            src_port = tcph[0]
            dst_port = tcph[1]
            seq = tcph[2]
            ack = tcph[3]
            flags = tcph[5]
            window = tcph[6]
            payload = packet[ip_header_length+tcph[4]:]

            return TCPPacket(src_ip, src_port, dst_ip, dst_port, seq, ack, flags, window, payload)

        except struct.error as e:
            print(f"Struct error: {e}")
            self.send_error_response("Invalid packet")

    def send_packet(self, packet):
        try:
            ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(packet.payload), 0, 0, 0x40, 6, 0, socket.inet_aton(packet.src_ip), socket.inet_aton(packet.dst_ip))
            tcp_header = struct.pack('!HHLLBBHHH', packet.src_port, packet.dst_port, packet.seq, packet.ack, 0x50, packet.flags, packet.window, 0, 0)
            data = ip_header + tcp_header + packet.payload

            print(f"[*] Sending packet payload: {packet.payload}")  # Log packet payload
            self.sock.sendto(data, (packet.dst_ip, 0))
            print(f"[>] Sent: {packet}")

        except socket.error as e:
            print(f"Socket error: {e}")
            self.send_error_response("Socket error")

    def handle_packet(self, packet):
        try:
            if self.state == LISTEN:
                if packet.flags & SYN:
                    print("[*] Received SYN packet, sending SYN-ACK")
                    self.seq = 0
                    self.ack = packet.seq + 1
                    synack_packet = TCPPacket(self.ip, self.port, packet.src_ip, packet.src_port, self.seq, self.ack, SYN | ACK, 29200, b'')
                    self.send_packet(synack_packet)
                    self.state = SYN_RCVD

            elif self.state == SYN_RCVD:
                if packet.flags & ACK and packet.ack == self.seq + 1:
                    print("[*] Received ACK, connection established")
                    self.state = ESTABLISHED
                    self.send_response()
                else:
                    print("[!] Expected ACK, but received unexpected packet")

            elif self.state == ESTABLISHED:
                print(f"[*] Server in ESTABLISHED state")
                if packet.flags & ACK:
                    print("[*] Received ACK, handling ACK")
                    self.handle_ack(packet.ack)
                if packet.flags & FIN:
                    print("[*] Received FIN, sending FIN-ACK")
                    self.ack = packet.seq + 1
                    finack_packet = TCPPacket(self.ip, self.port, packet.src_ip, packet.src_port, self.seq, self.ack, FIN | ACK, 29200, b'')
                    self.send_packet(finack_packet)
                    self.state = FIN_WAIT_1
                else:
                    print("[!] Unexpected packet in ESTABLISHED state")

            elif self.state == FIN_WAIT_1:
                if packet.flags & ACK:
                    print("[*] Received ACK in FIN_WAIT_1 state")
                    self.state = FIN_WAIT_2

            elif self.state == FIN_WAIT_2:
                if packet.flags & FIN:
                    print("[*] Received FIN in FIN_WAIT_2 state, sending ACK")
                    self.ack = packet.seq + 1
                    ack_packet = TCPPacket(self.ip, self.port, packet.src_ip, packet.src_port, self.seq, self.ack, ACK, 29200, b'')
                    self.send_packet(ack_packet)
                    self.state = TIME_WAIT
                    time.sleep(2)  # Wait for 2 seconds in TIME_WAIT state
                    self.state = CLOSED
                    print("[*] Connection closed")

        except Exception as e:
            print(f"Error: {e}")
            self.send_error_response("Error handling packet")

    def send_response(self):
        try:
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\n\r\nHello, Client!"
            packet = TCPPacket(self.ip, self.port, packet.src_ip, packet.src_port, self.seq, self.ack, ACK | PSH, 29200, response)
            print(f"[>] Sending packet: {packet}")
            self.send_buffer.append(packet)
            self.seq += len(response)

            self.transmit_packets()

        except Exception as e:
            print(f"Error: {e}")
            self.send_error_response("Error sending response")

    def transmit_packets(self):
        for packet in self.send_buffer:
            self.send_packet(packet)
            print(f"[>] Sent packet: {packet}")
            packet.retransmit_timer = time.time()
            self.retransmission_queue.append(packet)

        self.send_buffer.clear()

    def handle_ack(self, ack):
        while self.retransmission_queue:
            packet = self.retransmission_queue[0]
            if packet.seq + len(packet.payload) <= ack:
                self.retransmission_queue.pop(0)
            else:
                break

    def check_retransmission_queue(self):
        current_time = time.time()
        for packet in self.retransmission_queue:
            if current_time - packet.retransmit_timer > 1:
                self.send_packet(packet)
                packet.retransmit_timer = current_time

    def send_error_response(self, error_message):
        error_response = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {len(error_message)}\r\n\r\n{error_message}"
        error_packet = TCPPacket(self.ip, self.port, packet.dst_ip, packet.dst_port, self.seq, self.ack, ACK | PSH, 29200, error_response.encode())
        self.send_packet(error_packet)

# Main
def main():
    server = TCPServer(SERVER_IP, SERVER_PORT)
    server.start()

if __name__ == "__main__":
    main()