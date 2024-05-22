from scapy.all import *
import hashlib
import sys

# Define the server IP and port
server_ip = "71.19.146.5"
server_port = 8080

# Find the appropriate network interface
interfaces = get_working_ifaces()
if not interfaces:
    print("No available network interfaces found.")
    sys.exit(1)

interface = interfaces[0]  # Use the first available interface

# Create a TCP socket
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_socket.bind((str(interface.addr), 0))  # Bind the socket to the interface IP address

# Construct the initial SYN packet
ip = IP(dst=server_ip)
syn = TCP(sport=RandShort(), dport=server_port, flags="S", seq=RandShort())
syn_packet = ip / syn

# Send the SYN packet
tcp_socket.sendto(bytes(syn_packet), (server_ip, server_port))

# Receive the SYN-ACK packet
syn_ack_packet = tcp_socket.recv(65535)
syn_ack = syn_ack_packet[TCP]

# Construct the ACK packet
ack = TCP(sport=syn_ack.dport, dport=syn_ack.sport, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
ack_packet = ip / ack

# Send the ACK packet
tcp_socket.sendto(bytes(ack_packet), (server_ip, server_port))

# Receive the data packets
received_data = b""
while True:
    data_packet = tcp_socket.recv(65535)
    if data_packet:
        tcp_segment = data_packet[TCP]
        payload = tcp_segment.payload
        if payload:
            received_data += payload.load
        if tcp_segment.flags & 0x01 == 1:  # FIN flag set
            break

# Construct and send the FIN-ACK packet
fin_ack = TCP(sport=tcp_segment.dport, dport=tcp_segment.sport, flags="FA", seq=tcp_segment.ack, ack=tcp_segment.seq + len(payload))
fin_ack_packet = ip / fin_ack
tcp_socket.sendto(bytes(fin_ack_packet), (server_ip, server_port))

# Save the received data to a file
with open("received_data.txt", "wb") as f:
    f.write(received_data)

# Calculate and print the MD5 checksum of the received payload
md5_checksum = hashlib.md5(received_data).hexdigest()
print(f"MD5 (payload) = {md5_checksum}")

# Close the socket
tcp_socket.close()