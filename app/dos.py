from scapy.all import *

# Define IP layer
ip = IP(dst="10.0.1.3")

# Define TCP SYN packet
syn = TCP(sport=45922,dport=8080, flags="S", seq=1000)

# Send SYN packet and receive SYN-ACK response
syn_ack = sr1(ip/syn)

# Extract the acknowledgment number from the SYN-ACK response
ack_num = syn_ack.seq + 1

# Define TCP ACK packet
ack = TCP(dport=8080, sport=syn_ack.dport, flags="A", seq=syn_ack.ack, ack=ack_num)

# Send ACK packet to complete the TCP handshake
send(ip/ack)