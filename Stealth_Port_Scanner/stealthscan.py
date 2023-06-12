import time
import logging
from scapy.all import *
import sys

#Performs a stealth scan by sending a TCP request and if a response is given, replies with a RST flag.


def is_up(ip):
	icmp = IP(dst=ip)/ICMP()
	resp = sr1(icmp, timeout=10)
	if resp == None:
		return False
	else:
		return True

def main(*args):
	closed_ports = 0
	open_ports = []
	ip = sys.argv[1]
	start_time = time.time()
	ports = range(1, 1024)
	# Checks to see if IP can be reached
	if is_up(ip):
		for port in ports:
			# Send and receive a TCP packet with the SYN flag
			SYN = sr1(IP(dst=ip)/TCP(dport=port, flags='S'))
			# If the response has SYN and ACK flags, add the port to open_ports and send a RST flag TCP packet back
			if SYN.sprintf('%TCP.flags%') == "SA":
				open_ports.append(port)
				send(IP(dst=ip)/TCP(dport=port, flags='R'))
			# Else increment closed_ports and loop
			else:
				closed_ports += 1
		# Prints open port array, closed port int, and elapsed time
		print("\nOpen ports: " + str(open_ports) + "\n" + str(closed_ports) + " ports are closed.")
		print("Completed in " + str(time.time()-start_time)[:6] + " seconds.")
	else:
		print("Target could not be reached.")

if __name__ == '__main__':
	main()
