from scapy.all import *
import sys

# This tool scours a pcap file and detects for change in the arp table, giving a warning for if one is found, indicating a possible ARP poisoning attack	
def main(*args):
	pkts = sys.argv[1]
	ipdict = {}
	for p in pkts:
		if p.haslayer(ARP):
			# Focusing only on ARP reply packets
			if p.op == 2:
				# save source ip and mac address of the ARP packet
				ip = p.psrc
				mac = p.hwsrc
				if ip in ipdict:
				# If IP-MAC pair alrady exists in the ARP dictionary, do nothing
					if ipdict[ip] == mac:
						break
						# If the IP tries to change its MAC definition in the dictionary, throw a warning
					else:
						print("\033[1;31;40m[!] ARP poisoning detected! \033[1;37;40m" + mac + " tried to claim ip " + ip + " already claimed by " + ipdict[ip])
					# If IP is not found in the dictionary, add it
				else:
					ipdict[ip] = mac
					
if __name__ == "__main__":
	main()
	

