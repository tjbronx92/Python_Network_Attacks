#!/usr/bin/python3

from scapy.all import sniff, ARP
from signal import signal, SIGINT
import sys


arp_watcher_db_file = "/var/cache/arp-watcher.db"
ip_mac = {}

#   Save ARP table on user-interrupt
def sig_int_handler(signum, frame):
    print("Got SIGINT... Saving ARP database")
    try:
        f = open(arp_watcher_db_file, "w")

        for (IP, mac) in ip_mac.items():
            f.write(ip + " " + mac + "\n")
            f.close()
            print("Done.")
    except IOError:
        print("[*]ERROR: Cannot write file " + arp_watcher_db_file)
    sys.exit(1)

def watch_arp(pkt):
    #If is-at pakt recieved (ARP Respnse)
    if pkt[ARP].op == 2: # is-at (response)
        print(pkt[ARP].hwsrc + " " + pkt[ARP].psrc)

        #   Remember NEW Device
        if ip_mac.get(pkt[ARP].psrc) == None:
            print("Found new device" + pkt[ARP].hwsrc + " " + pkt[ARP].psrc)
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

        #   Known Device with different IP
        elif ip_mac.get(pkt[ARP].psrc) and ip_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
            print(pkt[ARP].hwsrc + " has got new ip " pkt[ARP].psrc + " (old " + ip_mac[pkt[ARP].psrc] + ")")
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

signal(SIGINT, sig_int_handler)

if len(sys.argv) < 2:
    print(sys.asgrv[0] "requires" " <iface>!!!")
    sys.exit(0)

try:
    fh = open(arp_watcher_db_file, "r")
except IOError:
    print("Cannot read file: " + arp_watcher_db_file)
    sys.exit(1)

for line in fh:
    line.chomp()
    (ip, mac) = line.split(" ")
    ip_mac[IP] = mac

sniff(prn=watch_arp,
      filter="arp",
      iface=sys.argv[1],
      store=0)