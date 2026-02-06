#!/usr/bin/env python3
import sys
from scapy.all import Ether, IP, TCP, Raw, sendp

iface   = "veth0"
dst_mac = "00:00:00:00:00:02"
src_ip  = "10.0.0.1"
dst_ip  = "10.0.0.2"
dport   = 443

start = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
count = int(sys.argv[2]) if len(sys.argv) > 2 else 1000  # how many ports to try

pkts = []
for k in range(count):
    sport = start + k
    pkts.append(
        Ether(dst=dst_mac)/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport)/Raw(b"X")
    )

sendp(pkts, iface=iface, verbose=False)
print(f"sent {count} packets: sport {start}..{start+count-1}")
