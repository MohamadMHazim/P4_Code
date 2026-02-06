#!/usr/bin/python

import os
import sys

if os.getuid() != 0:
    print("""
ERROR: This script requires root privileges.
       Use 'sudo' to run it.
""")
    quit()

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.0.2"

try:
    iface = sys.argv[2]
except:
    iface = "ens192"

try:
    msg = sys.argv[3]
except:
    msg = "This is a test message"

if ip_dst == "10.0.0.2" or ip_dst == "192.168.0.2":
    mac_dst = "00:00:00:00:00:02"
elif ip_dst == "20.0.0.1":
    mac_dst = "00:00:00:00:00:03"  # assume mac address of Tofino model veth0
else:
    mac_dst = "ff:ff:ff:ff:ff:ff"

print "Sending IP packet to", ip_dst
p = (Ether(dst=mac_dst)/
     IP(dst=ip_dst, src="10.0.0.1")/
     TCP(sport=8, dport=8)/
     msg)

sendp(p, iface=iface)
