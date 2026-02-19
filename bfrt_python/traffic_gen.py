#!/usr/bin/env python3
"""
Run multiple traffic cases (IPv4 TCP/UDP + optional IPv6 TCP) to exercise different buckets.
- Default: L3 send (kernel routing). No interface required.
- Optional: L2 send (Ethernet frames) by enabling USE_L2 and setting IFACE.
"""

import os
import time
import random
from scapy.all import IP, IPv6, TCP, UDP, Raw, Ether, send, sendp, get_if_hwaddr, conf

# =========================
# USER SETTINGS (edit these)
# =========================

DST_IPV4 = "10.0.0.2"        # destination IPv4
DST_IPV6 = ""               # optional, e.g. "2001:db8::2" (leave empty to skip IPv6 test)

DPORT_TCP = 5001
DPORT_UDP = 5002
DPORT_TCP_V6 = 5003

COUNT = 2000                # packets per case
PPS = 1000                  # packets per second (0 = as fast as possible)
PAYLOAD_LEN = 200           # bytes

# L2 mode: forces sending out a specific interface using sendp()
USE_L2 = False              # set True if you want strict L2 injection
IFACE = "veth0"             # used only when USE_L2=True

# =========================
# INTERNALS
# =========================

def payload(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))

def send_pkt(pkt, count: int, pps: int):
    inter = 0 if pps <= 0 else (1.0 / pps)
    if USE_L2:
        sendp(pkt, iface=IFACE, count=count, inter=inter, verbose=False)
    else:
        send(pkt, count=count, inter=inter, verbose=False)

def l2hdr():
    # Build Ether header only if using L2
    if not USE_L2:
        return None
    return Ether(src=get_if_hwaddr(IFACE))

def banner(msg: str):
    print("\n" + "=" * 60)
    print(msg)
    print("=" * 60)

def main():
    if USE_L2:
        # sanity check to fail fast if iface is wrong
        try:
            _ = get_if_hwaddr(IFACE)
        except Exception as e:
            raise SystemExit(f"ERROR: interface '{IFACE}' not found or down. Fix IFACE. ({e})")

    # Show default route iface scapy will use in L3 mode (helpful)
    if not USE_L2:
        try:
            print(f"[info] L3 mode: Scapy default iface = {conf.iface}")
        except Exception:
            pass

    # CASE 1: IPv4 TCP sport 40000
    banner("CASE 1: IPv4 TCP sport=40000")
    p1 = IP(dst=DST_IPV4) / TCP(sport=40000, dport=DPORT_TCP, flags="PA") / Raw(load=payload(PAYLOAD_LEN))
    pkt1 = (l2hdr() / p1) if USE_L2 else p1
    send_pkt(pkt1, COUNT, PPS)
    print(f"Sent {COUNT} packets to {DST_IPV4}:{DPORT_TCP} (TCP sport=40000)")

    # CASE 2: IPv4 TCP sport 40001
    banner("CASE 2: IPv4 TCP sport=40001")
    p2 = IP(dst=DST_IPV4) / TCP(sport=40001, dport=DPORT_TCP, flags="PA") / Raw(load=payload(PAYLOAD_LEN))
    pkt2 = (l2hdr() / p2) if USE_L2 else p2
    send_pkt(pkt2, COUNT, PPS)
    print(f"Sent {COUNT} packets to {DST_IPV4}:{DPORT_TCP} (TCP sport=40001)")

    # CASE 3: IPv4 UDP sport 40000
    banner("CASE 3: IPv4 UDP sport=40000")
    p3 = IP(dst=DST_IPV4) / UDP(sport=40000, dport=DPORT_UDP) / Raw(load=payload(PAYLOAD_LEN))
    pkt3 = (l2hdr() / p3) if USE_L2 else p3
    send_pkt(pkt3, COUNT, PPS)
    print(f"Sent {COUNT} packets to {DST_IPV4}:{DPORT_UDP} (UDP sport=40000)")

    # CASE 4: IPv6 TCP sport 40000 (optional)
    if DST_IPV6.strip():
        banner("CASE 4: IPv6 TCP sport=40000")
        p4 = IPv6(dst=DST_IPV6) / TCP(sport=40000, dport=DPORT_TCP_V6, flags="PA") / Raw(load=payload(PAYLOAD_LEN))
        pkt4 = (l2hdr() / p4) if USE_L2 else p4
        send_pkt(pkt4, COUNT, PPS)
        print(f"Sent {COUNT} packets to [{DST_IPV6}]:{DPORT_TCP_V6} (TCP sport=40000)")
    else:
        banner("CASE 4 skipped (DST_IPV6 is empty)")

    banner("DONE")

if __name__ == "__main__":
    main()
