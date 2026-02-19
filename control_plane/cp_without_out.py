import time
import struct
from collections import OrderedDict

# -------------------------
# Settings
# -------------------------
INTERVAL_SEC = 60
PRINT_EVERY = 1
INCLUDE_IPV6 = True

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD

PROTO_TCP    = 6
PROTO_UDP    = 17
PROTO_ICMP   = 1
PROTO_GRE    = 47
PROTO_ESP    = 50
PROTO_AH     = 51
PROTO_ICMPV6 = 58

# MAWI-style app inference by service port
TCP_APPS = OrderedDict([
    (80,  "http"),
    (443, "https"),
    (25,  "smtp"),
    (21,  "ftp"),
    (22,  "ssh"),
])

UDP_APPS = OrderedDict([
    (53,  "dns"),
    (443, "https"),   # QUIC often shows as UDP/443 in MAWI tables
])

# -------------------------
# CRC16 (same style as dataplane expectation)
# -------------------------
def crc16_ibm_reflected(data: bytes, poly=0xA001, init=0x0000) -> int:
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF

def bucket_idx(ether_type: int, proto: int, service_port: int) -> int:
    blob = struct.pack("!HBH", ether_type & 0xFFFF, proto & 0xFF, service_port & 0xFFFF)
    return crc16_ibm_reflected(blob)

# -------------------------
# BFRT register read
# -------------------------
def read_reg(reg_obj, idx: int) -> int:
    ent = reg_obj.get(idx, from_hw=True)
    data = ent.data
    k = next(iter(data.keys()))
    v = data[k]
    return int(v[0] if isinstance(v, list) else v)

# -------------------------
# Formatting helpers (MAWI-like)
# -------------------------
def fmt_int(n: int) -> str:
    return f"{n:d}"

def fmt_pct(part: int, whole: int) -> str:
    if whole <= 0:
        return " (0.00%)"
    return f" ({(part/whole)*100:6.2f}%)"

def fmt_bpp(bytes_: int, pkts: int) -> str:
    if pkts <= 0:
        return f"{0:7.2f}"
    return f"{(bytes_/pkts):7.2f}"

def row(label, pkts, bytes_, parent_pkts, parent_bytes, indent=0):
    pad = " " * indent
    return (
        f"{pad}{label:<10}"
        f"{fmt_int(pkts):>12}{fmt_pct(pkts, parent_pkts):>10}"
        f"{fmt_int(bytes_):>16}{fmt_pct(bytes_, parent_bytes):>10}"
        f"{fmt_bpp(bytes_, pkts):>10}"
    )

# -------------------------
# Core: build MAWI hierarchy from buckets
# -------------------------
def collect_counts(ingress):
    rinp = ingress.reg_in_pkts
    rinb = ingress.reg_in_bytes

    # Directionless: ONLY read "in" registers
    def get_bucket(eth, proto, port):
        idx = bucket_idx(eth, proto, port)
        pkts = read_reg(rinp, idx)
        byts = read_reg(rinb, idx)
        return pkts, byts

    def build_family(eth, tcp_label, udp_label):
        fam = {"pkts": 0, "bytes": 0, "children": {}}

        # TCP apps
        tcp_pkts = tcp_bytes = 0
        tcp_apps = {}
        for p, name in TCP_APPS.items():
            pk, by = get_bucket(eth, PROTO_TCP, p)
            tcp_apps[name] = (pk, by)
            tcp_pkts += pk
            tcp_bytes += by

        # UDP apps
        udp_pkts = udp_bytes = 0
        udp_apps = {}
        for p, name in UDP_APPS.items():
            pk, by = get_bucket(eth, PROTO_UDP, p)
            udp_apps[name] = (pk, by)
            udp_pkts += pk
            udp_bytes += by

        # Non-TCP/UDP protocols => port=0
        if eth == ETH_IPV6:
            icmp_pkts, icmp_bytes = get_bucket(eth, PROTO_ICMPV6, 0)
        else:
            icmp_pkts, icmp_bytes = get_bucket(eth, PROTO_ICMP, 0)

        gre_pkts, gre_bytes = get_bucket(eth, PROTO_GRE, 0)

        esp_pkts, esp_bytes = get_bucket(eth, PROTO_ESP, 0)
        ah_pkts,  ah_bytes  = get_bucket(eth, PROTO_AH, 0)

        # MAWI groups ESP+AH under "ipsec"
        ipsec_pkts  = esp_pkts + ah_pkts
        ipsec_bytes = esp_bytes + ah_bytes

        fam["children"][tcp_label] = {"pkts": tcp_pkts, "bytes": tcp_bytes, "apps": tcp_apps}
        fam["children"][udp_label] = {"pkts": udp_pkts, "bytes": udp_bytes, "apps": udp_apps}
        fam["children"]["icmp"]    = {"pkts": icmp_pkts,  "bytes": icmp_bytes}
        fam["children"]["gre"]     = {"pkts": gre_pkts,   "bytes": gre_bytes}
        fam["children"]["ipsec"]   = {"pkts": ipsec_pkts, "bytes": ipsec_bytes}

        fam["pkts"]  = tcp_pkts + udp_pkts + icmp_pkts + gre_pkts + ipsec_pkts
        fam["bytes"] = tcp_bytes + udp_bytes + icmp_bytes + gre_bytes + ipsec_bytes
        return fam

    ipv4 = build_family(ETH_IPV4, "tcp", "udp")
    ipv6 = build_family(ETH_IPV6, "tcp6", "udp6") if INCLUDE_IPV6 else None

    total_pkts  = ipv4["pkts"]  + (ipv6["pkts"]  if ipv6 else 0)
    total_bytes = ipv4["bytes"] + (ipv6["bytes"] if ipv6 else 0)

    return {
        "total": {"pkts": total_pkts, "bytes": total_bytes},
        "ipv4": ipv4,
        "ipv6": ipv6
    }

# -------------------------
# Print MAWI-like table
# -------------------------
def print_mawi(stats):
    total = stats["total"]
    ipv4  = stats["ipv4"]
    ipv6  = stats["ipv6"]

    print("\nProtocol Breakdown\n")
    print(f"{'protocol':<10}{'packets':>22}{'bytes':>26}{'bytes/pkt':>10}")
    print("-" * 70)

    print(row("total", total["pkts"], total["bytes"], total["pkts"], total["bytes"], indent=0))
    print(row("ip", ipv4["pkts"], ipv4["bytes"], total["pkts"], total["bytes"], indent=2))

    tcp = ipv4["children"]["tcp"]
    udp = ipv4["children"]["udp"]
    icmp4  = ipv4["children"]["icmp"]
    gre4   = ipv4["children"]["gre"]
    ipsec4 = ipv4["children"]["ipsec"]

    print(row("tcp", tcp["pkts"], tcp["bytes"], ipv4["pkts"], ipv4["bytes"], indent=4))
    for app, (pk, by) in tcp["apps"].items():
        print(row(app, pk, by, tcp["pkts"], tcp["bytes"], indent=6))

    print(row("udp", udp["pkts"], udp["bytes"], ipv4["pkts"], ipv4["bytes"], indent=4))
    for app, (pk, by) in udp["apps"].items():
        print(row(app, pk, by, udp["pkts"], udp["bytes"], indent=6))

    print(row("icmp",  icmp4["pkts"],  icmp4["bytes"],  ipv4["pkts"], ipv4["bytes"], indent=4))
    print(row("gre",   gre4["pkts"],   gre4["bytes"],   ipv4["pkts"], ipv4["bytes"], indent=4))
    print(row("ipsec", ipsec4["pkts"], ipsec4["bytes"], ipv4["pkts"], ipv4["bytes"], indent=4))

    if ipv6:
        print(row("ip6", ipv6["pkts"], ipv6["bytes"], total["pkts"], total["bytes"], indent=2))

        tcp6 = ipv6["children"]["tcp6"]
        udp6 = ipv6["children"]["udp6"]
        icmp6  = ipv6["children"]["icmp"]
        gre6   = ipv6["children"]["gre"]
        ipsec6 = ipv6["children"]["ipsec"]

        print(row("tcp6", tcp6["pkts"], tcp6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))
        for app, (pk, by) in tcp6["apps"].items():
            print(row(app, pk, by, tcp6["pkts"], tcp6["bytes"], indent=6))

        print(row("udp6", udp6["pkts"], udp6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))
        for app, (pk, by) in udp6["apps"].items():
            print(row(app, pk, by, udp6["pkts"], udp6["bytes"], indent=6))

        print(row("icmp6",  icmp6["pkts"],  icmp6["bytes"],  ipv6["pkts"], ipv6["bytes"], indent=4))
        print(row("gre6",   gre6["pkts"],   gre6["bytes"],   ipv6["pkts"], ipv6["bytes"], indent=4))
        print(row("ipsec6", ipsec6["pkts"], ipsec6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))

# -------------------------
# Main loop
# -------------------------
def main():
    ingress = bfrt.basic.pipe.Ingress
    i = 0
    while True:
        stats = collect_counts(ingress)
        if i % PRINT_EVERY == 0:
            print_mawi(stats)
        i += 1
        time.sleep(INTERVAL_SEC)

main()
