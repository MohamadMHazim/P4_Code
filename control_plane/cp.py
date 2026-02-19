import time
from collections import OrderedDict

# -------------------------
# Settings
# -------------------------
INTERVAL_SEC = 60
PRINT_EVERY = 1            # print every N polls (1 => every poll)
INCLUDE_IPV6 = True

# -------------------------
# IMPORTANT: Use ONLY the precomputed bucket indexes you gave me
# (No CRC calculation in control plane anymore)
# -------------------------

# IPv4
IDX_IPv4_IP = 49633

IDX_V4_TCP = OrderedDict([
    ("http",  64513),
    ("https",  9024),
    ("smtp",   2752),
    ("ftp",    4032),
    ("ssh",    3712),
    ("dns",   55233),
    ("bgp",   30016),
    ("other", 49153),
])

IDX_V4_UDP = OrderedDict([
    ("dns",   54129),
    ("https", 10224),   # QUIC/UDP 443
    ("other", 50353),
])

IDX_V4_OTHER = OrderedDict([
    ("icmp",      432),
    ("gre",      2256),
    ("ipsec-esp", 3648),
    ("ipsec-ah", 52753),
])

# IPv6
IDX_IPv6_IP6 = 45747  # ip6 / other6

IDX_V6_TCP = OrderedDict([
    ("http",  36691),
    ("https", 20498),
    ("smtp",  31122),
    ("ftp",   31890),
    ("ssh",   32210),
    ("dns",   42131),
    ("bgp",    1554),
    ("other", 45907),
])

IDX_V6_UDP = OrderedDict([
    ("dns",   40995),
    ("https", 21666),
    ("other", 47075),
])

IDX_V6_OTHER = OrderedDict([
    ("icmp6", 49043),
    ("frag6", 31602),  # optional
])

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
# Core: build MAWI hierarchy from buckets (ONLY fixed indexes)
# -------------------------
def collect_counts(ingress):
    # NOTE: your code used reg_in_pkts/reg_out_pkts etc.
    # but you only defined "rinp" and "rinb" before.
    # Fix: define all four and use them.
    rinp  = ingress.src_bucket_pkts
    routp = ingress.dst_bucket_pkts
    rinb  = ingress.src_bucket_bytes
    routb = ingress.dst_bucket_bytes

    def get_bucket(idx: int):
        pkts = read_reg(rinp, idx) + read_reg(routp, idx)
        byts = read_reg(rinb, idx) + read_reg(routb, idx)
        return pkts, byts

    def build_ipv4():
        fam = {"pkts": 0, "bytes": 0, "children": {}}

        # TCP
        tcp_apps = OrderedDict()
        tcp_pkts = tcp_bytes = 0
        for name, idx in IDX_V4_TCP.items():
            pk, by = get_bucket(idx)
            tcp_apps[name] = (pk, by)
            tcp_pkts += pk
            tcp_bytes += by

        # UDP
        udp_apps = OrderedDict()
        udp_pkts = udp_bytes = 0
        for name, idx in IDX_V4_UDP.items():
            pk, by = get_bucket(idx)
            udp_apps[name] = (pk, by)
            udp_pkts += pk
            udp_bytes += by

        # ICMP/GRE/IPSEC
        icmp_pkts, icmp_bytes = get_bucket(IDX_V4_OTHER["icmp"])
        gre_pkts,  gre_bytes  = get_bucket(IDX_V4_OTHER["gre"])

        esp_pkts, esp_bytes = get_bucket(IDX_V4_OTHER["ipsec-esp"])
        ah_pkts,  ah_bytes  = get_bucket(IDX_V4_OTHER["ipsec-ah"])

        ipsec_pkts  = esp_pkts + ah_pkts
        ipsec_bytes = esp_bytes + ah_bytes

        fam["children"]["tcp"]  = {"pkts": tcp_pkts, "bytes": tcp_bytes, "apps": tcp_apps}
        fam["children"]["udp"]  = {"pkts": udp_pkts, "bytes": udp_bytes, "apps": udp_apps}
        fam["children"]["icmp"] = {"pkts": icmp_pkts, "bytes": icmp_bytes}
        fam["children"]["gre"]  = {"pkts": gre_pkts, "bytes": gre_bytes}
        fam["children"]["ipsec"] = {"pkts": ipsec_pkts, "bytes": ipsec_bytes}

        fam["pkts"]  = tcp_pkts + udp_pkts + icmp_pkts + gre_pkts + ipsec_pkts
        fam["bytes"] = tcp_bytes + udp_bytes + icmp_bytes + gre_bytes + ipsec_bytes

        # Optional: if you want "ip" to be read directly from the ip bucket index:
        ip_pkts, ip_bytes = get_bucket(IDX_IPv4_IP)
        fam["ip_bucket"] = {"pkts": ip_pkts, "bytes": ip_bytes}

        return fam

    def build_ipv6():
        fam = {"pkts": 0, "bytes": 0, "children": {}}

        # TCP6
        tcp_apps = OrderedDict()
        tcp_pkts = tcp_bytes = 0
        for name, idx in IDX_V6_TCP.items():
            pk, by = get_bucket(idx)
            tcp_apps[name] = (pk, by)
            tcp_pkts += pk
            tcp_bytes += by

        # UDP6
        udp_apps = OrderedDict()
        udp_pkts = udp_bytes = 0
        for name, idx in IDX_V6_UDP.items():
            pk, by = get_bucket(idx)
            udp_apps[name] = (pk, by)
            udp_pkts += pk
            udp_bytes += by

        icmp6_pkts, icmp6_bytes = get_bucket(IDX_V6_OTHER["icmp6"])
        # Your MAWI screenshot does NOT show gre6/ipsec6, so we skip them unless you want them.
        # If you still want to show them, you must provide the computed indexes for IPv6 GRE/ESP/AH.
        frag6_pkts, frag6_bytes = get_bucket(IDX_V6_OTHER["frag6"])

        fam["children"]["tcp6"]  = {"pkts": tcp_pkts, "bytes": tcp_bytes, "apps": tcp_apps}
        fam["children"]["udp6"]  = {"pkts": udp_pkts, "bytes": udp_bytes, "apps": udp_apps}
        fam["children"]["icmp6"] = {"pkts": icmp6_pkts, "bytes": icmp6_bytes}
        fam["children"]["frag6"] = {"pkts": frag6_pkts, "bytes": frag6_bytes}

        fam["pkts"]  = tcp_pkts + udp_pkts + icmp6_pkts + frag6_pkts
        fam["bytes"] = tcp_bytes + udp_bytes + icmp6_bytes + frag6_bytes

        ip6_pkts, ip6_bytes = get_bucket(IDX_IPv6_IP6)
        fam["ip6_bucket"] = {"pkts": ip6_pkts, "bytes": ip6_bytes}

        return fam

    ipv4 = build_ipv4()
    ipv6 = build_ipv6() if INCLUDE_IPV6 else None

    total_pkts  = ipv4["pkts"]  + (ipv6["pkts"]  if ipv6 else 0)
    total_bytes = ipv4["bytes"] + (ipv6["bytes"] if ipv6 else 0)

    return {"total": {"pkts": total_pkts, "bytes": total_bytes},
            "ipv4": ipv4,
            "ipv6": ipv6}

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

    # total
    print(row("total", total["pkts"], total["bytes"], total["pkts"], total["bytes"], indent=0))

    # IPv4
    # We print the computed ipv4 aggregate; if you prefer the direct "ip bucket", swap to ipv4["ip_bucket"]
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

    # IPv6
    if ipv6:
        print(row("ip6", ipv6["pkts"], ipv6["bytes"], total["pkts"], total["bytes"], indent=2))

        tcp6 = ipv6["children"]["tcp6"]
        udp6 = ipv6["children"]["udp6"]
        icmp6 = ipv6["children"]["icmp6"]
        frag6 = ipv6["children"]["frag6"]

        print(row("tcp6", tcp6["pkts"], tcp6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))
        for app, (pk, by) in tcp6["apps"].items():
            print(row(app, pk, by, tcp6["pkts"], tcp6["bytes"], indent=6))

        print(row("udp6", udp6["pkts"], udp6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))
        for app, (pk, by) in udp6["apps"].items():
            print(row(app, pk, by, udp6["pkts"], udp6["bytes"], indent=6))

        print(row("icmp6", icmp6["pkts"], icmp6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))
        print(row("frag6", frag6["pkts"], frag6["bytes"], ipv6["pkts"], ipv6["bytes"], indent=4))

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
