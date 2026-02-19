import struct
import socket

# ------------------
# Build simple ICMP packet (Ethernet+IPv4+ICMP)
# ------------------
def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

src_mac = b'\x00\x11\x22\x33\x44\x55'
dst_mac = b'\x00\xaa\xbb\xcc\xdd\xee'
eth_type = struct.pack("!H", 0x0800)

# ICMP
icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b'hi'
icmp = struct.pack("!BBHHH", 8, 0, checksum(icmp), 1, 1) + b'hi'

# IPv4
version_ihl = 0x45
total_len = 20 + len(icmp)
ip_header = struct.pack("!BBHHHBBH4s4s",
    version_ihl, 0, total_len, 1, 0,
    64, 1, 0,
    socket.inet_aton("10.0.0.1"),
    socket.inet_aton("10.0.0.2")
)
ip_header = struct.pack("!BBHHHBBH4s4s",
    version_ihl, 0, total_len, 1, 0,
    64, 1, checksum(ip_header),
    socket.inet_aton("10.0.0.1"),
    socket.inet_aton("10.0.0.2")
)

packet = dst_mac + src_mac + eth_type + ip_header + icmp

# ------------------
# Send via pktgen
# ------------------
pktgen = bfrt.tf1.pktgen  # change if needed

APP_ID = 0
SOURCE_PORT = 68   # change to your pktgen source port

# Write packet to buffer
pktgen.pkt_buffer.add(offset=0, size=len(packet), data=packet)

# Configure app (send exactly 1 packet)
pktgen.app_cfg.add(
    app_id=APP_ID,
    pipe_id=0,
    trigger_type="ONE_SHOT",
    source_port=SOURCE_PORT,
    pkt_buffer_offset=0,
    length=len(packet),
    packets_per_batch=1,
    batch_count=1
)

# Enable app
pktgen.app_ctrl.add(app_id=APP_ID, pipe_id=0, enable=True)

print("Sent 1 ICMP packet via pktgen.")
