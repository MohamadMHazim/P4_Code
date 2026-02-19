#!/usr/bin/env python3

import struct

# CRC16-CCITT (Tofino default)
def crc16_ccitt(data: bytes, poly=0x1021, init=0xFFFF):
    crc = init
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---- INPUT VALUES ----
ether_type   = 0x86DD   # example IPv6
sel_protocol = 6        # TCP (example)
service_port = 443      # example port

# Pack exactly like P4 does (big endian!)
data = struct.pack("!H B H",
                   ether_type,
                   sel_protocol,
                   service_port)

hash_value = crc16_ccitt(data)

print("CRC16 hash value:", hash_value)
print("Register index:", hash_value)
