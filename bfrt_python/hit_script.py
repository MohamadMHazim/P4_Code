t = bfrt.basic.pipe.Ingress.reg_https_flow_pkts

def read_bytes(i):
    e = t.get(i, from_hw=True)
    return next(iter(e.data.values()))   # one field only

def to_int(b):
    if isinstance(b, list):
        return int.from_bytes(bytes(b), 'big')
    if isinstance(b, (bytes, bytearray)):
        return int.from_bytes(b, 'big')
    return int(b)

hit = None
for i in range(0, 65536):
    v = to_int(read_bytes(i))
    if v != 0:
        hit = (i, v)
        break

print("HTTPS HIT:", hit)
