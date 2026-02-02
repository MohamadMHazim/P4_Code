import os
from datetime import datetime

p4 = bfrt.basic.pipe.Ingress

out_dir = "/home/ubuntu/P4_Code/bfrt_python/out"
os.makedirs(out_dir, exist_ok=True)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")

def dump_to_file(reg, name):
    path = f"{out_dir}/{name}_{ts}.txt"
    print(f"\n--- Dumping {name} to {path} ---")

    with open(path, "w") as f:
        # Temporarily redirect stdout to file
        import sys
        old = sys.stdout
        sys.stdout = f
        try:
            try:
                # Preferred: read from HW
                reg.dump(from_hw=True, table=True)
            except TypeError:
                # Fallback: some BFRT builds don't support from_hw
                reg.dump(table=True)
        finally:
            sys.stdout = old

    print(f"Saved: {path}")

print("\n========== READING REGISTERS FROM HW ==========\n")

dump_to_file(p4.reg_flow_pkts,        "reg_flow_pkts")
dump_to_file(p4.reg_flow_bytes,       "reg_flow_bytes")
dump_to_file(p4.reg_https_flow_pkts,  "reg_https_flow_pkts")
dump_to_file(p4.reg_https_flow_bytes, "reg_https_flow_bytes")

bfrt.complete_operations()

print("\n========== DONE ==========\n")
print(f"Output folder: {out_dir}\n")
