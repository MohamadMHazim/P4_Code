import re
from pathlib import Path

OUT_DIR = Path("/home/ubuntu/P4_Code/bfrt_python/out")

# Match lines like:
# 0x0000000A         [0, 0, 12, 0]
LINE_RE = re.compile(r"^\s*(0x[0-9A-Fa-f]+)\s+\[(.*?)\]\s*$")

def parse_register_file(path):
    entries = []
    for line in path.read_text(errors="ignore").splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue

        idx = int(m.group(1), 16)
        values = [int(x.strip()) for x in m.group(2).split(",")]

        if any(v != 0 for v in values):
            entries.append((idx, values))

    return entries

def main():
    if not OUT_DIR.exists():
        print(f"ERROR: {OUT_DIR} does not exist")
        return

    files = sorted(OUT_DIR.glob("*.txt"))

    if not files:
        print("No register dump files found")
        return

    for f in files:
        print("\n" + "=" * 60)
        print(f"FILE: {f.name}")
        print("=" * 60)

        nonzero = parse_register_file(f)

        if not nonzero:
            print("  (all zero)")
            continue

        for idx, vals in nonzero:
            print(f"  [{idx}] = {vals}")

if __name__ == "__main__":
    main()
