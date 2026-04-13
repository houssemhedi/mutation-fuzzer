import os

os.makedirs("corpus", exist_ok=True)

seeds = {
    "seed_small.bin":   b"Hello",                 
    "seed_medium.bin":  b"A" * 32,                  
    "seed_boundary.bin":b"B" * 63,                  
    "seed_fmt.bin":     b"Normal log entry: OK\n",  
    "seed_struct.bin":  b"\x00" * 16 + b"\x01\x00\x00\x00" + b"\x00" * 16, 
}

for name, data in seeds.items():
    with open(f"corpus/{name}", "wb") as f:
        f.write(data)
    print(f"[+] {name:25s} ({len(data)} bytes)")

print(f"\n[*] Corpus ready: {len(seeds)} seeds in ./corpus/")