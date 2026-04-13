import sys
sys.path.insert(0, "fuzzer")
from mutators import ALL_MUTATORS

seed = b"Hello, fuzzer!"
print(f"[*] Seed: {seed!r}  ({len(seed)} bytes)\n")

for mutator in ALL_MUTATORS:
    result = mutator.mutate(seed)
    changed = sum(1 for a, b in zip(seed, result) if a != b)
    print(f"  [{mutator.name:15s}]  {len(result):4d} bytes  |  {result[:40]!r}")
