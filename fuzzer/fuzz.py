# fuzzer/fuzz.py
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from runner import fuzz

def main():
    p = argparse.ArgumentParser(
        description="mutation-based fuzzer — feeds malformed inputs into a binary"
    )
    p.add_argument("binary",      help="path to target binary")
    p.add_argument("--corpus",    default="corpus",  help="seed corpus directory")
    p.add_argument("--crashes",   default="crashes", help="crash output directory")
    p.add_argument("--iters",     type=int, default=0,
                   help="max iterations (0 = infinite)")
    p.add_argument("--mutator",   default=None,
                   help="force a specific mutator (default: random)")
    args = p.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[!] Binary not found: {args.binary}")
        sys.exit(1)

    # Optionally force a single mutator
    if args.mutator:
        from mutators import get_mutator, ALL_MUTATORS
        forced = get_mutator(args.mutator)
        ALL_MUTATORS.clear()
        ALL_MUTATORS.append(forced)
        print(f"[*] Forced mutator: {args.mutator}")

    fuzz(args.binary, args.corpus, args.crashes, args.iters)

if __name__ == "__main__":
    main()