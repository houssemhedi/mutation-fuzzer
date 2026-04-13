# fuzzer/triage_cli.py  (replace)
import argparse, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from triage import triage_crashes

p = argparse.ArgumentParser(description="triage + minimize crash inputs")
p.add_argument("binary",             help="plain target binary")
p.add_argument("--crashes",          required=True)
p.add_argument("--out",              default="triaged")
p.add_argument("--asan",             default=None, help="ASAN-compiled binary")
args = p.parse_args()

triage_crashes(args.binary, args.crashes, args.out, asan_binary=args.asan)