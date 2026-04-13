import argparse, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from greybox import fuzz_greybox

p = argparse.ArgumentParser(description="greybox coverage-guided fuzzer")
p.add_argument("binary",         help="plain target binary (crash detection)")
p.add_argument("--cov",          required=True, help="gcov-instrumented binary")
p.add_argument("--corpus",       default="corpus")
p.add_argument("--crashes",      default="crashes/greybox")
p.add_argument("--work",         default="/tmp/fuzz_cov_work")
p.add_argument("--iters",        type=int, default=0)
args = p.parse_args()

fuzz_greybox(
    args.binary, args.cov,
    args.corpus, args.crashes,
    args.work,   args.iters
)