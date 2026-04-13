# fuzzer/greybox.py
import os
import sys
import signal
import hashlib
import tempfile
import subprocess
import random
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from mutators import ALL_MUTATORS
from runner import CRASH_SIGS, save_crash
from coverage import CoverageTracker, get_coverage

TIMEOUT  = 2
MAX_INPUT = 65536


def fuzz_greybox(binary: str, cov_binary: str, corpus_dir: str,
                 crash_dir: str, work_dir: str, iterations: int = 0):
    """
    AFL-style greybox fuzzing loop:
    1. Pick seed from corpus (weighted by how many new paths it found)
    2. Mutate it
    3. Run on plain binary — check for crash
    4. Run on cov binary — check for new coverage
    5. If new coverage → add mutated input to corpus
    6. Repeat
    """
    # Load initial corpus
    corpus = []
    for p in Path(corpus_dir).iterdir():
        if p.is_file():
            data = p.read_bytes()
            corpus.append({
                "data":     data,
                "energy":   1,      # how many times to fuzz this seed
                "finds":    0,      # how many new paths this seed found
            })
    if not corpus:
        raise RuntimeError(f"No seeds in {corpus_dir}")

    os.makedirs(crash_dir, exist_ok=True)
    os.makedirs(work_dir,  exist_ok=True)

    tracker   = CoverageTracker()
    seen_crashes: set = set()
    count     = 0
    crashes   = 0
    new_paths = 0
    start     = time.time()

    print(f"[*] Greybox fuzzer starting")
    print(f"[*] Target (plain)    : {binary}")
    print(f"[*] Target (coverage) : {cov_binary}")
    print(f"[*] Initial corpus    : {len(corpus)} seeds")
    print(f"[*] Press Ctrl+C to stop\n")
    print(f"{'iter':>8}  {'exec/s':>7}  {'corpus':>7}  "
          f"{'coverage':>9}  {'crashes':>8}  {'new_paths':>9}")
    print("─" * 68)

    try:
        while True:
            if iterations and count >= iterations:
                break

            # Weighted seed selection — seeds that found more paths get picked more
            weights = [max(1, s["finds"] * 3 + 1) for s in corpus]
            seed    = random.choices(corpus, weights=weights, k=1)[0]
            mutator = random.choice(ALL_MUTATORS)
            mutated = mutator.mutate(seed["data"])

            if len(mutated) > MAX_INPUT:
                mutated = mutated[:MAX_INPUT]

            # ── Check for crash (fast plain binary) ───────────────────────────
            with tempfile.NamedTemporaryFile(delete=False, suffix=".fuzz") as tf:
                tf.write(mutated)
                tmppath = tf.name
            try:
                r = subprocess.run(
                    [binary, tmppath], timeout=TIMEOUT,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                rc  = r.returncode
                sig = CRASH_SIGS.get(rc, "")
            except subprocess.TimeoutExpired:
                sig = "TIMEOUT"
            finally:
                os.unlink(tmppath)

            count += 1

            if sig and sig != "TIMEOUT":
                h = hashlib.sha256(mutated).hexdigest()[:16]
                if h not in seen_crashes:
                    seen_crashes.add(h)
                    crashes += 1
                    fname = f"{crash_dir}/{Path(binary).name}_{sig}_{h}.bin"
                    Path(fname).write_bytes(mutated)
                    elapsed = time.time() - start
                    print(f"{count:>8}  {count/elapsed:>7.1f}  {len(corpus):>7}  "
                          f"{tracker.coverage_count:>9}  {crashes:>8}  "
                          f"{new_paths:>9}  \033[91m{sig}\033[0m → {Path(fname).name}")

            # ── Check for new coverage ────────────────────────────────────────
            cov = get_coverage(cov_binary, mutated, work_dir)
            if tracker.is_interesting(cov):
                new_paths += 1
                seed["finds"] += 1
                # Add this input to corpus — it found new paths
                corpus.append({
                    "data":   mutated,
                    "energy": 1,
                    "finds":  1,
                })
                elapsed = time.time() - start
                print(f"{count:>8}  {count/elapsed:>7.1f}  {len(corpus):>7}  "
                      f"{tracker.coverage_count:>9}  {crashes:>8}  "
                      f"{new_paths:>9}  \033[92m+path\033[0m (cov={tracker.coverage_count})")

            # Print stats every 200 iters
            if count % 200 == 0:
                elapsed = time.time() - start
                print(f"{count:>8}  {count/elapsed:>7.1f}  {len(corpus):>7}  "
                      f"{tracker.coverage_count:>9}  {crashes:>8}  {new_paths:>9}")

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start
    print(f"\n[+] Done — {count} iters in {elapsed:.1f}s ({count/elapsed:.1f} exec/s)")
    print(f"[+] Corpus grew : 5 → {len(corpus)} seeds")
    print(f"[+] New paths   : {new_paths}")
    print(f"[+] Coverage    : {tracker.coverage_count} lines")
    print(f"[+] Crashes     : {crashes}")