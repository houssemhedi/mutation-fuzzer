# fuzzer/runner.py
import os
import sys
import signal
import hashlib
import tempfile
import subprocess
import random
import time
from pathlib import Path
from mutators import ALL_MUTATORS

# ── Config ────────────────────────────────────────────────────────────────────
TIMEOUT      = 2          # seconds before we consider it a hang
MAX_INPUT    = 65536      # cap mutated input size (64 KB)
CRASH_SIGS   = {
    -signal.SIGSEGV: "SIGSEGV",   # segfault
    -signal.SIGABRT: "SIGABRT",   # abort (heap corruption, assert)
    -signal.SIGFPE:  "SIGFPE",    # divide by zero / FP exception
    -signal.SIGBUS:  "SIGBUS",    # bus error (misaligned access)
    -signal.SIGILL:  "SIGILL",    # illegal instruction
}

# ── Crash deduplication set (lives in memory this stage) ─────────────────────
seen_crashes = set()


def load_corpus(corpus_dir: str) -> list[bytes]:
    seeds = []
    for p in Path(corpus_dir).iterdir():
        if p.is_file():
            seeds.append(p.read_bytes())
    if not seeds:
        raise RuntimeError(f"No seeds found in {corpus_dir}")
    print(f"[*] Loaded {len(seeds)} seeds from {corpus_dir}")
    return seeds


def save_crash(crash_dir: str, data: bytes, sig_name: str, target_name: str) -> str | None:
    """
    Hash the crash input. If we've never seen this hash before,
    save it and return the filepath. Otherwise return None (duplicate).
    """
    h = hashlib.sha256(data).hexdigest()[:16]
    if h in seen_crashes:
        return None
    seen_crashes.add(h)

    os.makedirs(crash_dir, exist_ok=True)
    fname = f"{crash_dir}/{target_name}_{sig_name}_{h}.bin"
    Path(fname).write_bytes(data)
    return fname


def run_once(binary: str, data: bytes) -> tuple[int, str]:
    """
    Write data to a temp file, run binary on it.
    Returns (returncode, signal_name_or_empty).
    returncode < 0 means killed by signal.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".fuzz") as tf:
        tf.write(data)
        tmppath = tf.name

    try:
        result = subprocess.run(
            [binary, tmppath],
            timeout=TIMEOUT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        rc = result.returncode
        sig = CRASH_SIGS.get(rc, "")
        return rc, sig

    except subprocess.TimeoutExpired:
        return -999, "TIMEOUT"

    finally:
        os.unlink(tmppath)


def fuzz(binary: str, corpus_dir: str, crash_dir: str, iterations: int = 0):
    """
    Main fuzzing loop.
    iterations=0 means run forever.
    """
    corpus     = load_corpus(corpus_dir)
    target     = Path(binary).name
    count      = 0
    crashes    = 0
    hangs      = 0
    start_time = time.time()

    print(f"[*] Target  : {binary}")
    print(f"[*] Mutators: {[m.name for m in ALL_MUTATORS]}")
    print(f"[*] Fuzzing — press Ctrl+C to stop\n")
    print(f"{'iter':>8}  {'exec/s':>7}  {'crashes':>8}  {'hangs':>6}  {'corpus':>7}  last_signal")
    print("─" * 68)

    try:
        while True:
            if iterations and count >= iterations:
                break

            # Pick a random seed and a random mutator
            seed    = random.choice(corpus)
            mutator = random.choice(ALL_MUTATORS)
            mutated = mutator.mutate(seed)

            # Cap size to avoid absurdly slow runs
            if len(mutated) > MAX_INPUT:
                mutated = mutated[:MAX_INPUT]

            rc, sig = run_once(binary, mutated)
            count  += 1

            if sig == "TIMEOUT":
                hangs += 1

            elif sig:  # it's a real crash signal
                saved = save_crash(crash_dir, mutated, sig, target)
                if saved:
                    crashes += 1
                    elapsed = time.time() - start_time
                    execs_s = count / elapsed if elapsed > 0 else 0
                    print(f"{count:>8}  {execs_s:>7.1f}  {crashes:>8}  {hangs:>6}  {len(corpus):>7}  "
                          f"\033[91m{sig}\033[0m  → {Path(saved).name}")

            # Print stats every 500 iterations
            if count % 500 == 0:
                elapsed = time.time() - start_time
                execs_s = count / elapsed if elapsed > 0 else 0
                print(f"{count:>8}  {execs_s:>7.1f}  {crashes:>8}  {hangs:>6}  {len(corpus):>7}")

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print(f"\n[+] Done — {count} iterations in {elapsed:.1f}s  "
          f"({count/elapsed:.1f} exec/s)")
    print(f"[+] Unique crashes: {crashes}  |  Hangs: {hangs}")
    print(f"[+] Crash inputs saved to: {crash_dir}/")