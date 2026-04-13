import os
import re
import subprocess
import hashlib
import tempfile
import random
from pathlib import Path
from collections import Counter

TIMEOUT = 3

MAGIC_8  = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]

def classify_exploitability(rip: str, signal: str, asan_summary: str) -> str:
    try:
        rip_int = int(rip, 16)
    except ValueError:
        rip_int = 0

    if rip_int > 0:
        rip_bytes = rip_int.to_bytes(8, byteorder='little', signed=False)
        unique_bytes = set(rip_bytes) - {0x00}
        if len(unique_bytes) <= 2:
            return "EXPLOITABLE"

    if "stack-buffer-overflow" in asan_summary:  return "EXPLOITABLE"
    if "heap-buffer-overflow"  in asan_summary:  return "PROBABLY_EXPLOITABLE"
    if "use-after-free"        in asan_summary:  return "PROBABLY_EXPLOITABLE"
    if signal == "SIGILL":                        return "EXPLOITABLE"
    if signal == "SIGBUS":                        return "PROBABLY_EXPLOITABLE"
    if signal == "SIGABRT":                       return "PROBABLY_EXPLOITABLE"
    if signal == "SIGSEGV" and rip_int == 0:      return "PROBABLY_EXPLOITABLE"

    return "UNKNOWN"


def get_signal_fast(binary: str, crash_file: str) -> str:
    try:
        r = subprocess.run(
            [binary, crash_file], timeout=TIMEOUT,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        from runner import CRASH_SIGS
        return CRASH_SIGS.get(r.returncode, "UNKNOWN")
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def run_asan(asan_binary: str, crash_file: str) -> tuple[str, str]:
    """Run ASAN binary on crash file. Returns (summary_line, full_output)."""
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "halt_on_error=1:print_stats=0:color=never"
    try:
        r = subprocess.run(
            [asan_binary, crash_file],
            capture_output=True, text=True,
            timeout=TIMEOUT, env=env
        )
        output = r.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""

    m = re.search(r'SUMMARY:\s*AddressSanitizer:\s*(.+)', output)
    summary = m.group(1).strip() if m else ""
    return summary, output


def crash_signature(signal: str, rip: str, asan_summary: str) -> str:
    rip_norm = rip
    try:
        v = int(rip, 16)
        if v > 0x7f0000000000:
            rip_norm = "LIBC_ADDR"
    except ValueError:
        pass

    raw = f"{signal}|{rip_norm}|{asan_summary[:80]}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def minimize_crash(binary: str, crash_data: bytes, signal: str) -> bytes:

    from runner import CRASH_SIGS

    def still_crashes(data: bytes) -> bool:
        if not data:
            return False
        with tempfile.NamedTemporaryFile(delete=False, suffix=".min") as tf:
            tf.write(data)
            path = tf.name
        try:
            r = subprocess.run(
                [binary, path], timeout=TIMEOUT,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return CRASH_SIGS.get(r.returncode, "") == signal
        except subprocess.TimeoutExpired:
            return False
        finally:
            os.unlink(path)

    lo, hi, best = 1, len(crash_data), crash_data
    while lo <= hi:
        mid = (lo + hi) // 2
        if still_crashes(crash_data[:mid]):
            best, hi = crash_data[:mid], mid - 1
        else:
            lo = mid + 1

    improved = True
    while improved:
        improved = False
        i = 0
        while i < len(best):
            cand = best[:i] + best[i+1:]
            if still_crashes(cand):
                best, improved = cand, True
            else:
                i += 1

    return best


def triage_crashes(binary: str, crash_dir: str, out_dir: str,
                   asan_binary: str = None):
    crashes = sorted(Path(crash_dir).glob("*.bin"))
    if not crashes:
        print(f"[!] No crash files found in {crash_dir}")
        return

    MAX_FILES = 300
    if len(crashes) > MAX_FILES:
        print(f"[!] {len(crashes)} files found — sampling {MAX_FILES} randomly")
        crashes = random.sample(crashes, MAX_FILES)

    os.makedirs(out_dir, exist_ok=True)
    seen   = {}   # sig_hash → True
    report = []

    print(f"[*] Triaging {len(crashes)} files  |  binary={binary}")
    if asan_binary:
        print(f"[*] ASAN binary={asan_binary}")
    print()

    for crash_file in crashes:
        data   = Path(crash_file).read_bytes()
        signal = get_signal_fast(binary, str(crash_file))

        # Cheap dedup check before spawning ASAN
        fast_sig = crash_signature(signal, "unknown", "")

        asan_summary = ""
        rip          = "unknown"

        if fast_sig not in seen and asan_binary and Path(asan_binary).exists():
            asan_summary, asan_full = run_asan(asan_binary, str(crash_file))
            # Pull pc address out of ASAN output
            m = re.search(r'pc (0x[0-9a-f]+)', asan_full)
            if m:
                rip = m.group(1)

        sig_hash    = crash_signature(signal, rip, asan_summary)
        exploitable = classify_exploitability(rip, signal, asan_summary)

        if sig_hash not in seen:
            seen[sig_hash] = True

            print(f"[+] NEW  sig={sig_hash}  {signal:8s}  [{exploitable}]")
            if asan_summary:
                print(f"         ASAN: {asan_summary}")

            print(f"         minimizing...", end=" ", flush=True)
            minimized = minimize_crash(binary, data, signal)
            reduction = 100 * (1 - len(minimized) / len(data)) if data else 0
            print(f"{len(data)} → {len(minimized)} bytes ({reduction:.0f}% smaller)")

            fname = f"{out_dir}/unique_{sig_hash}_{signal}_{exploitable}.bin"
            Path(fname).write_bytes(minimized)

            report.append({
                "sig_hash":    sig_hash,
                "signal":      signal,
                "rip":         rip,
                "exploitable": exploitable,
                "asan":        asan_summary,
                "orig_size":   len(data),
                "min_size":    len(minimized),
                "reduction":   reduction,
                "file":        fname,
            })

        else:
            print(f"     DUP  sig={sig_hash}  {signal}")

    print(f"\n{'═'*72}")
    print(f"  TRIAGE REPORT  —  {Path(binary).name}")
    print(f"{'═'*72}")
    print(f"  Total files     : {len(crashes)}")
    print(f"  Unique classes  : {len(report)}")
    print()

    for r in report:
        color = {
            "EXPLOITABLE":          "\033[91m",
            "PROBABLY_EXPLOITABLE": "\033[93m",
            "UNKNOWN":              "\033[97m",
        }.get(r["exploitable"], "")
        reset = "\033[0m"

        print(f"  {color}[{r['exploitable']}]{reset}")
        print(f"  sig    : {r['sig_hash']}")
        print(f"  signal : {r['signal']}")
        print(f"  rip    : {r['rip']}")
        if r["asan"]:
            print(f"  asan   : {r['asan']}")
        print(f"  size   : {r['orig_size']} → {r['min_size']} bytes "
              f"({r['reduction']:.0f}% reduction)")
        print(f"  saved  : {r['file']}")
        print()

    print(f"{'═'*72}")
    print(f"  Exploitability breakdown:")
    for label, n in sorted(Counter(r["exploitable"] for r in report).items()):
        color = {
            "EXPLOITABLE":          "\033[91m",
            "PROBABLY_EXPLOITABLE": "\033[93m",
            "UNKNOWN":              "\033[97m",
        }.get(label, "")
        reset = "\033[0m"
        print(f"  {color}{label:25s}{reset} : {n}")
    print(f"{'═'*72}")
    print(f"  Minimized crashes saved to: {out_dir}/")