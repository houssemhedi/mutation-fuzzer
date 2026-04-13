#!/bin/bash
set -e

echo "[*] Building vulnerable targets..."

# ─── No mitigations (fuzzing targets) ────────────────────────────────────────
gcc target_bof.c  -o target_bof  -fno-stack-protector -z execstack -no-pie -w
gcc target_heap.c -o target_heap -fno-stack-protector -z execstack -no-pie -w
gcc target_fmt.c  -o target_fmt  -fno-stack-protector -z execstack -no-pie -w

echo "[+] Built: target_bof  target_heap  target_fmt  (no mitigations)"

# ─── With mitigations (for comparison / understanding) ───────────────────────
gcc target_bof.c  -o target_bof_hardened  -w
gcc target_heap.c -o target_heap_hardened -w
gcc target_fmt.c  -o target_fmt_hardened  -w

echo "[+] Built: target_bof_hardened  target_heap_hardened  target_fmt_hardened"
echo ""
echo "[*] Check mitigations with checksec:"
echo "    checksec --file=target_bof"
echo "    checksec --file=target_bof_hardened"
# ── ASAN builds (for triage and root cause analysis) ─────────────────────────
gcc target_bof.c  -o target_bof_asan  -fsanitize=address -fno-omit-frame-pointer -g -w
gcc target_heap.c -o target_heap_asan -fsanitize=address -fno-omit-frame-pointer -g -w
gcc target_fmt.c  -o target_fmt_asan  -fsanitize=address -fno-omit-frame-pointer -g -w
echo "[+] Built ASAN targets"