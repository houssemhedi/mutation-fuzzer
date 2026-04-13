# mutation-fuzzer

A mutation-based binary fuzzer built from scratch in Python, targeting C binaries.
Implements the core concepts behind AFL — mutation strategies, crash deduplication,
ASAN integration, and coverage-guided greybox feedback.

Built as a deep-dive into memory corruption and fuzzing internals.

---

## Architecture
mutation-fuzzer/
├── targets/
│   ├── target_bof.c        
│   ├── target_heap.c    
│   ├── target_fmt.c       
│   └── build.sh             
├── corpus/                   
├── crashes/                  
├── triaged/                  
└── fuzzer/
├── mutators.py           
├── runner.py            
├── triage.py             
├── coverage.py
├── greybox.py             
├── fuzz.py                
├── greybox_cli.py         
└── triage_cli.py       

---

## How it works

### Blackbox mode (dumb fuzzer)

Takes a seed from the corpus, applies a random mutation strategy, feeds the
result into the target binary, and checks the exit signal. On SIGSEGV / SIGABRT
/ SIGBUS / SIGILL — saves the input and continues.
seed → mutate → subprocess → signal? → save crash → repeat

### Greybox mode (coverage-guided)

Same loop but after each run, measures which lines were executed using gcov.
If the mutated input hit a new line not seen before, it gets added to the corpus
and fuzzed further. Seeds that find more paths get higher selection weight.
This is the core idea behind AFL.
seed → mutate → crash? save
→ new coverage? → add to corpus (weighted)
→ repeat

---

## Mutation strategies

| Strategy | What it does | Bug class targeted |
|---|---|---|
| `bit_flip` | Flip a single random bit | Off-by-one, boundary conditions |
| `byte_rand` | Replace a byte with random value | Type confusion |
| `byte_insert` | Insert N random bytes | Buffer overflow (grow input) |
| `byte_delete` | Delete a chunk of bytes | Underread, off-by-one |
| `magic_val` | Inject 0x00, 0xff, INT_MAX, etc | Integer overflow, signedness |
| `chunk_repeat` | Repeat a chunk N times | Buffer overflow (classic AAAA…) |
| `fmt_inject` | Inject %x, %n, %s specifiers | Format string bugs |
| `havoc` | Apply 2–8 random mutations | Complex multi-condition bugs |

---

## Crash triage

Each crash is:
1. Classified by signal (SIGSEGV / SIGABRT / SIGBUS / SIGILL)
2. Run under ASAN to get exact bug class and source location
3. Deduplicated by signature (signal + rip + ASAN summary)
4. Minimized to the smallest input that reproduces the crash
5. Rated for exploitability: EXPLOITABLE / PROBABLY_EXPLOITABLE / UNKNOWN

---

## Results

### target_bof — stack buffer overflow (CWE-121)

- **Bug:** `memcpy(buffer, data, size)` with fixed 64-byte stack buffer, no bounds check
- **Confirmed by ASAN:** `stack-buffer-overflow at target_bof.c:7 in parse_header`
- **Exploitability:** EXPLOITABLE — return address overwritten, RIP controlled
- **Minimized input:** 65 bytes (1 byte past buffer boundary)
- **Signals found:** SIGSEGV, SIGABRT, SIGBUS, SIGILL
- **Unique crash classes:** 13 from 2262 raw crashes
buffer[64] on stack
memcpy writes 200 bytes → overflows into saved RBP + RIP
RIP = 0x4141414141414141 → SIGSEGV on ret

### target_heap — heap overflow (CWE-122)

- **Bug:** `memcpy(r->name, data, size)` into a fixed heap allocation, no bounds check
- **Confirmed by ASAN:** `heap-buffer-overflow at target_heap.c:13 in parse_record`
- **Exploitability:** PROBABLY_EXPLOITABLE — heap metadata corrupted
- **Minimized input:** 73 bytes
- **Unique crash classes:** 4 from 234 raw crashes
malloc(sizeof(Record)) = 96 bytes
memcpy writes 500 bytes → corrupts adjacent heap chunk header
free() detects corruption → SIGABRT

### target_fmt — format string (CWE-134)

- **Bug:** `printf(buf)` where buf contains user-controlled data
- **Confirmed by ASAN:** `SEGV at target_fmt.c:10 in parse_log_entry`
- **Exploitability:** UNKNOWN by classifier (generic SEGV — %n write to bad addr)
- **Minimized input:** 2 bytes (`%n`)
- **Note:** In a real exploit scenario this allows arbitrary write via %n
printf("%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n")
→ writes to addresses read off the stack
→ SIGSEGV when target address is unmapped

---

## Fuzzer performance

| Mode | exec/s | Target |
|---|---|---|
| Blackbox | ~550 | target_bof |
| Greybox | ~90 | target_bof |

Greybox is ~6x slower due to gcov instrumentation overhead — same tradeoff as AFL.

---

## Mitigations comparison

```bash
checksec --file=targets/target_bof           # no protections
checksec --file=targets/target_bof_hardened  # full protections
```

| Mitigation | Fuzzing target | Hardened |
|---|---|---|
| Stack canary | ✗ | ✓ |
| NX | ✗ | ✓ |
| PIE / ASLR | ✗ | ✓ |
| RELRO | Partial | Full |

---

## Quick start

```bash
# 1. Build all targets
cd targets && ./build.sh && cd ..

# 2. Generate seed corpus
python3 generate_corpus.py

# 3. Run blackbox fuzzer
python3 fuzzer/fuzz.py targets/target_bof --crashes crashes/bof

# 4. Run greybox fuzzer
python3 fuzzer/greybox_cli.py targets/target_bof \
    --cov targets/target_bof_cov \
    --crashes crashes/greybox

# 5. Triage crashes
python3 fuzzer/triage_cli.py targets/target_bof \
    --crashes crashes/bof \
    --out triaged/bof \
    --asan targets/target_bof_asan
```

---

## Dependencies

```bash
sudo apt install gcc gdb gcov checksec
pip install --break-system-packages # (no Python deps beyond stdlib)
```

---

## Concepts demonstrated

- Mutation-based fuzzing (bit flip, byte insertion, magic values, havoc)
- Signal-based crash detection (SIGSEGV, SIGABRT, SIGBUS, SIGILL)
- Crash deduplication by signature hash
- Input minimization via binary search + byte deletion
- ASAN integration for root cause analysis
- Coverage-guided feedback loop (greybox, AFL-style)
- Exploitability classification
- Memory corruption bug classes: stack BOF, heap overflow, format string

---

## References

- [The Fuzzing Book](https://www.fuzzingbook.org) — mutation fuzzing theory
- [AFL++ source](https://github.com/AFLplusplus/AFLplusplus) — greybox fuzzing
- [Fuzzing101](https://github.com/antonio-morales/Fuzzing101) — hands-on exercises