import os
import re
import subprocess
import tempfile
import shutil
from pathlib import Path

TIMEOUT = 3


def get_coverage(cov_binary: str, input_data: bytes, work_dir: str) -> frozenset:
    """
    Run the gcov-instrumented binary on input_data.
    Returns a frozenset of (file, line) tuples representing covered lines.
    An input that covers NEW lines not seen before is 'interesting'.
    """
    run_dir = tempfile.mkdtemp(dir=work_dir)
    binary_name = Path(cov_binary).name
    binary_copy = os.path.join(run_dir, binary_name)
    shutil.copy2(cov_binary, binary_copy)

    gcno_src = cov_binary + ".gcno"
    if not os.path.exists(gcno_src):
        gcno_src = str(Path(cov_binary).parent / (binary_name + ".gcno"))
    if os.path.exists(gcno_src):
        shutil.copy2(gcno_src, run_dir)

    input_file = os.path.join(run_dir, "input.fuzz")
    Path(input_file).write_bytes(input_data)

    try:
        subprocess.run(
            [binary_copy, input_file],
            timeout=TIMEOUT, cwd=run_dir,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        pass

    covered = set()
    gcda_files = list(Path(run_dir).glob("*.gcda"))
    if not gcda_files:
        shutil.rmtree(run_dir, ignore_errors=True)
        return frozenset()

    try:
        r = subprocess.run(
            ["gcov", "-b", "-c"] + [str(f) for f in gcda_files],
            capture_output=True, text=True, cwd=run_dir, timeout=TIMEOUT
        )
        for line in r.stdout.splitlines():
            m = re.match(r'.*:(\d+):\s*(.+)', line)
            if m:
                lineno = int(m.group(1))
                content = m.group(2).strip()
                if content not in ('#####', '-', '0') and lineno > 0:
                    covered.add(lineno)
    except Exception:
        pass

    shutil.rmtree(run_dir, ignore_errors=True)
    return frozenset(covered)


class CoverageTracker:
    def __init__(self):
        self.total_covered: set = set()
        self.interesting_count = 0

    def is_interesting(self, new_coverage: frozenset) -> bool:
        new_lines = new_coverage - self.total_covered
        if new_lines:
            self.total_covered.update(new_lines)
            return True
        return False

    @property
    def coverage_count(self) -> int:
        return len(self.total_covered)
