"""Heavy obfuscation 의 1-단계 deobfuscation (#Z1).

목적: heavy obfuscation 우회로 static analyzer (Stage 2/4c) 가 놓치는 케이스를
*deobfuscated 텍스트* 도 함께 매칭하게 함. 두 본문 합쳐 indicator 매칭하면
heavy-obfuscation recall 이 회복됨.

지원 디코딩:
  - base64 chains (`base64.b64decode("...").decode()`, `Buffer.from(b64,'base64')`,
    `atob("...")`)
  - hex chains (`bytes.fromhex("...")`, `'\\x41\\x42...'`)
  - JS escape sequences (`String.fromCharCode(65, 66, ...)`)
  - URL/percent encoding
  - 단순 char-array → 문자열

비용: 0 — 모든 디코딩은 in-process 정적 변환. *실행* 없음 (eval 등 호출 안 함).

API:
  deobfuscate(source, language) -> DeobfuscationResult
    .decoded_layers: list[str]  — 각 단계 디코드 결과 (n 단계 중첩 디코딩 가능)
    .final_text:     str        — 모든 디코드 합친 평탄화 텍스트 (Stage 2 매칭용)
    .layer_count:    int
    .stats:          dict       — 어느 종류 디코드가 몇 번 일어났는지

본 모듈은 *strings* 만 추출/디코드 — full Python execution 은 절대 X (보안).
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field

MAX_LAYERS = 3            # 무한 재귀 방지 (보통 2단계 안에서 끝남)
MAX_TOTAL_SIZE = 5_000_000  # 5MB cap — 시간 / 메모리 보호
MIN_STRING_LEN = 8         # 매우 짧은 문자열은 디코드 시도 X (false positive 방지)


# ─────────────── 정규식 ───────────────

# Python b64decode: "base64.b64decode("...") 또는 .b64decode(b"...")"
_PY_B64_CALL_RE = re.compile(
    r"""base64\.b64decode\s*\(\s*[bf]?["']([A-Za-z0-9+/=\s]+)["']""",
    re.DOTALL,
)
# JS atob: 'atob("...")'
_JS_ATOB_RE = re.compile(
    r"""atob\s*\(\s*["']([A-Za-z0-9+/=\s]+)["']""",
    re.DOTALL,
)
# JS Buffer.from(b64, 'base64')
_JS_BUFFER_B64_RE = re.compile(
    r"""Buffer\.from\s*\(\s*["']([A-Za-z0-9+/=\s]+)["']\s*,\s*["']base64["']""",
    re.DOTALL,
)
# Python bytes.fromhex("DEADBEEF")
_PY_HEX_RE = re.compile(
    r"""bytes\.fromhex\s*\(\s*[bf]?["']([0-9a-fA-F\s]+)["']""",
    re.DOTALL,
)
# Hex escape literal in string: "\x41\x42..."
_HEX_ESC_LITERAL_RE = re.compile(r"((?:\\x[0-9a-fA-F]{2}){4,})")
# Unicode escape: AB...
_UNI_ESC_LITERAL_RE = re.compile(r"((?:\\u[0-9a-fA-F]{4}){4,})")
# JS String.fromCharCode(65, 66, ...)
_FROM_CHAR_CODE_RE = re.compile(
    r"String\.fromCharCode\s*\(([\s\d,]+)\)",
)
# URL percent encoding %41%42... (4+ in row)
_URL_PCT_RE = re.compile(r"((?:%[0-9a-fA-F]{2}){8,})")


# ─────────────── 결과 ───────────────

@dataclass
class DeobfuscationResult:
    decoded_layers: list[str] = field(default_factory=list)
    final_text: str = ""
    layer_count: int = 0
    stats: dict = field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return bool(self.decoded_layers)


# ─────────────── 단일 패스 디코더 ───────────────

def _try_decode_b64(s: str) -> str | None:
    """짧거나 base64 가 아니면 None."""
    cleaned = re.sub(r"\s+", "", s)
    if len(cleaned) < MIN_STRING_LEN:
        return None
    # base64 character set 만 — 잘못된 문자 있으면 skip
    if not re.match(r"^[A-Za-z0-9+/]+=*$", cleaned):
        return None
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_decode_hex(s: str) -> str | None:
    cleaned = re.sub(r"\s+", "", s)
    if len(cleaned) < MIN_STRING_LEN or len(cleaned) % 2 != 0:
        return None
    if not re.match(r"^[0-9a-fA-F]+$", cleaned):
        return None
    try:
        decoded = bytes.fromhex(cleaned)
    except ValueError:
        return None
    return decoded.decode("utf-8", errors="replace")


def _try_decode_hex_escape(s: str) -> str | None:
    """\\x41\\x42... 형태."""
    try:
        codepoints = re.findall(r"\\x([0-9a-fA-F]{2})", s)
        if not codepoints:
            return None
        return bytes(int(h, 16) for h in codepoints).decode(
            "utf-8", errors="replace",
        )
    except Exception:
        return None


def _try_decode_unicode_escape(s: str) -> str | None:
    """\\u0041\\u0042... 형태."""
    try:
        codepoints = re.findall(r"\\u([0-9a-fA-F]{4})", s)
        if not codepoints:
            return None
        return "".join(chr(int(c, 16)) for c in codepoints)
    except Exception:
        return None


def _try_decode_char_code_array(s: str) -> str | None:
    """'65, 66, 67' → 'ABC'."""
    try:
        nums = [int(n.strip()) for n in s.split(",") if n.strip()]
        if not nums or any(n < 0 or n > 0x10FFFF for n in nums):
            return None
        return "".join(chr(n) for n in nums)
    except (ValueError, OverflowError):
        return None


def _try_decode_url_pct(s: str) -> str | None:
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return None


# ─────────────── 단일 layer 처리 ───────────────

def _process_layer(source: str) -> tuple[str, dict[str, int]]:
    """source 의 모든 인코딩 패턴을 한 번 decode → 디코드 결과 합집합 + stats.

    반환: (decoded_concat_text, stats)
      stats = {"b64_calls": N, "hex_calls": N, ...}
    """
    decoded_chunks: list[str] = []
    stats: dict[str, int] = {}

    def _record(kind: str):
        stats[kind] = stats.get(kind, 0) + 1

    # 1) Python base64.b64decode("...")
    for m in _PY_B64_CALL_RE.finditer(source):
        d = _try_decode_b64(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("py_b64")

    # 2) JS atob("...")
    for m in _JS_ATOB_RE.finditer(source):
        d = _try_decode_b64(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("js_atob")

    # 3) JS Buffer.from(b64, 'base64')
    for m in _JS_BUFFER_B64_RE.finditer(source):
        d = _try_decode_b64(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("js_buffer_b64")

    # 4) Python bytes.fromhex("...")
    for m in _PY_HEX_RE.finditer(source):
        d = _try_decode_hex(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("py_hex")

    # 5) Hex escape literal "\x41..."
    for m in _HEX_ESC_LITERAL_RE.finditer(source):
        d = _try_decode_hex_escape(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("hex_escape")

    # 6) Unicode escape "\uXXXX"
    for m in _UNI_ESC_LITERAL_RE.finditer(source):
        d = _try_decode_unicode_escape(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("unicode_escape")

    # 7) JS String.fromCharCode(65, 66, ...)
    for m in _FROM_CHAR_CODE_RE.finditer(source):
        d = _try_decode_char_code_array(m.group(1))
        if d:
            decoded_chunks.append(d)
            _record("from_char_code")

    # 8) URL percent encoding (긴 sequence)
    for m in _URL_PCT_RE.finditer(source):
        d = _try_decode_url_pct(m.group(1))
        if d and d != m.group(1):
            decoded_chunks.append(d)
            _record("url_pct")

    return ("\n".join(decoded_chunks), stats)


# ─────────────── 메인 API ───────────────

def deobfuscate(
    source: str,
    language: str = "python",
    *,
    max_layers: int = MAX_LAYERS,
) -> DeobfuscationResult:
    """source 에 대해 *iterative* 디코딩.

    layer 1 결과에 또 base64 / hex 패턴이 있으면 layer 2 적용. max_layers
    번까지 또는 결과가 더 이상 변하지 않을 때까지.

    `language` 는 현재 패턴이 보편적이라 사용 안 함 (향후 확장용).
    """
    result = DeobfuscationResult()

    if len(source) > MAX_TOTAL_SIZE:
        # 너무 큰 입력 — 시간/메모리 보호 위해 skip
        return result

    current = source
    accum_stats: dict[str, int] = {}
    for i in range(max_layers):
        decoded, stats = _process_layer(current)
        if not decoded.strip():
            break
        # stats 누적
        for k, v in stats.items():
            accum_stats[k] = accum_stats.get(k, 0) + v
        # 무한 루프 방지: 디코드 결과가 이미 본 layer 와 동일하면 stop
        if decoded in result.decoded_layers:
            break
        result.decoded_layers.append(decoded)
        # 다음 layer 의 입력 = 이번 layer 의 출력 (중첩 디코드)
        current = decoded
        # 결과가 너무 커지면 break
        if sum(len(L) for L in result.decoded_layers) > MAX_TOTAL_SIZE:
            break

    result.layer_count = len(result.decoded_layers)
    result.final_text = "\n".join(result.decoded_layers)
    result.stats = accum_stats
    return result


def augment_source_for_matching(
    source: str, language: str = "python",
) -> str:
    """원본 + 디코드 결과를 합쳐 indicator/regex 매칭용 평탄 텍스트.

    Stage 2/4c 가 이 합본 텍스트를 받으면 obfuscation 우회된 케이스도 매칭 가능.
    원본은 손상 X — 결과는 분석 전용.
    """
    deobf = deobfuscate(source, language)
    if not deobf.has_findings:
        return source
    # 원본 + 디코드 layer 들. 각 layer 사이 주석 marker — 라인 번호는 부정확해지지만
    # *매칭* 목적이라 OK.
    parts = [source]
    for i, layer in enumerate(deobf.decoded_layers, 1):
        parts.append(f"\n# pkgsentinel-deobf-layer-{i} (synthetic)\n{layer}")
    return "\n".join(parts)
