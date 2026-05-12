"""
문자열 상수 풀 분석.

난독화 공격 대응:
  - 소스 파일에서 문자열 리터럴 추출
  - base64 / hex / rot13 / 긴 인코딩 문자열 식별
  - 디코딩 시도 → 결과가 "수상한 형태" 면 플래그
  - 엔트로피 계산 (높으면 난독화 의심)

예:
  payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk="
  → base64 디코드 → "import os; os.system('rm -rf /')" → 위험
"""
from __future__ import annotations

import ast
import base64
import math
import re
from dataclasses import dataclass

# ─────────────── 데이터 구조 ───────────────

@dataclass
class SuspiciousString:
    line: int
    raw: str                      # 원본 문자열 (잘릴 수 있음)
    decoded: str | None           # 디코딩 결과 (가능 시)
    encoding: str                 # 'base64' | 'hex' | 'high_entropy' | 'unknown'
    reason: str                   # 왜 의심스러운가
    entropy: float                # Shannon 엔트로피

    def short(self) -> str:
        s = self.raw
        return s[:80] + "..." if len(s) > 80 else s

    def to_dict(self) -> dict:
        return {
            "line": self.line,
            "raw": self.raw,
            "decoded": self.decoded,
            "encoding": self.encoding,
            "reason": self.reason,
            "entropy": self.entropy,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SuspiciousString:
        return cls(
            line=d["line"],
            raw=d["raw"],
            decoded=d.get("decoded"),
            encoding=d.get("encoding", "unknown"),
            reason=d.get("reason", ""),
            entropy=float(d.get("entropy", 0.0)),
        )


# ─────────────── 엔트로피 ───────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ─────────────── 디코딩 시도 ───────────────

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{20,}$")


def _try_decode(raw: str) -> tuple[str | None, str]:
    """
    returns: (decoded_text, encoding_type)
    디코딩 불가 시 (None, 'unknown')
    """
    stripped = raw.strip()

    # base64 후보
    if _BASE64_RE.match(stripped):
        try:
            padded = stripped + "=" * ((4 - len(stripped) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=False)
            text = decoded_bytes.decode("utf-8", errors="replace")
            # 결과가 주로 printable ASCII 인지 확인 (의미 있는 디코딩인지)
            if sum(c.isprintable() for c in text) / max(len(text), 1) > 0.8:
                return text, "base64"
        except Exception:
            pass

    # hex 후보
    if _HEX_RE.match(stripped):
        try:
            hex_str = stripped.removeprefix("0x")
            if len(hex_str) % 2 == 0:
                decoded_bytes = bytes.fromhex(hex_str)
                text = decoded_bytes.decode("utf-8", errors="replace")
                if sum(c.isprintable() for c in text) / max(len(text), 1) > 0.8:
                    return text, "hex"
        except Exception:
            pass

    return None, "unknown"


# ─────────────── 디코딩 결과 의심도 평가 ───────────────

_SUSPICIOUS_TOKENS = [
    # 실행 관련
    "exec(", "eval(", "subprocess", "os.system", "popen", "spawn",
    "child_process", "Function(", "__import__", "importlib",
    # 네트워크
    "http://", "https://", "requests.", "urllib.", "fetch(",
    "axios.", "net.Socket", "socket.socket",
    # 파일 / 시스템
    "os.environ", "process.env", "open(", "fs.readFile",
    "/etc/passwd", "/.ssh/", "/.aws/", "appdata",
    # 쉘
    " -c ", "bash ", "/bin/sh", "cmd.exe", "powershell",
    " curl ", " wget ", "certutil",
    # 인코딩 체인
    "base64", "atob", "b64decode",
]


def _suspicion_reason(decoded: str) -> str | None:
    lower = decoded.lower()
    for tok in _SUSPICIOUS_TOKENS:
        if tok.lower() in lower:
            return f"decoded contains suspicious token: {tok!r}"
    return None


# ─────────────── Python AST 기반 문자열 수집 ───────────────

def extract_python_strings(source: str) -> list[SuspiciousString]:
    """Python 소스에서 의심 문자열 추출."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    suspicious: list[SuspiciousString] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            raw = node.value
            if len(raw) < 16:  # 짧은 문자열은 노이즈
                continue

            line = getattr(node, "lineno", 0)
            ent = shannon_entropy(raw)

            # 1) 디코딩 시도
            decoded, encoding = _try_decode(raw)
            if decoded:
                reason = _suspicion_reason(decoded)
                if reason:
                    suspicious.append(SuspiciousString(
                        line=line, raw=raw, decoded=decoded,
                        encoding=encoding, reason=reason, entropy=ent,
                    ))
                    continue

            # 2) 엔트로피 매우 높음 (일반 문자열보다 훨씬 랜덤) + 충분히 김
            if len(raw) >= 40 and ent >= 4.5:
                suspicious.append(SuspiciousString(
                    line=line, raw=raw, decoded=None,
                    encoding="high_entropy", reason=f"high entropy ({ent:.2f})",
                    entropy=ent,
                ))

    return suspicious


# ─────────────── JavaScript 정규식 기반 ───────────────

_JS_STRING_RE = re.compile(r"""(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")""")


def extract_js_strings(source: str) -> list[SuspiciousString]:
    """JS 소스에서 의심 문자열 추출 (정규식 기반)."""
    suspicious: list[SuspiciousString] = []
    for i, line in enumerate(source.splitlines(), start=1):
        for m in _JS_STRING_RE.finditer(line):
            raw = m.group(1) or m.group(2) or ""
            if len(raw) < 16:
                continue
            ent = shannon_entropy(raw)

            decoded, encoding = _try_decode(raw)
            if decoded:
                reason = _suspicion_reason(decoded)
                if reason:
                    suspicious.append(SuspiciousString(
                        line=i, raw=raw, decoded=decoded,
                        encoding=encoding, reason=reason, entropy=ent,
                    ))
                    continue

            if len(raw) >= 40 and ent >= 4.5:
                suspicious.append(SuspiciousString(
                    line=i, raw=raw, decoded=None,
                    encoding="high_entropy", reason=f"high entropy ({ent:.2f})",
                    entropy=ent,
                ))
    return suspicious


# ─────────────── 통합 ───────────────

def analyze_strings(path: str, content: str, language: str) -> list[SuspiciousString]:
    if language == "python":
        return extract_python_strings(content)
    if language == "javascript":
        return extract_js_strings(content)
    return []


# ─────────────── 자체 테스트 ───────────────

if __name__ == "__main__":
    sample = '''
import base64

# 평범한 긴 문자열 — 탐지되면 안 됨
msg = "This is a normal long message for logging purposes."

# base64 로 인코딩된 악성 페이로드 — 탐지되어야 함
payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk="

# hex 인코딩 — 탐지되어야 함
key = "0x696d706f7274206f733b206f732e73797374656d2827726d202d7266202f2729"

# 높은 엔트로피 — 탐지될 수 있음
secret = "xK8#mPqR2$vN9wT3!yB5^sF7&jD1*hL4%gA6@kC0(nM8)zH2"

exec(base64.b64decode(payload))
'''
    results = analyze_strings("test.py", sample, "python")
    print(f"found {len(results)} suspicious strings:")
    for r in results:
        print(f"\nL{r.line}: [{r.encoding}] entropy={r.entropy:.2f}")
        print(f"  reason: {r.reason}")
        print(f"  raw:    {r.short()}")
        if r.decoded:
            print(f"  decoded: {r.decoded[:100]}")
