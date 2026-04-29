"""
Stage 5 — LLM 이중 검증.

우리 엔진이 추출한 Behavior Sequence + 매칭된 TTP + 코드 스니펫을
컨텍스트로 제공하고, LLM이 재판단하도록 한다.

현재는 두 가지 모드:
  1. `claude`   : 실제 Anthropic API 호출 (ANTHROPIC_API_KEY 필요)
  2. `stub`     : 결정적 규칙 기반 stub (API 키 없을 때 개발/테스트용)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Literal

from ..schema import LLMVerdict
from .stage2_behavior import FileSequence
from .stage4_ttp_match import TTPMatch

# ─────────────── LLM 응답 ───────────────

@dataclass
class LLMResponse:
    verdict: LLMVerdict
    reasoning: str
    most_convincing_evidence: str
    model: str


# ─────────────── 프롬프트 ───────────────

SYSTEM_PROMPT = (
    "You are a software supply chain security analyst. "
    "Given behavior sequences extracted from a package and TTP matches "
    "from official frameworks (MITRE ATT&CK, etc.), determine whether "
    "the package performs a security-relevant malicious action. "
    "Your reply MUST be valid JSON with fields: "
    "verdict (malicious | suspicious | benign), reasoning (string), "
    "most_convincing_evidence (string). No other output."
)


def _build_user_prompt(
    package: str,
    version: str,
    ecosystem: str,
    file_seq: FileSequence,
    ttp_matches: list[TTPMatch],
    code_snippet: str,
    version_diff_summary: str | None = None,
    taint_slice: str | None = None,
) -> str:
    ttp_block = ""
    if ttp_matches:
        lines = ["Matched TTPs:"]
        for m in ttp_matches[:5]:
            lines.append(
                f"- {m.ttp.ttp_id} ({m.ttp.ttp_source.value}): {m.ttp.ttp_name} "
                f"(similarity {m.similarity:.2f}, severity {m.ttp.severity.value})"
            )
            desc = m.ttp.description.replace("\n", " ")[:300]
            lines.append(f"  Description: {desc}")
        ttp_block = "\n".join(lines)

    diff_block = f"\n\nVersion diff: {version_diff_summary}" if version_diff_summary else ""

    # taint slice 가 존재하면 우선 첨부, 없으면 일반 code snippet 사용
    if taint_slice and taint_slice.strip():
        evidence_label = "Taint flows (source -> sink slices):"
        evidence_body = taint_slice[:1800]
    else:
        evidence_label = "Code evidence:"
        evidence_body = code_snippet[:1500]

    return f"""Package: {package} {version} ({ecosystem})

File: {file_seq.path}
Behavior sequence: {' -> '.join(file_seq.sequence)}
Dimensions: {', '.join(d.value for d in file_seq.dimensions)}

{ttp_block}{diff_block}

{evidence_label}
```
{evidence_body}
```

Respond with JSON only (fields: verdict, reasoning, most_convincing_evidence).
"""


# ─────────────── Anthropic 호출 ───────────────

def _call_claude(system: str, user: str, model: str) -> str:
    """
    Anthropic SDK 호출. 설치/키 없으면 RuntimeError.
    """
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError(
            "anthropic 패키지가 설치되지 않았습니다. pip install anthropic"
        ) from e

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY 환경변수 미설정")

    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=1000,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    # 텍스트 첫 블록
    for block in resp.content:
        if hasattr(block, "text"):
            return block.text
    raise RuntimeError("claude 응답에 text 블록이 없음")


def _parse_llm_json(text: str) -> dict:
    """LLM 응답을 JSON 으로 파싱. 앞뒤 코드블록 제거."""
    t = text.strip()
    if t.startswith("```"):
        # ```json ... ``` 제거
        lines = t.splitlines()
        t = "\n".join(line for line in lines if not line.startswith("```"))
    return json.loads(t)


# ─────────────── Stub (오프라인 모드) ───────────────

def _stub_review(file_seq: FileSequence, ttp_matches: list[TTPMatch]) -> LLMResponse:
    """
    LLM API 없이 동작하는 결정적 stub.

    매우 보수적으로 동작:
      - 정답은 실제 Claude API 에서만 가능
      - stub 는 대부분 BENIGN 이고, 매우 명확한 조합만 SUSPICIOUS/MALICIOUS
    """
    dims = set(file_seq.dimensions)
    from ..schema import AttackDimension

    # 명확한 credential theft 조합: Info + Encoding + Network 세 가지 모두
    creds_combo = {
        AttackDimension.INFORMATION_READING,
        AttackDimension.ENCODING,
        AttackDimension.DATA_TRANSMISSION,
    }
    # 명확한 remote exec 조합: Network + Execution
    remote_exec = {
        AttackDimension.DATA_TRANSMISSION,
        AttackDimension.PAYLOAD_EXECUTION,
    }

    # Setup/install hook 파일에서 위 조합이 보이면 매우 의심스러움
    is_install_hook = any(
        kw in file_seq.path.lower()
        for kw in ("setup.py", "postinstall", "preinstall")
    )

    if creds_combo.issubset(dims) and is_install_hook:
        return LLMResponse(
            verdict=LLMVerdict.MALICIOUS,
            reasoning="Stub: credential 탈취 체인이 설치 훅 파일에 존재.",
            most_convincing_evidence=f"file={file_seq.path}, creds-theft chain",
            model="stub",
        )

    if creds_combo.issubset(dims):
        return LLMResponse(
            verdict=LLMVerdict.SUSPICIOUS,
            reasoning="Stub: info-read + encode + send 조합 등장 (맥락 검토 필요).",
            most_convincing_evidence=f"file={file_seq.path}",
            model="stub",
        )

    if remote_exec.issubset(dims) and is_install_hook:
        return LLMResponse(
            verdict=LLMVerdict.SUSPICIOUS,
            reasoning="Stub: 설치 훅에서 네트워크 + 실행 조합.",
            most_convincing_evidence=f"file={file_seq.path}",
            model="stub",
        )

    return LLMResponse(
        verdict=LLMVerdict.BENIGN,
        reasoning="Stub: 정적 규칙으로 명확한 공격 패턴 미확인 (실제 판정은 Claude API 필요).",
        most_convincing_evidence="none",
        model="stub",
    )


# ─────────────── 공개 API ───────────────

def review(
    package: str,
    version: str,
    ecosystem: str,
    file_seq: FileSequence,
    ttp_matches: list[TTPMatch],
    code_snippet: str = "",
    version_diff_summary: str | None = None,
    mode: Literal["claude", "stub"] = "stub",
    model: str = "claude-sonnet-4-5",
    taint_slice: str | None = None,
) -> LLMResponse:
    if mode == "stub":
        return _stub_review(file_seq, ttp_matches)

    prompt = _build_user_prompt(
        package, version, ecosystem,
        file_seq, ttp_matches, code_snippet, version_diff_summary,
        taint_slice=taint_slice,
    )
    raw = _call_claude(SYSTEM_PROMPT, prompt, model=model)
    try:
        parsed = _parse_llm_json(raw)
    except Exception as e:
        raise RuntimeError(f"LLM JSON 파싱 실패: {e}\n원문: {raw[:300]}") from e

    return LLMResponse(
        verdict=LLMVerdict(parsed.get("verdict", "benign")),
        reasoning=parsed.get("reasoning", ""),
        most_convincing_evidence=parsed.get("most_convincing_evidence", ""),
        model=model,
    )
