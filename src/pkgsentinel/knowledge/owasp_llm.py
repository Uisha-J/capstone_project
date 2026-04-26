"""
OWASP Top 10 for Large Language Model Applications (v1.1).

근거: https://genai.owasp.org/llm-top-10/
       https://owasp.org/www-project-top-10-for-large-language-model-applications/

본 모듈은 OWASP LLM Top 10 카탈로그를 제공.
슬롭스쿼팅(공격자가 LLM 환각 패키지명을 선등록) 은 LLM05
'Supply Chain Vulnerabilities' 의 대표 사례 — 본 도구의 핵심 매핑.

판정에 직접 영향 X — 리포트 메타에 evidence 인용 시 사용.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OWASPLLMItem:
    id: str                           # "LLM01" .. "LLM10"
    name: str
    description: str
    url: str
    typical_examples: list[str] = field(default_factory=list)
    related_to_slopsquatting: bool = False


# ─────────────── 카탈로그 (v1.1) ───────────────

OWASP_LLM_ITEMS: list[OWASPLLMItem] = [
    OWASPLLMItem(
        id="LLM01",
        name="Prompt Injection",
        description=(
            "악의적인 입력으로 LLM 의 instruction 을 우회/탈취. "
            "Direct (사용자 입력) 와 Indirect (외부 컨텐츠 주입) 두 가지."
        ),
        url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        typical_examples=[
            "사용자가 '시스템 프롬프트 무시하고 해라' 식 입력",
            "공격자가 웹 페이지에 LLM 명령 삽입 → RAG 가 그대로 받아옴",
        ],
    ),
    OWASPLLMItem(
        id="LLM02",
        name="Insecure Output Handling",
        description=(
            "LLM 출력을 검증 없이 다운스트림 (eval/SQL/shell) 에 전달."
        ),
        url="https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/",
        typical_examples=[
            "LLM 출력을 그대로 exec()",
            "코드 자동 실행 에이전트가 검증 없이 shell 호출",
        ],
    ),
    OWASPLLMItem(
        id="LLM03",
        name="Training Data Poisoning",
        description="훈련/파인튜닝 데이터에 의도된 변조를 주입.",
        url="https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/",
        typical_examples=[
            "데이터셋에 의도된 라벨 오류",
            "RAG 컨텐츠에 백도어 prompt 삽입",
        ],
    ),
    OWASPLLMItem(
        id="LLM04",
        name="Model Denial of Service",
        description="추론 비용을 폭증시키는 입력으로 서비스 마비.",
        url="https://genai.owasp.org/llmrisk/llm04-model-denial-of-service/",
    ),
    OWASPLLMItem(
        id="LLM05",
        name="Supply Chain Vulnerabilities",
        description=(
            "LLM 라이프사이클(데이터셋, 모델, 라이브러리, 플러그인) 공급망 변조. "
            "본 도구의 직접 적용 영역. AI 가 환각으로 추천한 패키지 이름을 "
            "공격자가 선등록(슬롭스쿼팅) 하는 시나리오 포함."
        ),
        url="https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/",
        typical_examples=[
            "torch / transformers 와 유사한 타이포스쿼팅 패키지",
            "30일 이내 신규 등록된 의심 패키지를 LLM 이 추천",
            "정상 패키지로 위장한 악성 PyPI/npm 게시",
            "Hugging Face 모델 ckpt 에 pickle 실행 코드 삽입",
        ],
        related_to_slopsquatting=True,
    ),
    OWASPLLMItem(
        id="LLM06",
        name="Sensitive Information Disclosure",
        description="LLM 이 훈련 데이터/시스템 프롬프트의 민감 정보를 출력.",
        url="https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/",
    ),
    OWASPLLMItem(
        id="LLM07",
        name="Insecure Plugin Design",
        description="LLM 플러그인 인터페이스가 권한 분리/검증을 결여.",
        url="https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/",
    ),
    OWASPLLMItem(
        id="LLM08",
        name="Excessive Agency",
        description="LLM 에이전트에 과도한 도구/권한 부여로 의도치 않은 동작.",
        url="https://genai.owasp.org/llmrisk/llm08-excessive-agency/",
    ),
    OWASPLLMItem(
        id="LLM09",
        name="Overreliance",
        description="LLM 출력을 비판 없이 신뢰해 잘못된 의사결정/코드 채택.",
        url="https://genai.owasp.org/llmrisk/llm09-overreliance/",
        typical_examples=[
            "환각된 패키지 import 문을 검증 없이 실행 (= 슬롭스쿼팅 트리거)",
        ],
        related_to_slopsquatting=True,
    ),
    OWASPLLMItem(
        id="LLM10",
        name="Model Theft",
        description="모델 가중치/구조를 비인가 추출.",
        url="https://genai.owasp.org/llmrisk/llm10-model-theft/",
    ),
]


# ─────────────── 헬퍼 ───────────────

def get(id: str) -> Optional[OWASPLLMItem]:
    for it in OWASP_LLM_ITEMS:
        if it.id == id:
            return it
    return None


def slopsquatting_related() -> list[OWASPLLMItem]:
    return [it for it in OWASP_LLM_ITEMS if it.related_to_slopsquatting]


def stats() -> dict:
    return {
        "total": len(OWASP_LLM_ITEMS),
        "slopsquatting_related": sum(
            1 for it in OWASP_LLM_ITEMS if it.related_to_slopsquatting
        ),
        "ids": [it.id for it in OWASP_LLM_ITEMS],
    }


# ─────────────── 슬롭스쿼팅 시그니처 매핑 ───────────────
# 본 도구가 어떤 verdict 일 때 어떤 OWASP LLM 항목을 인용할지

def map_verdict_to_owasp(verdict_str: str) -> list[str]:
    """우리 verdict → 인용할 OWASP LLM 항목 IDs."""
    v = verdict_str.upper()
    if v in ("MALICIOUS", "HIGH_RISK"):
        return ["LLM05", "LLM09"]
    if v == "SUSPICIOUS":
        return ["LLM05"]
    if v == "CANNOT_ANALYZE":
        return ["LLM05", "LLM09"]
    return []


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    s = stats()
    print(f"OWASP LLM Top 10: {s['total']} items")
    print(f"  slopsquatting-related: {s['slopsquatting_related']}")
    print()
    print("Items:")
    for it in OWASP_LLM_ITEMS:
        flag = " [SLOP]" if it.related_to_slopsquatting else ""
        print(f"  [{it.id}]{flag} {it.name}")
        print(f"    {it.description[:120]}")
        if it.typical_examples:
            for ex in it.typical_examples[:1]:
                print(f"    ex: {ex}")
    print()
    print("Verdict mapping:")
    for v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "CLEAN", "CANNOT_ANALYZE"):
        ids = map_verdict_to_owasp(v)
        print(f"  {v:<14} -> {ids}")
