"""
MITRE ATLAS — Adversarial Threat Landscape for AI Systems.

근거: https://atlas.mitre.org/

ATLAS 는 ATT&CK 의 ML/AI 시스템 변형 프레임워크.
본 모듈은 슬롭스쿼팅/AI-supply-chain 시나리오에 직접 관련된
기법(AML.T*) 을 카탈로그화한다.

판정에 직접 영향 주지 않음 — 리포트의 추가 매핑/근거 인용에만 사용.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AtlasTactic(str, Enum):
    RECON = "Reconnaissance"
    RESOURCE = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    ML_ATTACK_STAGING = "ML Attack Staging"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    DEFENSE_EVASION = "Defense Evasion"
    DISCOVERY = "Discovery"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class AtlasTechnique:
    id: str                            # 예: "AML.T0010.002"
    name: str
    tactic: AtlasTactic
    description: str
    url: str
    related_supply_chain: bool = False  # 슬롭스쿼팅 / 패키지 공격 직접 관련 여부
    detection_hints: list[str] = field(default_factory=list)


# ─────────────── 카탈로그 ───────────────

ATLAS_TECHNIQUES: list[AtlasTechnique] = [
    AtlasTechnique(
        id="AML.T0010",
        name="ML Supply Chain Compromise",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description=(
            "공격자가 ML 시스템의 공급망 어딘가(데이터/모델/SW/하드웨어)를 "
            "변조하여 다운스트림 시스템에 침투."
        ),
        url="https://atlas.mitre.org/techniques/AML.T0010/",
        related_supply_chain=True,
        detection_hints=[
            "갑작스런 신규 의존성 추가",
            "비공식 미러 / 동일명 다른 출처",
            "patch 버전에 비정상 코드 추가",
        ],
    ),
    AtlasTechnique(
        id="AML.T0010.001",
        name="Hardware Supply Chain",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description="ML 시스템에 사용되는 하드웨어 변조.",
        url="https://atlas.mitre.org/techniques/AML.T0010.001/",
        related_supply_chain=False,
    ),
    AtlasTechnique(
        id="AML.T0010.002",
        name="ML Supply Chain Compromise: ML Software",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description=(
            "ML 라이브러리/프레임워크/도구에 악성 코드를 주입. "
            "PyPI 의 torch / transformers 등 합법적 이름과 유사한 패키지를 "
            "등록해 install-time 실행하는 슬롭스쿼팅이 대표적."
        ),
        url="https://atlas.mitre.org/techniques/AML.T0010.002/",
        related_supply_chain=True,
        detection_hints=[
            "타이포스쿼팅 이름 (torch ↔ torchs)",
            "setup.py/postinstall 의 install-time 코드",
            "ML 키워드(torch/transformers/sklearn) 의존성 → 비-ML 사이드이펙트",
        ],
    ),
    AtlasTechnique(
        id="AML.T0010.003",
        name="ML Supply Chain Compromise: Data",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description="훈련 데이터셋 변조 (poisoning).",
        url="https://atlas.mitre.org/techniques/AML.T0010.003/",
        related_supply_chain=True,
        detection_hints=[
            "데이터셋 다운로드 URL 의 hash 불일치",
            "dataset 샘플 일부에 의도된 라벨 오류",
        ],
    ),
    AtlasTechnique(
        id="AML.T0010.004",
        name="ML Supply Chain Compromise: Model",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description="사전훈련 모델 가중치 자체 변조.",
        url="https://atlas.mitre.org/techniques/AML.T0010.004/",
        related_supply_chain=True,
        detection_hints=[
            "Hugging Face 모델 hash 불일치",
            "pickle 모델에 임의 코드 실행 가능 객체 포함",
        ],
    ),
    AtlasTechnique(
        id="AML.T0019",
        name="Publish Poisoned Datasets",
        tactic=AtlasTactic.RESOURCE,
        description="공격자가 변조된 데이터셋을 공개 리포지토리에 게시.",
        url="https://atlas.mitre.org/techniques/AML.T0019/",
        related_supply_chain=True,
    ),
    AtlasTechnique(
        id="AML.T0020",
        name="Publish Hallucinated Entities",
        tactic=AtlasTactic.RESOURCE,
        description=(
            "LLM 이 환각으로 추천한 비존재 패키지 이름을 공격자가 선등록 - "
            "본 도구의 핵심 위협 모델."
        ),
        url="https://atlas.mitre.org/techniques/AML.T0020/",
        related_supply_chain=True,
        detection_hints=[
            "30일 이내 신규 등록",
            "다른 LLM 도 같은 이름 추천 (반복성)",
            "공식 PyPI/npm 검색결과 1개 미만",
        ],
    ),
    AtlasTechnique(
        id="AML.T0050",
        name="Command and Scripting Interpreter",
        tactic=AtlasTactic.EXECUTION,
        description="ML 환경에서 임의 코드 실행 (eval, exec, pickle 역직렬화 등).",
        url="https://atlas.mitre.org/techniques/AML.T0050/",
        related_supply_chain=True,
        detection_hints=[
            "torch.load / pickle.loads 입력 검증 부재",
            "config 파일 yaml.load() 사용",
        ],
    ),
    AtlasTechnique(
        id="AML.T0048",
        name="External Harms",
        tactic=AtlasTactic.IMPACT,
        description=(
            "ML 모델/라이브러리 손상이 외부 사용자/시스템 의사결정에 영향. "
            "예: 악성 패키지가 토큰 탈취 → 다운스트림 CI 노출."
        ),
        url="https://atlas.mitre.org/techniques/AML.T0048/",
        related_supply_chain=True,
    ),
]


# ─────────────── 헬퍼 ───────────────

def get(id: str) -> AtlasTechnique | None:
    for t in ATLAS_TECHNIQUES:
        if t.id == id:
            return t
    return None


def supply_chain_relevant() -> list[AtlasTechnique]:
    return [t for t in ATLAS_TECHNIQUES if t.related_supply_chain]


def by_tactic(tac: AtlasTactic) -> list[AtlasTechnique]:
    return [t for t in ATLAS_TECHNIQUES if t.tactic == tac]


def stats() -> dict:
    by_t: dict[str, int] = {}
    for t in ATLAS_TECHNIQUES:
        by_t[t.tactic.value] = by_t.get(t.tactic.value, 0) + 1
    return {
        "total": len(ATLAS_TECHNIQUES),
        "supply_chain_relevant": sum(
            1 for t in ATLAS_TECHNIQUES if t.related_supply_chain
        ),
        "by_tactic": by_t,
    }


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    s = stats()
    print(f"MITRE ATLAS techniques: {s['total']}")
    print(f"  supply-chain relevant: {s['supply_chain_relevant']}")
    print("  by tactic:")
    for k, v in s["by_tactic"].items():
        print(f"    {k:<25} {v}")
    print()
    print("Slopsquatting-relevant techniques:")
    for t in supply_chain_relevant():
        print(f"  [{t.id}] {t.name}")
        print(f"    tactic: {t.tactic.value}")
        print(f"    {t.description[:120]}")
