"""run_pipeline 전반에 걸쳐 흐르는 상태와 입력 옵션 묶음.

PipelineOptions: 동작 플래그 (불변)
PipelineContext: 분석 대상 + 옵션 + 누적 결과 + 단계 간 흐르는 산출물
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .knowledge.package_categories import CategoryGuess
from .schema import Ecosystem, Evidence, StageResult
from .stages.stage1b_full_source import FullSourceExtract
from .stages.stage2_behavior import BehaviorReport


@dataclass
class PipelineOptions:
    """run_pipeline 호출 시 전달되는 동작 플래그.

    분석 결과에는 영향을 주지 않고 어떤 단계를 켜고 끄거나
    무결성/캐싱 정책을 바꾸는 용도.
    """
    llm_mode: str = "claude"
    enable_deps: bool = False
    enable_sandbox: bool = False
    verbose: bool = False
    use_multi_agent: bool = True
    integrity_mode: str = "strict"      # "fast" | "strict" | "paranoid"
    use_cache: bool = True
    force_rescan: bool = False
    use_threat_filter: bool = True


@dataclass
class PipelineContext:
    """파이프라인 전 단계가 공유하는 상태.

    - 입력: package/ecosystem/version + options
    - 누적: stage_results, evidence (각 단계가 append)
    - 흐름: ext, behavior, diff, description (앞 단계가 set, 뒤 단계가 read)
    """
    # 입력 (불변)
    package: str
    ecosystem: Ecosystem
    version: str | None = None
    options: PipelineOptions = field(default_factory=PipelineOptions)

    # 누적 (가변)
    stage_results: list[StageResult] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    # 단계간 흐름
    ext: FullSourceExtract | None = None
    behavior: BehaviorReport | None = None
    diff: object | None = None         # stage3b_full_diff.DiffReport
    description: str | None = None

    # stage_cache 키용. Stage 1B 후 ext.source_files 의 정렬된 path+content sha256 합산.
    # archive 자체의 sha 가 아니라 *분석에 사용된 입력의 sha* — cache 키 일관성 목적.
    archive_sha256: str | None = None

    # 패키지 기능 카테고리 (web_framework / data_science / dev_tool 등).
    # Stage 0 (registry) 후 metadata.description 으로 분류. broad-purpose 카테고리는
    # 좁은 anomaly 검사 스킵 + sequence_patterns / indicator_matcher 의 가드 용.
    category: CategoryGuess | None = None
