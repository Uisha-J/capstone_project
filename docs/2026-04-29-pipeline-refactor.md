# 2026-04-29 — pipeline.py 리팩터링 보고

## 배경

`src/pkgsentinel/pipeline.py` 가 1,330 줄이었고 그 중 `run_pipeline()` 단일
함수가 ~650 줄을 차지. 단계 호출 + Evidence 변환 + 캐시 + 리포트 조립이
한 함수에 뭉쳐 있어 가독성/유지보수가 어려웠음. 두 단계로 분할.

## 결과 요약

| 항목 | 변경 |
|---|---|
| `pipeline.py` | 1,330 → 957 lines (-28%) |
| 신규 모듈 | `evidence/`, `reporting/`, `cli.py`, `_pipeline_state.py` |
| 테스트 | **82 passed, 0 failed** (Python 3.11.15) |
| 회귀 | 0 건 |

## 커밋

| SHA | 내용 |
|---|---|
| `99f37d1` | Option A — 변환기/리포팅/CLI 추출 |
| `5623ff4` | Option B — PipelineContext + PipelineOptions 도입 |

## Option A: 파일 분할

`pipeline.py` 안에 박혀 있던 보조 코드를 의존 방향이 단방향인 모듈로 이동.

```
src/pkgsentinel/
  evidence/
    converters.py   # _xxx_to_evidence 7개 + STANDALONE_WEAK_INDICATORS
    snippets.py     # find_file_seq, snippet_for, match_confidence
  reporting/
    serialize.py    # report_to_serializable (캐시 저장용)
    formats.py      # format_report, format_cyclonedx
  cli.py            # 기존 __main__ 블록을 main() 으로 추출
```

**Backward-compat**: `pipeline.py` 가 새 모듈 심볼을 underscore alias 로
re-import (`as _xxx`). 따라서:
- `run_pipeline` 본문 한 줄도 안 바뀜
- `worker.py` 의 `from ..pipeline import _report_to_serializable`,
  `__main__.py` 의 `from .pipeline import format_report` 등 기존
  import 경로 그대로 작동

## Option B: 컨텍스트 객체 도입

13 개 함수 인자와 6 개 흐르는 지역변수를 두 dataclass 로 묶음
(`src/pkgsentinel/_pipeline_state.py`).

```python
@dataclass
class PipelineOptions:
    llm_mode: str = "stub"
    enable_deps: bool = False
    enable_sandbox: bool = False
    verbose: bool = False
    use_multi_agent: bool = True
    integrity_mode: str = "strict"
    use_cache: bool = True
    force_rescan: bool = False
    use_threat_filter: bool = True

@dataclass
class PipelineContext:
    package: str
    ecosystem: Ecosystem
    version: str | None = None
    options: PipelineOptions = field(default_factory=PipelineOptions)
    # 누적
    stage_results: list[StageResult] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    # 단계간 흐름
    ext: FullSourceExtract | None = None
    behavior: BehaviorReport | None = None
    diff: object | None = None
    description: str | None = None
```

`run_pipeline` 본문의 ~140 곳 (`stage_results`, `evidence_list`, `ext`,
`behavior`, `diff`, `description`, 8 개 옵션 플래그) 를 모두 `ctx.X` /
`ctx.options.X` 참조로 전환. 호출 시그니처는 그대로 유지.

## 검증

- Python 3.11.15 + 전체 deps (numpy, sentence-transformers, sqlcipher3,
  anthropic, openai 등) 환경 구축
- `pytest tests/` 전 14 개 파일 모두 실행
- **82 passed, 82 warnings, 0 failed** (warnings 은 기존 코드의 `return`-style
  테스트 패턴 — 본 리팩터와 무관)
- 영향권 핵심인 `test_benchmark_harness` (5 tests, `run_pipeline` 직접 사용)
  포함 전부 통과

## 도중 이슈

Option B mass-replace 시 SyntaxError 3 건 — `description=value` 형태의
kwarg 라벨이 `ctx.description=value` 로 잘못 치환됨. 정규식 lookbehind 는
attribute access 는 막았지만 kwarg 위치는 못 막아 발생. 3 곳 수동 복원 후
전 테스트 통과.

## 다음 단계 (미진행)

원 계획의 **Step 3: StageHandler protocol** — 13 개 단계 블록을 동일
인터페이스의 핸들러 클래스로 추출하고, `run_pipeline` 을 핸들러 리스트
순회 루프로 축약. Option B 의 `PipelineContext` 가 그 토대.

```python
class StageHandler(Protocol):
    name: str
    required: bool
    def run(self, ctx: PipelineContext) -> StageOutcome: ...
```

추출 시 try/except 보일러플레이트(현재 23 곳)도 `_execute_stage()` 한 곳으로
수렴 가능. 추가로 `stages/_policy.py` 로 "필수/선택/게이트" 정책 분리,
`StageResult.payload: dict` 의 단계별 TypedDict 타입화 등이 후속 작업.
