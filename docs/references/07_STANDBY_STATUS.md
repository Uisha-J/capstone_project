# 3일 대기 상태 — 구현 준비 완료

> **작성일: 2026-04-25**
> **예정 재개일: 2026-04-28 (3일 후)**
>
> 그동안 추가로 구현하지 않음. 사용자 지시 있을 때만 재개.

---

## 현재 완료된 작업

### 구현 완료
- [x] Phase A-1: 전 파일 분석 커버리지 (`stage1b_full_source.py`)
- [x] Phase A-2: 문자열 상수 풀 분석 (`string_analysis.py`)
- [x] Phase A-3: 파일 레벨 버전 diff (`stage3b_full_diff.py`)
- [x] Phase B-1: 의존성 트리 재귀 분석 (`stage_dependency.py`)
- [x] Phase B-2: JS tree-sitter AST 파서 (`js_ast_parser.py`)
- [x] Phase B-3: 이상 탐지 기준선 (`anomaly_baseline.py`)
- [x] Phase C-1: 바이너리 분석 (`stage_binary.py`)
- [x] Phase C-2: 샌드박스 동적 분석 (`stage_sandbox.py`)
- [x] Phase D-1: 최근 공급망 공격 수집기 (`osv.py`)
- [x] Phase D-2: 공격 이력 매칭기 (`attack_index.py`, `stage0b_attack_history.py`)
- [x] 파이프라인 전체 통합
- [x] FP 튜닝 (flask → CLEAN, colors → HIGH_RISK, 합성 악성 → MALICIOUS)

### 문서화 완료
- [x] 참고 자료 마스터 인덱스
- [x] 학술 논문 9편 상세 카탈로그
- [x] 공식 표준/프레임워크 11건 상세
- [x] 산업 보고서 11건 상세
- [x] 사용 도구/라이브러리 10건 상세
- [x] 데이터 소스 8건 상세
- [x] 관련 프로젝트 5건 비교

---

## 3일 후 재개 시 우선 작업 목록 (우선순위 순)

### Priority 1 — 47개 악성 지표 카탈로그

> 근거: Unveiling Malicious Logic (2025) — https://arxiv.org/html/2512.12559v1

**작업:**
- `detector/knowledge/malicious_indicators.py` 신규 생성
- 7개 유형 × 47개 지표 정의
- 현재 4 Dimension 과 매핑 레이어 작성 (기존 코드 호환성 유지)

**예상 소요:** 3~4시간

---

### Priority 2 — Taint Slicing 간이 버전 ✅ 완료

> 근거: Taint-Based Code Slicing for LLMs (2025) — https://arxiv.org/html/2512.12313

**완료된 작업:**
- ✅ `detector/stages/taint_slicer.py` 신규 생성 (293라인)
- ✅ Python AST 기반 source/sink/transform 카탈로그
  - SOURCES: `os.environ.get`, `getenv`, `open`, `subprocess.check_output`, …
  - SINKS: `requests.post/put`, `urllib.request.urlopen`, `exec`, `eval`, `os.system`, …
  - TRANSFORMS: `base64.b64encode/decode`, `json.dumps`, `.encode()/.decode()`, …
- ✅ `_PyTaintAnalyzer` (`ast.NodeVisitor`):
  - `visit_Assign`: `var = source(...)` 또는 `var = transform(other_var)` 추적
  - `visit_Call`: sink 인자에 tainted 변수 등장 시 flow 기록
  - `_collect_names_in_expr`: BinOp/Subscript/JoinedStr/Tuple/IfExp 까지 재귀 처리
  - `__import__("X").Y(...)` / `importlib.import_module("X").Y(...)` 난독화 평탄화
- ✅ `slice_for_llm()`: source_line ~ sink_line ±2 라인만 추출
- ✅ Stage 5 (`stage5_llm_review.py`) `taint_slice` 매개변수 추가 — 슬라이스 있으면 우선 사용
- ✅ 파이프라인에 **Stage 4D: Taint Slicing** 신설 (Stage 4C → 4D → 5)
- ✅ 단위 테스트 (`tests/test_taint_slicer.py`): 악성 3 flow / 정상 0 flow / slice 포맷 검증 — ALL OK

**검증 결과:**
- 단순 흐름 (`os.environ.get → base64 → requests.post`) — 탐지
- BinOp 결합 (`(a + b).encode()`) — 탐지
- 난독화 (`__import__("os").environ.get`) — 탐지
- 정상 코드 (`requests.get + json.loads`) — 0 flow (false positive 없음)
- 기존 47-indicator 테스트, 합성 악성 파이프라인 테스트 — 회귀 없음

---

### Priority 3 — LLM Multi-Agent (Stage 5 분리) ✅ 완료

> 근거: LAMPS (2025) — https://arxiv.org/html/2601.12148v1

**완료된 작업:**
- ✅ `detector/stages/stage5_multi_agent.py` 신규 생성 (445라인)
- ✅ 3 개 에이전트 분리:
  - **semantic_agent**: 코드 의미 + taint flow + behavior sequence
  - **diff_agent**: 버전 diff + 신규 API 호출 분석
  - **dependency_agent**: 선언 의존성 vs 패키지 설명 정합성 분석
- ✅ 각 에이전트별 Stub 모드 (오프라인 결정적 규칙)
- ✅ `consensus()` 합의 규칙:
  - 2명 이상 MALICIOUS → MALICIOUS
  - 1명 MALICIOUS + 1명 이상 SUSPICIOUS → MALICIOUS
  - 2명 이상 SUSPICIOUS 이상 → SUSPICIOUS
  - 1명만 MALICIOUS → SUSPICIOUS (보수)
  - 그 외 → BENIGN
- ✅ `agreement_ratio` 동의율 계산 (0.0 ~ 1.0)
- ✅ 기존 `LLMResponse` 와 호환되는 `consensus_to_llm_response()` 어댑터
- ✅ `pipeline.run_pipeline(use_multi_agent=True)` 기본 활성화
- ✅ Stage 5 StageResult payload 에 multi-agent 통계 (avg_agreement, verdicts) 포함
- ✅ 단위 + 통합 테스트 (`tests/test_multi_agent.py`):
  - 5가지 합의 규칙 검증 — 통과
  - 악성 샘플 → MALICIOUS — 통과
  - 정상 샘플 → BENIGN — 통과
  - 어댑터 — 통과

**검증 결과:**
- 합성 악성 (creds → base64 → http.post) 에서 semantic=MALICIOUS / diff=SUSP / dep=SUSP → consensus **MALICIOUS** (agreement 0.67)
- 정상 (json.loads) 에서 3 에이전트 모두 BENIGN → consensus **BENIGN** (agreement 1.00)
- 47-indicator / synthetic_malicious 회귀 — 영향 없음

---

### Priority 4 — OpenSSF Scorecard 연동 ✅ 완료

> 근거: OpenSSF Scorecard — https://scorecard.dev/
> API : https://api.securityscorecards.dev/

**완료된 작업:**
- ✅ `detector/stages/stage_scorecard.py` 신규 생성 (260라인)
- ✅ `extract_github_repo()`: 다양한 URL 형식 (https/.git/git+/git@) 에서 owner/repo 추출
- ✅ `find_github_repo_in_metadata()`: PyPI(`info.project_urls`, `home_page`) + npm(`repository.url`, `homepage`, `versions[latest].repository`) 자동 검색
- ✅ `fetch_scorecard()`: Scorecard API 호출 (8s 타임아웃, 실패 무해)
- ✅ `extract_risk_signals()`: 임계값 미만 항목을 사람-읽기 쉬운 신호 문장으로 변환
  - Maintained < 3, Code-Review < 5, Branch-Protection < 3,
    Token-Permissions < 5, Vulnerabilities < 7, Pinned-Dependencies < 3,
    Dangerous-Workflow < 7
- ✅ `pipeline.py` 에 **Stage 0C: scorecard** 신설 (Stage 0B 직후)
- ✅ `report.package_meta["scorecard"]` 및 `["scorecard_risks"]` 채움
- ✅ 단위 테스트 (`tests/test_scorecard.py`):
  - URL 추출 9 케이스 — 통과
  - PyPI / npm 메타 추출 — 통과
  - 404 처리 — 통과
  - 실 API live fetch (선택, `SCORECARD_LIVE=1`) — 통과 확인 (pallets/flask 7.1/10)

**검증 결과:**
- pallets/flask: overall 7.1/10, 14 checks, 1 risk signal (Code-Review=0)
- chalk/chalk: npm 메타에서 슬러그 정상 추출
- 미존재 repo: 404 → `available=False` 안전 반환 (예외 없음)
- 판정에 영향 없음 (참고 메타로만 사용) — 기존 verdict 회귀 없음

---

### Priority 5 — NIST SSDF 준수 체크 ✅ 완료

> 근거: NIST SP 800-218 (SSDF v1.1) — https://csrc.nist.gov/pubs/sp/800/218/final

**완료된 작업:**
- ✅ `detector/stages/stage_ssdf.py` 신규 생성 (300라인)
- ✅ 11 개 항목 평가:
  - **PO.4.1** Security policy / report channel
  - **PS.1.1** File integrity protection (signed releases)
  - **PS.2.1** Software change history disclosed
  - **PS.3.1** SBOM provided
  - **PW.4.1** Component actively maintained
  - **PW.4.4** Authoritative source (PyPI/npm)
  - **PW.4.5** Component integrity verifiable (PyPI sha256, npm integrity)
  - **PW.7.1** Code review policy (PR-based)
  - **PW.8.1** Test/scan automation (SAST/Fuzzing)
  - **RV.1.1** No known unpatched vulnerabilities
  - **RV.2.1** Vulnerability reporting channel
- ✅ 각 항목 상태: PASS / FAIL / UNKNOWN + evidence + reference URL
- ✅ Scorecard 와 결합 → 임계값 미달은 FAIL
- ✅ 로컬 파일 검사 (SECURITY.md, CHANGES.*, sbom*.json, cyclonedx*, spdx*) 추가 신호
- ✅ 파이프라인 통합 — `report.package_meta["ssdf"]` 채움
- ✅ 단위 테스트 (`tests/test_ssdf.py`):
  - 잘 관리된 패키지 → 10/11 PASS
  - 방치된 패키지 → 7 FAIL / 3 UNK / 1 PASS
  - 스코어카드 없음 → 로컬 신호로 4 PASS
  - npm `dist.integrity` 인식 → PW.4.5 PASS

**판정에 직접 영향 없음** — 메타 정보로만 사용.

---

### Priority 6 — Sequential Pattern Mining ✅ 완료

> 근거: Unveiling Malicious Logic (2025) — https://arxiv.org/html/2512.12559v1

**완료된 작업:**
- ✅ `detector/stages/sequence_patterns.py` 신규 생성 (220라인)
- ✅ Slot 모델 (`SeqSlot(dim, min, max)`) — dimension 별 정규식풍 반복
- ✅ 6개 시퀀스 패턴 카탈로그:
  - **SP-001** Credential exfiltration: `INFO{1,5} → ENCODE{0,3} → DATA_SEND{1,2}`
  - **SP-002** Download-and-execute: `DATA{1,2} → EXEC{1,2}`
  - **SP-003** Encoded payload execution: `ENCODE{1,3} → EXEC{1,2}`
  - **SP-004** System reconnaissance + exfil: `INFO{2,10} → DATA_SEND{1,2}`
  - **SP-005** Info-driven execution: `INFO{1,3} → EXEC{1,2}`
  - **SP-006** Full kill-chain: `INFO{1,10} → ENCODE{1,5} → EXEC{1,3} → DATA{1,3}`
- ✅ `mine(behavior)` 탐욕적 매칭 — 파일별·패턴별 1회 매칭
- ✅ `_sequence_match_to_evidence()` Evidence 변환
- ✅ 파이프라인 **Stage 4E** 신설
- ✅ 단위 테스트 (`tests/test_sequence_patterns.py`):
  - Credential exfil → SP-001 — 통과
  - Encoded exec → SP-003 — 통과
  - Recon → SP-001 + SP-004 — 통과
  - Benign → 0 matches — 통과

**검증 결과:**
- 정상 코드(`requests.get + json.loads`) 0 매칭 — false positive 없음
- 합성 악성 시퀀스에서 패턴 코드 정확히 매칭

---

### Priority 7 — SLSA 레벨 조회 ✅ 완료

> 근거:
>   - SLSA v1.0 — https://slsa.dev/
>   - npm provenance — https://docs.npmjs.com/generating-provenance-statements
>   - PEP-740 (PyPI Index Attestations) — https://peps.python.org/pep-0740/

**완료된 작업:**
- ✅ `detector/stages/stage_slsa.py` 신규 생성 (200라인)
- ✅ npm 메타 분석:
  - `versions[latest].dist.attestations` 존재 → provenance 인정
  - `versions[latest].dist.signatures` 존재 → signed
  - 둘 다 → L2 / 하나만 → L1 / 없음 → L0
- ✅ PyPI 메타 분석:
  - `urls[].has_attestations` (PEP-740) → L2
  - sha256 만 있으면 무결성 신호만 (note)
- ✅ 결과: `SLSALevel` (L0 / L1 / L2 / L3+ / UNKNOWN), `has_provenance`, `has_signature`, `builder_url`, `source_uri`
- ✅ 파이프라인 **Stage 0D** 신설 (Stage 0C 직후)
- ✅ `report.package_meta["slsa"]` 채움
- ✅ 단위 테스트 (`tests/test_slsa.py`):
  - 5 케이스 (no meta / npm 무 / npm 유 / PyPI 무 / PyPI 유) — 통과
  - 라이브 sigstore@npm 4.x — provenance 인식 확인

**검증 결과:**
- npm sigstore: L2 (provenance + signed)
- PyPI sigstore: L0 (PEP-740 미배포 단계)
- 판정에 직접 영향 없음 (참고 메타) — 기존 verdict 회귀 없음

---

### Priority 8 — CycloneDX VEX 출력 ✅ 완료

> 근거: CycloneDX v1.5/1.6 — https://cyclonedx.org/
>        VEX (Vulnerability Exploitability eXchange) — https://cyclonedx.org/capabilities/vex/

**완료된 작업:**
- ✅ `detector/stages/stage_vex.py` 신규 생성 (180라인)
- ✅ `to_cyclonedx(report)` — `AnalysisReport` → CycloneDX v1.5 dict
- ✅ `to_json(report)` — JSON 문자열 직렬화
- ✅ `pipeline.format_cyclonedx(report)` 공개 헬퍼
- ✅ purl 생성 (PyPI / npm)
- ✅ Verdict → analysis.state 매핑:
  - MALICIOUS / HIGH_RISK → exploitable
  - SUSPICIOUS / ERROR / CANNOT_ANALYZE → in_triage
  - CLEAN → not_affected
- ✅ Severity → CycloneDX rating.severity (high/medium/low)
- ✅ component.properties 에 verdict, scorecard score, slsa level, ssdf pass 비율 포함
- ✅ vulnerabilities[] 각각:
  - `id` = TTP/Indicator code
  - `source.name` = MITRE ATT&CK / OWASP / GHSA 등
  - `analysis.state` = LLM verdict 별 매핑
  - `analysis.detail` = behavior sequence + 파일/라인
  - `properties` = vector_similarity, confidence, llm_model, llm_verdict
- ✅ 단위 테스트 (`tests/test_vex.py`):
  - 기본 구조 — 통과
  - state 매핑 4 케이스 — 통과
  - component properties (5종) — 통과
  - JSON 라운드트립 — 통과
  - npm purl — 통과

---

### Priority 9 — 벤치마크 실행 ✅ 하니스 구현 완료 (실데이터 대기)

> 근거: NPM Benchmark (2025) — https://arxiv.org/html/2603.27549

**완료된 작업:**
- ✅ `detector/benchmarks/__init__.py` 패키지 신설
- ✅ `detector/benchmarks/harness.py` 신규 생성 (270라인)
  - `BenchmarkRow` (입력) / `BenchmarkResult` (개별) / `BenchmarkSummary` (집계)
  - CSV / JSONL 양쪽 로더
  - `run_benchmark(rows, max_packages, output_jsonl, pipeline_kwargs)`
  - Precision / Recall / F1 / Accuracy 자동 산출
  - by-label breakdown, 평균 수행 시간
  - 점진적 출력 (25개마다 진행 로그)
  - argparse CLI: `--ecosystem`, `--max`, `--output`, `--summary`,
    `--llm-mode`, `--single-agent`
- ✅ `detector/benchmarks/sample_dataset.csv` 5행 mini 샘플
- ✅ 단위 테스트 (`tests/test_benchmark_harness.py`) — 모킹 사용:
  - basic 4-case (2 mal + 2 benign) → P=R=F1=1.0
  - FP 케이스 → P=0.5
  - FN 케이스 → R=0.0
  - error/cannot_analyze 처리
  - CSV 로더 5 행 파싱

**대기 작업 (실데이터 필요):**
- ⏳ NPM Benchmark 데이터셋 (6,420 + 7,288) 다운로드
- ⏳ PyPI 데이터셋 다운로드
- ⏳ Claude `/security-review` 비교 실행
- ⏳ 결과 표 작성

**사용 예:**
```
python -m detector.benchmarks.harness data/npm_benchmark.csv \
    --ecosystem npm --max 500 --output results.jsonl --summary summary.json
```

---

### Priority 10 — MITRE ATLAS + OWASP LLM Top 10 수집기 ✅ 완료

> 근거:
>   - MITRE ATLAS — https://atlas.mitre.org/
>   - OWASP Top 10 for LLM Applications v1.1 — https://genai.owasp.org/llm-top-10/

**완료된 작업:**
- ✅ `detector/knowledge/mitre_atlas.py` 신규 (210라인)
  - `AtlasTactic` (11 tactic enum)
  - `AtlasTechnique` (id/name/tactic/description/url/related_supply_chain/detection_hints)
  - 9 개 ATLAS 기법 카탈로그 (8 supply-chain 관련):
    - AML.T0010 / .001 / .002 / .003 / .004 (ML Supply Chain Compromise)
    - AML.T0019 (Publish Poisoned Datasets)
    - AML.T0020 (Publish Hallucinated Entities) — 슬롭스쿼팅 직접 매칭
    - AML.T0050 (Command and Scripting Interpreter)
    - AML.T0048 (External Harms)
- ✅ `detector/knowledge/owasp_llm.py` 신규 (180라인)
  - 10 개 OWASP LLM Top 10 (v1.1) 항목 전부
  - LLM05 (Supply Chain Vulnerabilities) + LLM09 (Overreliance) 슬롭스쿼팅 매핑
  - `map_verdict_to_owasp()` — 우리 verdict → OWASP IDs 매핑
- ✅ 파이프라인 연동 — `report.package_meta["owasp_llm_top10"]` 및 `["mitre_atlas"]` 자동 채움
- ✅ 단위 테스트 (`tests/test_atlas_owasp.py`):
  - ATLAS 통계 / get / 슬롭스쿼팅 항목 — 통과
  - OWASP 기본 / LLM05 / verdict 매핑 5 케이스 — 통과

---

## 완료 시 예상 최종 상태

위 10개 작업 완료 시:
- **탐지 세밀도**: 현재 4 Dimension → 47 지표 (약 12배 증가)
- **LLM 비용**: Taint slicing 으로 토큰 수 50~70% 감소 추정
- **판정 해석성**: Multi-agent 로 근거 분리 제시
- **공신력**: OpenSSF + NIST + SLSA + CycloneDX 4중 매핑
- **검증**: 실제 벤치마크 데이터로 Precision/Recall 수치 확보

---

## 복귀 시 체크리스트

3일 후 재개하는 경우 이 순서로 진행:

1. [ ] 본 문서 재열람
2. [ ] `references/` 디렉토리 내 6개 카탈로그 재훑어보기
3. [ ] `detector_engine_design.md` 재확인
4. [ ] 로컬 상태 확인: `git status`, `docker ps`, 캐시 파일 유효성
5. [ ] Priority 1 (47 지표 카탈로그) 부터 순차 시작

---

## 재개 시 유의사항

- OSV 캐시는 2026-04-24 시점. 필요 시 재수집:
  ```
  python -m detector.knowledge.osv PyPI
  python -m detector.knowledge.osv npm
  ```
- MITRE 캐시는 2026-04-24 시점. 최신 갱신 필요 시:
  ```
  python -m detector.knowledge.mitre_attack
  python -m detector.knowledge.embedder
  ```
- Python 가상환경 및 설치된 패키지 확인:
  - `tree-sitter`, `tree-sitter-javascript`
  - `sentence-transformers`
  - `pefile`, `pyelftools`
  - `fpdf2`, `python-docx`, `anthropic`
