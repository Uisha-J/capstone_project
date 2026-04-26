# 사용 도구 및 라이브러리 (10건)

> 본 프로젝트 구현에서 실제 사용하거나 참고한 도구.

---

## 4.1 Tree-sitter ★ (현재 V2 사용)

> **증분 파싱 라이브러리**

| 항목 | 값 |
|---|---|
| 공식 | https://tree-sitter.github.io/tree-sitter/ |
| GitHub 본체 | https://github.com/tree-sitter/tree-sitter |
| GitHub Issue (관련) | https://github.com/tree-sitter/tree-sitter/issues/4476 |

### 4.1.1 Tree-sitter JavaScript

| 항목 | 값 |
|---|---|
| Python 패키지 | `tree-sitter-javascript` (PyPI) |
| Haskell 바인딩 문서 | https://hackage.haskell.org/package/tree-sitter-typescript-0.4.1.0/docs/TreeSitter-TypeScript-AST.html |
| Haskell 최신 | https://hackage.haskell.org/package/tree-sitter-typescript-0.4.2.0/docs/TreeSitter-TypeScript-AST.html |

### 4.1.2 Tree-sitter 사용 가이드 (블로그)

| 항목 | 값 |
|---|---|
| Medium | https://medium.com/@email2dineshkuppan/semantic-code-indexing-with-ast-and-tree-sitter-for-ai-agents-part-1-of-3-eb5237ba687a |

**V2 내 사용:** `detector/stages/js_ast_parser.py`

---

## 4.2 Sentence-Transformers ★ (현재 V2 사용)

> **문장 임베딩 모델**

| 항목 | 값 |
|---|---|
| 공식 | https://www.sbert.net/ |
| Python 패키지 | `sentence-transformers` |
| 사용 모델 | `all-MiniLM-L6-v2` |

**V2 내 사용:** `detector/knowledge/embedder.py`

---

## 4.3 pgvector

> **PostgreSQL 벡터 검색 확장**

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/pgvector/pgvector |

**V2 계획:** 지식 DB 대규모화 시 메모리 인덱스 → pgvector 전환

---

## 4.4 Qdrant

> **벡터 검색 엔진**

| 항목 | 값 |
|---|---|
| 공식 | https://qdrant.tech/ |

**V2 계획:** pgvector 대안

---

## 4.5 Anthropic Claude

> **LLM API (V2 Stage 5 에서 사용)**

| 항목 | 값 |
|---|---|
| Anthropic 공식 문서 | https://docs.anthropic.com/en/docs/build-with-claude |
| Claude Code GitHub Action | https://github.com/anthropics/claude-code-action |

**V2 내 사용:** `detector/stages/stage5_llm_review.py`

---

## 4.6 Python 바이너리 분석 (현재 V2 사용)

### 4.6.1 pefile

| 항목 | 값 |
|---|---|
| Python 패키지 | `pefile` (PyPI) |
| 용도 | Windows PE 바이너리 import 테이블 분석 |

### 4.6.2 pyelftools

| 항목 | 값 |
|---|---|
| Python 패키지 | `pyelftools` (PyPI) |
| 용도 | Linux ELF 심볼 테이블 분석 |

**V2 내 사용:** `detector/stages/stage_binary.py`

---

## 4.7 Docker (현재 V2 사용)

> **컨테이너 격리**

| 항목 | 값 |
|---|---|
| 공식 | https://www.docker.com/ |

**V2 내 사용:** `detector/stages/stage_sandbox.py` — 샌드박스 격리 실행

---

## 4.8 fpdf2 (현재 V2 사용)

> **Python PDF 생성**

| 항목 | 값 |
|---|---|
| PyPI | `fpdf2` |

**V2 내 사용:** 보고서 PDF 변환 (`gen_overview_pdf.py`)

---

## 4.9 python-docx (현재 V2 사용)

> **Python Word 문서 생성**

| 항목 | 값 |
|---|---|
| PyPI | `python-docx` |

**V2 내 사용:** `gen_docx.py`

---

## 4.10 markitdown (현재 V2 사용)

> **Microsoft 의 문서 → Markdown 변환**

| 항목 | 값 |
|---|---|
| PyPI | `markitdown[pptx]` |

---

## 4.11 FastAPI (V1/V2 사용)

> **Python 웹 프레임워크 (API 서버)**

| 항목 | 값 |
|---|---|
| 공식 | https://fastapi.tiangolo.com/ |

---

## 4.12 rapidfuzz (V1 에서 사용)

> **편집거리 빠른 계산**

| 항목 | 값 |
|---|---|
| PyPI | `rapidfuzz` |

---

## 4.13 httpx (V1 에서 사용)

> **비동기 HTTP 클라이언트**

| 항목 | 값 |
|---|---|
| PyPI | `httpx` |

---

## 4.14 n8n (V1 에서 사용)

> **워크플로우 자동화**

| 항목 | 값 |
|---|---|
| 공식 | https://n8n.io/ |

---

## 4.15 VS Code Extension API

> **VSCode 확장 개발**

| 항목 | 값 |
|---|---|
| 공식 | https://code.visualstudio.com/api |

**V2 내 사용:** `vscode-slop-detector/`

---

## 4.16 Chrome Extension (Manifest V3)

> **Chrome 확장프로그램 개발**

| 항목 | 값 |
|---|---|
| 공식 | https://developer.chrome.com/docs/extensions/mv3/intro/ |

**V2 내 사용:** `slop-detector-extension/`
