"""
Pytest 공통 설정.

pyproject.toml [tool.pytest.ini_options] 의 pythonpath 가 src/ 를 sys.path 에
넣어주므로, 각 test 파일에서 `from pkgsentinel.X import Y` 가 그대로 작동한다.

`pip install -e .` 로 설치한 경우엔 pythonpath 설정도 불필요.

DB 격리:
- ThreatDB / StageCache / AnalysisCache 는 `src/pkgsentinel/db/data/threat_db.sqlcipher`
  를 영구적으로 사용. 다른 키로 만든 잔재가 있으면 같은 키 테스트도 실패.
- 본 conftest 가 세션 시작 시 그 파일을 제거 (test 간 격리). production 에는 영향 없음.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# 안전망: pytest 설정 없이 직접 실행 (`python tests/test_xxx.py`) 해도 작동하도록.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# 잔재 DB 제거 — pytest 세션 시작 시 한 번. CI 에서는 항상 fresh, 로컬에서도 일관.
_DB_DIR = Path(__file__).resolve().parent.parent / "src" / "pkgsentinel" / "db" / "data"
if _DB_DIR.exists():
    for _f in _DB_DIR.glob("threat_db.sqlcipher*"):
        try:
            _f.unlink()
        except OSError:
            pass

# DB key 환경변수 — CI workflow 와 동일 값. 미설정 시에만 보충.
os.environ.setdefault("AISLOP_DB_KEY", "ci-test-passphrase-do-not-reuse")
