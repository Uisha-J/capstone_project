"""
Pytest 공통 설정.

pyproject.toml [tool.pytest.ini_options] 의 pythonpath 가 src/ 를 sys.path 에
넣어주므로, 각 test 파일에서 `from pkgsentinel.X import Y` 가 그대로 작동한다.

`pip install -e .` 로 설치한 경우엔 pythonpath 설정도 불필요.
"""
from __future__ import annotations

import sys
from pathlib import Path

# 안전망: pytest 설정 없이 직접 실행 (`python tests/test_xxx.py`) 해도 작동하도록.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
