"""HTTP server — Flask 어댑터.

분리 원칙:
  - pkgsentinel/api/*.py 는 *순수 함수* (handle_analyze 등)
  - pkgsentinel/server/*.py 는 framework 어댑터 (Flask app, routing, env)

이렇게 분리하면:
  - testing: 순수 함수 단위 테스트 만으로 충분
  - swap: FastAPI / aiohttp 로 교체 시 server/ 만 다시 작성
"""

from .app import create_app

__all__ = ["create_app"]
