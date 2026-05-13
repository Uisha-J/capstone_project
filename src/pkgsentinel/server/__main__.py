"""pkgsentinel server CLI 진입점.

사용:
  python -m pkgsentinel.server [--bind 0.0.0.0] [--port 8787] [--debug]

prod 에서는 gunicorn 권장:
  gunicorn -w 4 -b 0.0.0.0:8787 pkgsentinel.server:app
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from .. import _dotenv as _aislopsq_dotenv
from .app import create_app

_aislopsq_dotenv.load()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="pkgsentinel HTTP server")
    p.add_argument("--bind", default=os.environ.get("PKGSENTINEL_BIND", "0.0.0.0"))
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("PKGSENTINEL_PORT", "8787")))
    p.add_argument("--debug", action="store_true",
                   help="Flask debug 모드 (dev 전용)")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # HMAC secret 경고
    if not os.environ.get("PKGSENTINEL_HMAC_SECRET"):
        print(
            "WARNING: PKGSENTINEL_HMAC_SECRET not set — HMAC 검증 비활성 (dev only)",
            file=sys.stderr,
        )

    app = create_app()
    print(
        f"pkgsentinel server listening on http://{args.bind}:{args.port}",
        file=sys.stderr,
    )
    app.run(host=args.bind, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
