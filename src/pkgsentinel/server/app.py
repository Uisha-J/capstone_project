"""Flask app — pkgsentinel HTTP 서버 (#S3).

세 endpoint 노출:
  - POST /api/v1/analyze         (#S1) — 패키지 분석 + 캐시
  - POST /api/v1/runtime-alert   (#R5/#L1) — Falco/Wazuh/Tetragon webhook
  - GET|POST /api/v1/iocs/export (#S2) — 학습 IOC sync

추가:
  - GET  /healthz       — liveness probe (DB 연결 X)
  - GET  /readyz        — readiness probe (DB 연결 O)
  - GET  /metrics       — 단순 카운터 (Prometheus 형식; 의존성 0)

환경 변수:
  PKGSENTINEL_HMAC_SECRET — HMAC 검증용. 미설정 시 검증 skip (dev 모드).
  PKGSENTINEL_PORT        — 기본 8787
  PKGSENTINEL_BIND        — 기본 0.0.0.0
  AISLOP_DB_KEY           — SQLCipher 키 (필수, prod)

사용:
  python -m pkgsentinel.server         # dev 서버 (Flask built-in)
  gunicorn pkgsentinel.server:app      # prod (gunicorn 별도 설치)
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

try:
    from flask import Flask, Response, jsonify, request
except ImportError as e:  # pragma: no cover
    raise RuntimeError(
        "Flask 가 설치되지 않음. 'pip install flask' 또는 "
        "'pip install pkgsentinel[server]' 후 재시도."
    ) from e

from ..api import handle_analyze, handle_iocs_export, handle_runtime_alert

log = logging.getLogger("pkgsentinel.server")

# ─────────────── 단순 in-process 카운터 (Prometheus 호환) ───────────────

_METRICS: dict[str, int] = {
    "pkgsentinel_requests_total": 0,
    "pkgsentinel_analyze_total": 0,
    "pkgsentinel_analyze_cache_hits_total": 0,
    "pkgsentinel_analyze_errors_total": 0,
    "pkgsentinel_runtime_alert_total": 0,
    "pkgsentinel_iocs_export_total": 0,
    "pkgsentinel_hmac_failures_total": 0,
}


def _bump(key: str, n: int = 1) -> None:
    _METRICS[key] = _METRICS.get(key, 0) + n


def _get_secret() -> str | None:
    """HMAC secret env 조회. 빈 문자열은 None 으로 취급."""
    s = os.environ.get("PKGSENTINEL_HMAC_SECRET", "").strip()
    return s or None


def _get_signature_headers() -> tuple[str | None, int | None]:
    """X-AISLOPSQ-Signature / Timestamp 헤더 추출."""
    sig = request.headers.get("X-AISLOPSQ-Signature")
    ts_str = request.headers.get("X-AISLOPSQ-Timestamp")
    try:
        ts = int(ts_str) if ts_str else None
    except (TypeError, ValueError):
        ts = None
    return sig, ts


def _json_body() -> tuple[dict, bytes]:
    """body bytes + parsed JSON. parse 실패 시 빈 dict."""
    raw = request.get_data(cache=True)
    if not raw:
        return {}, b""
    try:
        return json.loads(raw.decode("utf-8")), raw
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, raw


def create_app(*, hmac_secret: str | None = None) -> Flask:
    """Flask app factory.

    Args:
      hmac_secret: 강제 secret. None 이면 PKGSENTINEL_HMAC_SECRET env 사용.

    Returns:
      구성된 Flask 인스턴스.
    """
    app = Flask("pkgsentinel")
    app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024   # 4 MiB

    # 매 요청 카운터
    @app.before_request
    def _count() -> None:
        _bump("pkgsentinel_requests_total")

    # ─────────────── /api/v1/analyze ───────────────
    @app.post("/api/v1/analyze")
    def _analyze() -> tuple[Response, int]:
        _bump("pkgsentinel_analyze_total")
        body, raw = _json_body()
        sig, ts = _get_signature_headers()
        secret = hmac_secret or _get_secret()
        resp, code = handle_analyze(
            body,
            signature_header=sig,
            timestamp_ms=ts,
            raw_body=raw,
            shared_secret=secret,
        )
        if code == 401:
            _bump("pkgsentinel_hmac_failures_total")
        if code >= 500:
            _bump("pkgsentinel_analyze_errors_total")
        if isinstance(resp, dict) and resp.get("cache", {}).get("hit"):
            _bump("pkgsentinel_analyze_cache_hits_total")
        return jsonify(resp), code

    # ─────────────── /api/v1/runtime-alert ───────────────
    @app.post("/api/v1/runtime-alert")
    def _runtime_alert() -> tuple[Response, int]:
        _bump("pkgsentinel_runtime_alert_total")
        body, raw = _json_body()
        sig, ts = _get_signature_headers()
        secret = hmac_secret or _get_secret()
        resp, code = handle_runtime_alert(
            body,
            signature_header=sig,
            timestamp_ms=ts,
            raw_body=raw,
            shared_secret=secret,
        )
        if code == 401:
            _bump("pkgsentinel_hmac_failures_total")
        return jsonify(resp), code

    # ─────────────── /api/v1/iocs/export ───────────────
    @app.route("/api/v1/iocs/export", methods=["GET", "POST"])
    def _iocs_export() -> tuple[Response, int]:
        _bump("pkgsentinel_iocs_export_total")
        if request.method == "GET":
            # query string → dict
            body = {k: v for k, v in request.args.items()}
            raw = b""
        else:
            body, raw = _json_body()
        sig, ts = _get_signature_headers()
        secret = hmac_secret or _get_secret()
        resp, code = handle_iocs_export(
            body,
            signature_header=sig if request.method == "POST" else None,
            timestamp_ms=ts if request.method == "POST" else None,
            raw_body=raw if request.method == "POST" else None,
            shared_secret=secret if request.method == "POST" else None,
        )
        if code == 401:
            _bump("pkgsentinel_hmac_failures_total")
        return jsonify(resp), code

    # ─────────────── liveness ───────────────
    @app.get("/healthz")
    def _healthz() -> tuple[Response, int]:
        return jsonify({"ok": True, "service": "pkgsentinel",
                        "ts": int(time.time())}), 200

    # ─────────────── readiness ───────────────
    @app.get("/readyz")
    def _readyz() -> tuple[Response, int]:
        # DB 연결 시도 — fail 시 503
        try:
            from ..db.threat_db import get_default_db
            db = get_default_db()
            with db.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        except Exception as e:
            return jsonify({"ok": False, "error": f"db: {type(e).__name__}: {e}"}), 503
        return jsonify({"ok": True}), 200

    # ─────────────── metrics (Prometheus exposition) ───────────────
    @app.get("/metrics")
    def _metrics() -> Response:
        lines = []
        for k, v in sorted(_METRICS.items()):
            lines.append(f"# TYPE {k} counter")
            lines.append(f"{k} {v}")
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    # ─────────────── error handler ───────────────
    @app.errorhandler(404)
    def _nf(_e: Any) -> tuple[Response, int]:
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(405)
    def _method(_e: Any) -> tuple[Response, int]:
        return jsonify({"error": "method not allowed"}), 405

    @app.errorhandler(413)
    def _too_big(_e: Any) -> tuple[Response, int]:
        return jsonify({"error": "request body too large (max 4 MiB)"}), 413

    return app


# WSGI entrypoint — gunicorn 등이 가져갈 수 있도록 module-level app 노출
def _wsgi_app() -> Flask:
    return create_app()


# 지연 평가 — `from pkgsentinel.server import app` 패턴 지원
def __getattr__(name: str) -> Any:  # pragma: no cover
    if name == "app":
        return _wsgi_app()
    raise AttributeError(name)
