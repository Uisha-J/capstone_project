"""TAXII 2.1 sink — STIX 2.1 객체를 TAXII collection 에 push.

근거: TAXII 2.1 spec — https://docs.oasis-open.org/cti/taxii/v2.1/

흐름:
  STIX bundle (from stix_sink.to_stix_bundle) → TAXII envelope → POST.

본 모듈은 단일 클래스 `TaxiiSink` 제공.
  - `post_bundle(bundle)`: 한 bundle 의 objects 를 TAXII envelope 로 감싸
    `collections/{id}/objects/` 엔드포인트로 POST.
  - 인증: Basic (user/pass) 또는 Bearer token.
  - TLS / cert 검증: 기본 활성. verify=False 옵션은 의도적 X — TAXII 서버는
    프로덕션 환경 가정.

호환 모드:
  - TaxiiSink(collection_objects_url=...) — collection objects 엔드포인트 직접 URL
  - TaxiiSink(api_root_url=..., collection_id=...) — API root + collection ID 분리

응답 처리:
  - 200/201/202: success → 응답 본문에서 status 객체 파싱 (성공/실패 카운트)
  - 4xx/5xx: 에러 메시지 보존

근거 RFC:
  - 5.3 Collection Resources / `POST objects/`
  - 5.4 Status Resources
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass
class TaxiiSink:
    """TAXII 2.1 collection 으로 STIX 객체를 push.

    필수 — `collection_objects_url` 또는 (`api_root_url` + `collection_id`).
    """
    # 옵션 1: full URL
    collection_objects_url: str | None = None

    # 옵션 2: API root + collection ID — 자동 조합
    api_root_url: str | None = None      # e.g. "https://taxii.example.com/api/v1"
    collection_id: str | None = None     # e.g. "indicators-aislopsq"

    # 인증 — Basic 또는 Bearer 중 하나
    basic_user: str | None = None
    basic_pass: str | None = None
    bearer_token: str | None = None

    timeout: int = 15
    user_agent: str = "ai-slopsq-taxii/1.0"
    # 추가 헤더 (예: X-Tenant-ID 등 커스텀)
    extra_headers: dict[str, str] = field(default_factory=dict)

    # ── URL 빌더 ──

    def _endpoint(self) -> str:
        """collection objects endpoint URL 계산. 실패 시 ValueError."""
        if self.collection_objects_url:
            return self.collection_objects_url.rstrip("/") + "/"
        if self.api_root_url and self.collection_id:
            root = self.api_root_url.rstrip("/")
            return f"{root}/collections/{self.collection_id}/objects/"
        raise ValueError(
            "TaxiiSink requires either collection_objects_url or "
            "(api_root_url + collection_id)"
        )

    def _auth_header(self) -> str | None:
        if self.bearer_token:
            return f"Bearer {self.bearer_token}"
        if self.basic_user is not None and self.basic_pass is not None:
            cred = base64.b64encode(
                f"{self.basic_user}:{self.basic_pass}".encode(),
            ).decode("ascii")
            return f"Basic {cred}"
        return None

    # ── 페이로드 빌더 ──

    @staticmethod
    def to_envelope(bundle: dict) -> dict:
        """STIX bundle → TAXII envelope.

        TAXII 2.1 spec §5.3.4 — POST objects 의 body 는 `{"objects": [...]}`
        형태 envelope. 우리 bundle 의 `objects` 를 그대로 추출.
        """
        objects = bundle.get("objects") or []
        return {"objects": objects}

    # ── 메인 송신 ──

    def post_bundle(self, bundle: dict) -> dict:
        """STIX bundle 의 objects 를 TAXII envelope 로 wrap 해서 POST.

        반환: {
          "ok": bool, "status_code": int|None,
          "endpoint": str,
          "object_count": int,
          "status": dict|None,  # TAXII Status 객체 (성공 시)
          "error": str|None,
        }
        """
        try:
            endpoint = self._endpoint()
        except ValueError as e:
            return {
                "ok": False, "status_code": None, "endpoint": None,
                "object_count": 0, "status": None, "error": str(e),
            }

        envelope = self.to_envelope(bundle)
        body = json.dumps(envelope, ensure_ascii=False).encode("utf-8")

        headers = {
            "Content-Type": "application/taxii+json;version=2.1",
            "Accept": "application/taxii+json;version=2.1",
            "User-Agent": self.user_agent,
        }
        auth = self._auth_header()
        if auth:
            headers["Authorization"] = auth
        headers.update(self.extra_headers)

        req = urllib.request.Request(
            endpoint, data=body, method="POST", headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_body = resp.read()
                status_code = resp.status
                ok = 200 <= status_code < 300
                status_obj = None
                if resp_body:
                    try:
                        status_obj = json.loads(resp_body.decode("utf-8"))
                    except Exception:
                        status_obj = {"raw": resp_body[:200].decode(
                            "utf-8", "replace")}
                return {
                    "ok": ok, "status_code": status_code, "endpoint": endpoint,
                    "object_count": len(envelope["objects"]),
                    "status": status_obj, "error": None,
                }
        except urllib.error.HTTPError as e:
            body_str = ""
            try:
                body_str = e.read()[:300].decode("utf-8", "replace")
            except Exception:
                pass
            return {
                "ok": False, "status_code": e.code, "endpoint": endpoint,
                "object_count": len(envelope["objects"]),
                "status": None,
                "error": f"HTTP {e.code}: {body_str}",
            }
        except urllib.error.URLError as e:
            return {
                "ok": False, "status_code": None, "endpoint": endpoint,
                "object_count": len(envelope["objects"]),
                "status": None,
                "error": f"URLError: {e}",
            }
        except Exception as e:
            return {
                "ok": False, "status_code": None, "endpoint": endpoint,
                "object_count": len(envelope["objects"]),
                "status": None,
                "error": f"{type(e).__name__}: {e}",
            }
