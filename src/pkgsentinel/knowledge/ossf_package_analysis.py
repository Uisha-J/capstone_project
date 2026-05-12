"""OSSF Package Analysis 결과 흡수 (Docker / Linux 의존 제거).

근거: https://github.com/ossf/package-analysis (Apache 2.0)
- OSSF 가 PyPI / npm 신규 패키지를 격리 Docker 컨테이너에서 실행
- syscall, network, file I/O 캡처 → JSON 결과
- 결과는 GCS public bucket / BigQuery public dataset 에 publish
  - GCS: gs://ossf-malware-analysis-results/<ecosystem>/<package>/<version>.json
- 하루 ~5,000 신규 PyPI/npm 패키지 분석 — 우리가 같은 일을 *코드만* 가지고
  Docker / Linux 환경 없이 받아 쓰면 됨.

본 모듈의 역할
  1. 단일 (package, ecosystem, version) 에 대해 OSSF 결과 JSON fetch
  2. ObservedBehavior 데이터구조로 변환 — pipeline 의 `_sandbox_to_evidence`
     와 호환 (기존 sandbox stage 코드 변경 0)
  3. 캐싱 — 동일 패키지 재조회 시 네트워크 호출 회피

OssfDataSandbox 가 BaseSandbox 를 구현 → get_default_sandbox 의 default 로 사용.
DockerSandbox / StraceDockerSandbox 는 opt-in experimental 로 남김.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ..schema import Ecosystem
from ..stages.stage_sandbox import BaseSandbox, ObservedBehavior

# GCS public URL — 인증 불필요. CORS 허용.
_GCS_BUCKET_URL = (
    "https://storage.googleapis.com/ossf-malware-analysis-results"
)

# 응답 캐시 — 동일 (eco, pkg, ver) 재조회 회피
_FETCH_CACHE: dict[tuple[str, str, str], dict | None] = {}


def _ecosystem_to_dir(ecosystem: Ecosystem) -> str:
    if ecosystem == Ecosystem.PYPI:
        return "pypi"
    if ecosystem == Ecosystem.NPM:
        return "npm"
    return ecosystem.value.lower()


def fetch_ossf_analysis(
    package: str,
    ecosystem: Ecosystem,
    version: str,
    *,
    timeout: int = 15,
) -> dict | None:
    """OSSF Package Analysis 결과 JSON 한 건 fetch. 없으면 None.

    GCS 의 layout: <bucket>/<ecosystem>/<package>/<version>.json
    네트워크 / 권한 문제는 None (caller 가 graceful fallback).
    """
    eco_dir = _ecosystem_to_dir(ecosystem)
    key = (eco_dir, package.lower(), version)
    if key in _FETCH_CACHE:
        return _FETCH_CACHE[key]

    # 일부 패키지명에 / @ 가 포함 → URL escape
    from urllib.parse import quote
    url = (
        f"{_GCS_BUCKET_URL}/{eco_dir}/{quote(package, safe='')}"
        f"/{quote(version, safe='')}.json"
    )
    req = urllib.request.Request(
        url, headers={"User-Agent": "pkgsentinel-ossf/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # OSSF 가 아직 이 패키지 분석 안 함 — 정상 케이스
            _FETCH_CACHE[key] = None
            return None
        # 다른 HTTP 오류 — 일시적 → cache 안 함, 다음 호출에서 재시도
        return None
    except Exception:
        return None

    _FETCH_CACHE[key] = data
    return data


def parse_ossf_to_observed(
    data: dict, *, duration_s: float = 0.0,
) -> ObservedBehavior:
    """OSSF result JSON → ObservedBehavior.

    OSSF 결과 스키마 (Analysis.{install,import} 의 phase 별 dynamic 데이터):
      - Analysis.install.Files / Sockets / Commands / DNS
      - Analysis.import.* (PyPI import-time 만)
    각 phase 의 행위를 합쳐 단일 ObservedBehavior.
    """
    obs = ObservedBehavior(mode="ossf-package-analysis", duration_s=duration_s)
    # 최상위 또는 Analysis 하위에 phase 가 있을 수 있음
    phases = data.get("Analysis") or {}
    if not isinstance(phases, dict):
        return obs
    if not phases:
        # 일부 dump 는 phase 키 없이 평탄
        phases = {"default": data}

    seen_files: set[str] = set()
    seen_procs: set[str] = set()
    seen_net: set[str] = set()

    for _phase_name, phase in phases.items():
        if not isinstance(phase, dict):
            continue
        # Files: [{Path, Read, Write, Delete}]
        for f in (phase.get("Files") or []):
            if not isinstance(f, dict):
                continue
            path = f.get("Path", "")
            if not path:
                continue
            if f.get("Write") or f.get("Delete"):
                if path not in seen_files:
                    obs.file_writes.append(path)
                    seen_files.add(path)
            elif f.get("Read"):
                # 자격증명 / SSH / AWS 등 의심스러운 경로 읽기만 기록
                low = path.lower()
                if any(s in low for s in (
                    ".ssh", ".aws", "credentials", "passwd",
                    "shadow", ".npmrc", ".pypirc", "environ",
                )):
                    label = f"read sensitive {path}"
                    if label not in seen_files:
                        obs.file_writes.append(label)
                        seen_files.add(label)

        # Commands: [{Command: [str], Environment: [str]}]
        for c in (phase.get("Commands") or []):
            if not isinstance(c, dict):
                continue
            cmd = c.get("Command")
            if isinstance(cmd, list) and cmd:
                cmd_str = " ".join(str(x) for x in cmd[:6])[:200]
            elif isinstance(cmd, str):
                cmd_str = cmd[:200]
            else:
                continue
            if cmd_str not in seen_procs:
                obs.process_spawns.append(cmd_str)
                seen_procs.add(cmd_str)

        # Sockets: [{Address, Port, Hostnames}]
        for s in (phase.get("Sockets") or []):
            if not isinstance(s, dict):
                continue
            addr = s.get("Address")
            port = s.get("Port")
            hostnames = s.get("Hostnames") or []
            if isinstance(hostnames, list) and hostnames:
                label = f"connect {hostnames[0]} ({addr}:{port})"
            elif addr:
                label = f"connect {addr}:{port}"
            else:
                continue
            if label not in seen_net:
                obs.network_requests.append(label[:200])
                seen_net.add(label)

        # DNS: [{Hostname, Queries}]  (Hostnames 와 별개로 DNS-only 트래픽도 캡처)
        for d in (phase.get("DNS") or []):
            if not isinstance(d, dict):
                continue
            host = d.get("Hostname")
            if host:
                label = f"DNS {host}"
                if label not in seen_net:
                    obs.network_requests.append(label[:200])
                    seen_net.add(label)

    return obs


# ─────────────── BaseSandbox 구현 ───────────────

class OssfDataSandbox(BaseSandbox):
    """OSSF Package Analysis 결과를 fetch 해 ObservedBehavior 로 변환.

    이게 *현재 추천 default* — Docker / Linux 의존 0, 인증 0, 비용 0.
    OSSF 가 우리보다 더 좋은 격리 환경으로 매일 수천 패키지 분석.

    한계: OSSF 가 *아직* 분석 안 한 패키지 (방금 publish) 는 결과 없음.
    이 경우 ObservedBehavior(error="no OSSF analysis") 로 graceful fallback.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def run(
        self,
        package: str,
        ecosystem: Ecosystem,
        version: str,
    ) -> ObservedBehavior:
        t0 = time.time()
        data = fetch_ossf_analysis(
            package, ecosystem, version, timeout=self.timeout,
        )
        elapsed = time.time() - t0
        if data is None:
            return ObservedBehavior(
                mode="ossf-package-analysis",
                duration_s=elapsed,
                error="no OSSF analysis result for this (package, version)",
            )
        return parse_ossf_to_observed(data, duration_s=elapsed)
