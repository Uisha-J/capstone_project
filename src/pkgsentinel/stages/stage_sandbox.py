"""
샌드박스 동적 분석.

Docker 격리 컨테이너에서 `pip install --dry-run` 혹은 실제 install 을 실행하고:
  - 생성된 프로세스
  - 발생한 네트워크 요청 (iptables / tcpdump 또는 로그)
  - 생성/변경된 파일

을 관찰해 동적 행위 프로필을 수집.

현재 제약:
  - 실제 동작은 Docker 데몬 필요
  - 프로토타입에서는 "mock 모드" 로 개념 증명
  - 진짜 구현은 다음 요소 필요:
      * Docker SDK (docker-py)
      * 네트워크 캡처 (strace / sysdig / bpftrace)
      * 파일시스템 diff

이 모듈의 현재 역할:
  1. 인터페이스 정의 (ObservedBehavior 데이터 모델)
  2. Mock 모드 동작 (실행하지 않고 정적 분석 결과를 동적인 것처럼 포맷)
  3. 실제 Docker 통합은 별도 docker-compose 서비스로 Phase C-2b 에서 완성

설계상 향후 교체 가능하도록 BaseSandbox 추상화.
"""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..schema import Ecosystem


# ─────────────── 관찰된 동적 행위 ───────────────

@dataclass
class ObservedBehavior:
    """샌드박스 내부에서 관찰된 실제 행위."""
    process_spawns: list[str] = field(default_factory=list)         # "curl http://..."
    network_requests: list[str] = field(default_factory=list)       # "GET http://..."
    file_writes: list[str] = field(default_factory=list)            # "/tmp/x"
    env_reads: list[str] = field(default_factory=list)              # "AWS_*"

    mode: str = "mock"                                               # "mock" | "docker"
    duration_s: float = 0.0
    error: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(
            self.process_spawns
            or self.network_requests
            or self.file_writes
        )


# ─────────────── 베이스 ───────────────

class BaseSandbox(ABC):
    @abstractmethod
    def run(
        self,
        package: str,
        ecosystem: Ecosystem,
        version: str,
    ) -> ObservedBehavior:
        raise NotImplementedError


# ─────────────── Mock 샌드박스 ───────────────

class MockSandbox(BaseSandbox):
    """실행 없이 정적 힌트만 반환. Docker 미사용 환경용."""

    def run(self, package, ecosystem, version) -> ObservedBehavior:
        return ObservedBehavior(
            mode="mock",
            duration_s=0.0,
            error="sandbox not executed (mock mode)",
        )


# ─────────────── Docker 샌드박스 ───────────────

DOCKER_IMAGE_PY = "python:3.11-slim"
DOCKER_IMAGE_NODE = "node:20-alpine"


class DockerSandbox(BaseSandbox):
    """
    격리 컨테이너에서 install 실행 후 관찰.

    접근 방식:
      1. --network none 으로 우선 install --dry-run (네트워크 차단 상태에서 시도)
         → 네트워크 접근 시도 시 실패 로그 확인
      2. 실제 install 은 --network bridge + DNS/트래픽 로깅
      3. 파일 생성은 /sandbox 마운트 diff 로 확인

    현재는 개념 증명 — 실제 운영 전에 보안 검토 필요 (악성 코드가 실행됨).
    """

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def _available(self) -> bool:
        return shutil.which("docker") is not None

    def run(self, package, ecosystem, version) -> ObservedBehavior:
        if not self._available():
            return ObservedBehavior(
                mode="docker",
                error="docker not available on this host",
            )

        if ecosystem == Ecosystem.PYPI:
            return self._run_pypi(package, version)
        if ecosystem == Ecosystem.NPM:
            return self._run_npm(package, version)

        return ObservedBehavior(
            mode="docker",
            error=f"unsupported ecosystem: {ecosystem}",
        )

    def _run_pypi(self, package: str, version: str) -> ObservedBehavior:
        import time

        target = f"{package}=={version}" if version and version != "unknown" else package
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",       # 일단 네트워크 차단 — 설치 스크립트가 네트워크 시도하는지 관찰
            "--read-only",
            "--tmpfs", "/tmp",
            DOCKER_IMAGE_PY,
            "pip", "install", "--dry-run", "--no-cache-dir", "--disable-pip-version-check",
            target,
        ]
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout, text=True,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            combined = stdout + "\n" + stderr
        except subprocess.TimeoutExpired:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error="timeout (possibly hanging install script)",
            )
        except Exception as e:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error=f"docker failed: {e}",
            )

        # 간이 로그 파싱
        obs = ObservedBehavior(mode="docker", duration_s=time.time() - t0)

        import re
        # 네트워크 실패 로그 = 설치 과정에서 네트워크를 시도한 증거
        if re.search(r"(Temporary failure|Network is unreachable|Could not fetch)", combined):
            obs.network_requests.append("pip install attempted network (blocked by --network none)")

        if "Executing" in combined or "Running setup.py" in combined:
            obs.process_spawns.append("setup.py executed during pip install")

        return obs

    def _run_npm(self, package: str, version: str) -> ObservedBehavior:
        import time

        target = f"{package}@{version}" if version and version != "unknown" else package
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--tmpfs", "/workdir:rw",
            "-w", "/workdir",
            DOCKER_IMAGE_NODE,
            "sh", "-c",
            f"npm init -y >/dev/null 2>&1 && "
            f"npm install --ignore-scripts=false --no-audit --no-fund --dry-run {target} 2>&1 | head -200",
        ]
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout, text=True,
            )
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error="timeout",
            )
        except Exception as e:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error=f"docker failed: {e}",
            )

        obs = ObservedBehavior(mode="docker", duration_s=time.time() - t0)

        import re
        if re.search(r"(ENOTFOUND|ECONNREFUSED|getaddrinfo)", combined):
            obs.network_requests.append("npm install attempted network (blocked)")
        if "postinstall" in combined.lower() or "preinstall" in combined.lower():
            obs.process_spawns.append("install hook script executed")

        return obs


# ─────────────── 선택 헬퍼 ───────────────

def get_default_sandbox() -> BaseSandbox:
    """Docker 가 있으면 DockerSandbox, 없으면 MockSandbox."""
    docker_sandbox = DockerSandbox()
    if docker_sandbox._available():
        return docker_sandbox
    return MockSandbox()


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    sb = get_default_sandbox()
    print(f"Using sandbox: {type(sb).__name__}")

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    obs = sb.run(pkg, eco, "latest")
    print(f"mode       : {obs.mode}")
    print(f"duration   : {obs.duration_s:.2f}s")
    print(f"error      : {obs.error}")
    print(f"processes  : {obs.process_spawns}")
    print(f"network    : {obs.network_requests}")
    print(f"file writes: {obs.file_writes}")
