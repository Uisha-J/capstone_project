"""
경량 dotenv 로더.

python-dotenv 의존성 없이 표준 라이브러리만으로 작동.
설치되어 있으면 그것 사용 (더 정확한 파싱).

검색 위치 (순서대로 첫 매칭):
  1. 환경변수 AISLOP_DOTENV (명시적 경로)
  2. <cwd>/.env
  3. <repo_root>/.env

원칙:
  - **이미 환경변수에 있으면 덮어쓰지 않음** (override=False)
  - 한 번 로드하면 캐시 (idempotent)
  - 실패해도 raise 하지 않음 — 호출자 분석 영향 없음
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


_LOADED: bool = False


def _candidates() -> list[Path]:
    paths: list[Path] = []
    # 1) 명시적 경로
    explicit = os.environ.get("AISLOP_DOTENV")
    if explicit:
        paths.append(Path(explicit))

    # repo root 추정 — 본 파일 위치 기준
    # .../<repo>/src/pkgsentinel/_dotenv.py → repo = parents[2]
    here = Path(__file__).resolve()
    try:
        repo_root = here.parents[2]
    except IndexError:
        repo_root = here.parent

    # 2) cwd
    paths.append(Path.cwd() / ".env")
    # 3) repo root
    paths.append(repo_root / ".env")

    return paths


def _parse_dotenv(text: str) -> dict[str, str]:
    """매우 단순한 .env 파서. KEY=VALUE 한 줄씩."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # export KEY=VALUE 도 지원
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        # 따옴표 제거
        if (len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"')):
            val = val[1:-1]
        if key:
            out[key] = val
    return out


def _try_python_dotenv(path: Path, override: bool) -> Optional[dict[str, str]]:
    """python-dotenv 가 있으면 그걸로 파싱 (escape 등 더 정확)."""
    try:
        from dotenv import dotenv_values  # type: ignore
    except ImportError:
        return None
    try:
        return dict(dotenv_values(path))
    except Exception:
        return None


def load(
    *,
    paths: list[Path] | None = None,
    override: bool = False,
    quiet: bool = True,
) -> dict[str, str]:
    """첫 번째로 발견된 .env 파일을 환경변수에 적용.

    반환값: 로드된 키들의 마스킹된 정보 {KEY: 'len=N, prefix=...'}.
    이미 로드한 적 있으면 빈 dict 반환 (idempotent).
    """
    global _LOADED
    if _LOADED:
        return {}

    candidates = paths or _candidates()
    for p in candidates:
        try:
            if not p.is_file():
                continue
        except OSError:
            continue

        # python-dotenv 우선 시도
        parsed = _try_python_dotenv(p, override)
        if parsed is None:
            try:
                parsed = _parse_dotenv(p.read_text(encoding="utf-8"))
            except Exception:
                continue

        loaded: dict[str, str] = {}
        for k, v in parsed.items():
            if v is None:
                continue
            if not override and os.environ.get(k):
                continue
            os.environ[k] = v
            # 마스킹 정보
            n = len(v)
            prefix = v[:6] if n >= 6 else v
            loaded[k] = f"len={n}, prefix='{prefix}...'"

        _LOADED = True
        if not quiet:
            print(f"[dotenv] loaded from {p}")
            for k, info in loaded.items():
                print(f"  {k}: {info}")
        return loaded

    return {}


# ─────────────── 진단 ───────────────

def report() -> dict:
    """현재 dotenv 상태 진단 (어디서 로드됐는지, 어떤 키가 있는지)."""
    info: dict = {
        "loaded": _LOADED,
        "candidates": [str(p) for p in _candidates()],
        "candidates_exist": [],
    }
    for p in _candidates():
        try:
            if p.is_file():
                info["candidates_exist"].append(str(p))
        except OSError:
            pass

    # 주요 키 보유 여부 (값 마스킹)
    interesting = [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
        "GITHUB_TOKEN", "AISLOP_DB_KEY",
    ]
    info["env_keys"] = {}
    for k in interesting:
        v = os.environ.get(k, "")
        if v:
            info["env_keys"][k] = f"len={len(v)}, prefix='{v[:6]}...'"
        else:
            info["env_keys"][k] = None
    return info


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import json
    loaded = load(quiet=False)
    print()
    print(json.dumps({"loaded_keys": sorted(loaded.keys()),
                      "report": report()}, indent=2, ensure_ascii=False))
