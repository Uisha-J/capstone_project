"""
DB 마스터 패스프레이즈 관리.

우선순위 (resolve_passphrase 가 위에서 아래로 시도):
  1. 환경변수 AISLOP_DB_KEY
  2. ~/.aislopsquatting/db.key (단일 파일, POSIX 0600)
  3. (대화형 모드) Windows DPAPI / macOS Keychain / Linux Secret Service
     - 본 구현에선 keyring 패키지 시도, 미설치 시 SKIP
  4. 자동 생성 (secrets.token_urlsafe(32)) → 위 (2) 위치에 저장

원칙:
  - 평문 키를 코드/git 에 절대 두지 않음
  - CI 에서는 1번 (env) 사용
  - 로컬 개발에서는 2번 (key file) 사용
  - 졸업과제 데모용으로는 자동 생성도 허용
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

ENV_KEY = "AISLOP_DB_KEY"
KEYFILE_PATH = Path.home() / ".aislopsquatting" / "db.key"
KEYRING_SERVICE = "ai-slopsquatting-detector"
KEYRING_USER = "threat-db"


# ─────────────── 조회 ───────────────

def from_env() -> str | None:
    v = os.environ.get(ENV_KEY)
    return v.strip() if v else None


def from_keyfile() -> str | None:
    if not KEYFILE_PATH.exists():
        return None
    try:
        v = KEYFILE_PATH.read_text(encoding="utf-8").strip()
        return v or None
    except OSError:
        return None


def from_keyring() -> str | None:
    try:
        import keyring  # type: ignore
    except ImportError:
        return None
    try:
        v = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
        return v or None
    except Exception:
        return None


def resolve_passphrase() -> str | None:
    return from_env() or from_keyfile() or from_keyring()


# ─────────────── 생성 / 저장 ───────────────

def generate_passphrase(nbytes: int = 32) -> str:
    """URL-safe Base64 인코딩된 토큰. 32 bytes = 256 bits 엔트로피."""
    return secrets.token_urlsafe(nbytes)


def save_to_keyfile(passphrase: str) -> Path:
    KEYFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(KEYFILE_PATH.parent,
                     stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass
    KEYFILE_PATH.write_text(passphrase, encoding="utf-8")
    if os.name == "posix":
        try:
            os.chmod(KEYFILE_PATH, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    return KEYFILE_PATH


def save_to_keyring(passphrase: str) -> bool:
    try:
        import keyring  # type: ignore
    except ImportError:
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER, passphrase)
        return True
    except Exception:
        return False


# ─────────────── 보장 ───────────────

def ensure_passphrase(
    *,
    auto_generate: bool = True,
    prefer_keyring: bool = False,
) -> str:
    """패스프레이즈가 없으면 자동 생성 후 저장.

    auto_generate=False 면 없을 때 RuntimeError.
    prefer_keyring=True 면 OS 키링 우선, 실패 시 keyfile.
    """
    p = resolve_passphrase()
    if p:
        return p
    if not auto_generate:
        raise RuntimeError(
            "DB 패스프레이즈를 찾지 못했습니다. "
            f"환경변수 {ENV_KEY} 또는 {KEYFILE_PATH} 파일이 필요합니다."
        )
    new_p = generate_passphrase()
    if prefer_keyring and save_to_keyring(new_p):
        return new_p
    save_to_keyfile(new_p)
    return new_p


# ─────────────── 진단 ───────────────

def report() -> dict:
    """현재 키 상태 진단 (졸업과제 데모용)."""
    env_p = from_env()
    keyfile_p = from_keyfile()
    keyring_p = from_keyring()
    return {
        "env": {
            "var": ENV_KEY,
            "present": env_p is not None,
        },
        "keyfile": {
            "path": str(KEYFILE_PATH),
            "exists": KEYFILE_PATH.exists(),
            "permissions_ok": _check_keyfile_perms(),
        },
        "keyring": {
            "available": _keyring_available(),
            "present": keyring_p is not None,
        },
        "active_source": (
            "env" if env_p else
            "keyfile" if keyfile_p else
            "keyring" if keyring_p else
            "none"
        ),
    }


def _check_keyfile_perms() -> bool | str:
    if not KEYFILE_PATH.exists():
        return "n/a"
    if os.name != "posix":
        return "windows-acl"     # POSIX 권한 모델 부적용
    st = KEYFILE_PATH.stat()
    # 다른 사용자가 읽을 수 없어야 함
    return (st.st_mode & 0o077) == 0


def _keyring_available() -> bool:
    try:
        import keyring  # noqa: F401
        return True
    except ImportError:
        return False


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse
    import json
    import sys

    p = argparse.ArgumentParser(description="DB master key manager")
    p.add_argument("--report", action="store_true", help="현재 키 상태 진단")
    p.add_argument("--ensure", action="store_true",
                   help="없으면 생성 후 저장")
    p.add_argument("--generate", action="store_true",
                   help="새 키 생성 + keyfile 저장 (기존 덮어씀)")
    p.add_argument("--show", action="store_true",
                   help="현재 활성 키를 stdout 출력 (CI 위험! 주의)")
    p.add_argument("--prefer-keyring", action="store_true",
                   help="OS 키링 우선 사용")
    args = p.parse_args()

    if args.generate:
        new_p = generate_passphrase()
        if args.prefer_keyring and save_to_keyring(new_p):
            print(f"OK: saved to OS keyring ({KEYRING_SERVICE})")
        else:
            path = save_to_keyfile(new_p)
            print(f"OK: saved to {path}")
        if args.show:
            print(f"key: {new_p}")
        sys.exit(0)

    if args.ensure:
        ensure_passphrase(prefer_keyring=args.prefer_keyring)
        print("OK: passphrase ready")

    if args.report:
        print(json.dumps(report(), indent=2))

    if args.show:
        p = resolve_passphrase()
        if p is None:
            print("(none)")
        else:
            print(p)
