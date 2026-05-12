"""master_key.py KMS 백엔드 단위 테스트.

실 SDK 호출 없이 — 환경변수 처리 + import 우회 로직만 검증.
실제 백엔드 호출은 통합 환경 (AWS/Vault/GCP 자격증명 있는 곳) 에서만 가능.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.db import master_key as mk


def _clear_env(*names):
    """일시 제거. 호출 측에서 _restore_env(saved) 로 원복할 책임."""
    saved = {}
    for n in names:
        if n in os.environ:
            saved[n] = os.environ.pop(n)
    return saved


def _restore_env(saved: dict):
    for n, v in saved.items():
        os.environ[n] = v


def test_from_kms_no_backend_set():
    print("== KMS: backend env 없음 → None ==")
    saved = _clear_env(mk.ENV_KMS_BACKEND)
    try:
        assert mk.from_kms() is None
        print("  OK")
    finally:
        _restore_env(saved)


def test_from_kms_unknown_backend():
    print("\n== KMS: unknown backend → None ==")
    saved = _clear_env(mk.ENV_KMS_BACKEND)
    os.environ[mk.ENV_KMS_BACKEND] = "azure"  # 미지원
    try:
        assert mk.from_kms() is None
        print("  OK")
    finally:
        os.environ.pop(mk.ENV_KMS_BACKEND, None)
        _restore_env(saved)


def test_aws_secret_id_missing():
    print("\n== AWS: SECRET_ID 없으면 None ==")
    saved = _clear_env(mk.ENV_AWS_SECRET_ID, mk.ENV_KMS_BACKEND)
    try:
        assert mk.from_aws_secrets_manager() is None
        print("  OK")
    finally:
        _restore_env(saved)


def test_vault_addr_missing():
    print("\n== Vault: VAULT_ADDR 없으면 None ==")
    saved = _clear_env(mk.ENV_VAULT_ADDR, mk.ENV_VAULT_TOKEN, mk.ENV_VAULT_PATH)
    try:
        assert mk.from_hashicorp_vault() is None
        print("  OK")
    finally:
        _restore_env(saved)


def test_gcp_name_missing():
    print("\n== GCP: SECRET_NAME 없으면 None ==")
    saved = _clear_env(mk.ENV_GCP_NAME)
    try:
        assert mk.from_gcp_secret_manager() is None
        print("  OK")
    finally:
        _restore_env(saved)


def test_resolve_priority_kms_over_env():
    """from_kms() 가 None 이면 env 로 fallback."""
    print("\n== resolve_passphrase 우선순위 ==")
    saved = _clear_env(
        mk.ENV_KMS_BACKEND, mk.ENV_AWS_SECRET_ID,
        mk.ENV_VAULT_ADDR, mk.ENV_VAULT_TOKEN, mk.ENV_VAULT_PATH,
        mk.ENV_GCP_NAME,
        mk.ENV_KEY,
    )
    os.environ[mk.ENV_KEY] = "env-value-only"
    try:
        v = mk.resolve_passphrase()
        assert v == "env-value-only", v
        print(f"  OK: KMS 미설정 → env fallback ({v})")
    finally:
        os.environ.pop(mk.ENV_KEY, None)
        _restore_env(saved)


def main():
    tests = [
        test_from_kms_no_backend_set,
        test_from_kms_unknown_backend,
        test_aws_secret_id_missing,
        test_vault_addr_missing,
        test_gcp_name_missing,
        test_resolve_priority_kms_over_env,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception:
            import traceback
            traceback.print_exc()
            failed += 1
    print("\n" + ("ALL OK" if failed == 0 else f"FAILED: {failed}"))


if __name__ == "__main__":
    main()
