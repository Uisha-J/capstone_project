"""SLSA 추정 단위 테스트."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages.stage_slsa import SLSALevel, evaluate


def test_no_metadata():
    print("== No metadata ==")
    rpt = evaluate(None, Ecosystem.NPM)
    print(f"  level={rpt.level.value}, error={rpt.error}")
    return rpt.level == SLSALevel.UNKNOWN


def test_npm_no_provenance():
    print("\n== npm without provenance ==")
    raw = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://example.com/x-1.0.0.tgz",
                    "shasum": "abc",
                },
            },
        },
    }
    rpt = evaluate(raw, Ecosystem.NPM)
    print(f"  level={rpt.level.value}, prov={rpt.has_provenance}, sig={rpt.has_signature}")
    return rpt.level == SLSALevel.L0


def test_npm_with_provenance():
    print("\n== npm with provenance + signature ==")
    raw = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://example.com/x-1.0.0.tgz",
                    "attestations": {
                        "url": "https://registry.npmjs.org/-/npm/v1/attestations/x@1.0.0",
                        "count": 2,
                    },
                    "signatures": [
                        {"keyid": "...", "sig": "..."},
                    ],
                },
                "repository": {"url": "git+https://github.com/x/x.git"},
            },
        },
    }
    rpt = evaluate(raw, Ecosystem.NPM)
    print(f"  level={rpt.level.value}, prov={rpt.has_provenance}, sig={rpt.has_signature}")
    print(f"  source_uri={rpt.source_uri}")
    print(f"  notes={rpt.notes}")
    return rpt.level == SLSALevel.L2 and rpt.has_provenance and rpt.has_signature


def test_pypi_no_attestation():
    print("\n== PyPI without PEP-740 attestation ==")
    raw = {
        "info": {
            "home_page": "https://example.com",
            "project_urls": {"Source": "https://github.com/x/x"},
        },
        "urls": [
            {
                "url": "https://files.pythonhosted.org/x.whl",
                "filename": "x.whl",
                "digests": {"sha256": "x" * 64},
            },
        ],
    }
    rpt = evaluate(raw, Ecosystem.PYPI)
    print(f"  level={rpt.level.value}, prov={rpt.has_provenance}, sig={rpt.has_signature}")
    print(f"  notes={rpt.notes}")
    return rpt.level == SLSALevel.L0


def test_pypi_with_attestation():
    print("\n== PyPI with PEP-740 has_attestations ==")
    raw = {
        "info": {
            "project_urls": {"Source": "https://github.com/x/x"},
        },
        "urls": [
            {
                "url": "https://files.pythonhosted.org/x.whl",
                "filename": "x.whl",
                "digests": {"sha256": "x" * 64},
                "has_attestations": True,
            },
        ],
    }
    rpt = evaluate(raw, Ecosystem.PYPI)
    print(f"  level={rpt.level.value}, prov={rpt.has_provenance}")
    print(f"  notes={rpt.notes}")
    return rpt.level == SLSALevel.L2 and rpt.has_provenance


def test_real_npm():
    """선택적 라이브 테스트 (SLSA_LIVE=1)."""
    if os.getenv("SLSA_LIVE") != "1":
        print("\n== Live npm SKIPPED (set SLSA_LIVE=1) ==")
        return True
    from pkgsentinel.stages.stage0_registry import check
    info = check("sigstore", Ecosystem.NPM)
    rpt = evaluate(info.raw_metadata, Ecosystem.NPM)
    print("\n== Live npm sigstore ==")
    print(f"  level={rpt.level.value}, prov={rpt.has_provenance}")
    return rpt.has_provenance  # sigstore npm 은 provenance 보유


def main():
    ok = True
    ok &= test_no_metadata()
    ok &= test_npm_no_provenance()
    ok &= test_npm_with_provenance()
    ok &= test_pypi_no_attestation()
    ok &= test_pypi_with_attestation()
    ok &= test_real_npm()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
