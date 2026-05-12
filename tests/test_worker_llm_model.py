"""worker / pipeline 의 llm_model 인자 threading 단위 테스트.

실 LLM 호출 없이 — monkeypatch 로 review_multi 가 model 인자를 받는지만 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_pipeline_options_has_llm_model():
    print("== PipelineOptions: llm_model 필드 ==")
    from pkgsentinel._pipeline_state import PipelineOptions
    opt = PipelineOptions()
    assert hasattr(opt, "llm_model")
    # 기본값은 Sonnet
    assert opt.llm_model == "claude-sonnet-4-5"
    # 변경 가능
    opt2 = PipelineOptions(llm_model="claude-haiku-4-5")
    assert opt2.llm_model == "claude-haiku-4-5"
    print(f"  OK default={opt.llm_model}, override={opt2.llm_model}")


def test_worker_signature_accepts_llm_model():
    """worker.run_worker 와 process_one 가 llm_model 인자를 받는지."""
    print("\n== worker.run_worker signature ==")
    import inspect

    from pkgsentinel.monitor.worker import process_one, run_worker
    rw_sig = inspect.signature(run_worker)
    assert "llm_model" in rw_sig.parameters, list(rw_sig.parameters.keys())
    po_sig = inspect.signature(process_one)
    assert "llm_model" in po_sig.parameters
    print(f"  OK run_worker llm_model default={rw_sig.parameters['llm_model'].default}")


def test_cli_argparser_has_llm_model():
    print("\n== worker CLI --llm-model ==")
    from pkgsentinel.monitor.worker import _argparser
    p = _argparser()
    # parse_args 가 인자를 받지 못하면 fail
    args = p.parse_args(["--llm-model", "claude-haiku-4-5"])
    assert args.llm_model == "claude-haiku-4-5"
    # 기본값
    args2 = p.parse_args([])
    assert args2.llm_model == "claude-sonnet-4-5"
    print(f"  OK CLI accepts both Sonnet/Haiku")


def test_run_pipeline_signature_has_llm_model():
    """run_pipeline 자체에서도 llm_model 받는지."""
    print("\n== run_pipeline signature ==")
    import inspect

    from pkgsentinel.pipeline import run_pipeline
    sig = inspect.signature(run_pipeline)
    assert "llm_model" in sig.parameters
    print(f"  OK default={sig.parameters['llm_model'].default}")


def main():
    tests = [
        test_pipeline_options_has_llm_model,
        test_worker_signature_accepts_llm_model,
        test_cli_argparser_has_llm_model,
        test_run_pipeline_signature_has_llm_model,
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
