"""
`python -m pkgsentinel <package>` 진입점.
"""
from .pipeline import run_pipeline
from .reporting.formats import format_report
from .schema import Ecosystem


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="pkgsentinel",
        description="Package Threat Detection Engine V2",
    )
    parser.add_argument("package")
    parser.add_argument("--ecosystem", "-e", choices=["PyPI", "npm"], default="PyPI")
    parser.add_argument("--version", "-v", default=None)
    parser.add_argument(
        "--llm",
        choices=["stub", "claude"],
        default="claude",
        help=(
            "Stage 5 LLM 검증 모드 (default: claude). "
            "stub 은 정적 분석만 — 인기 패키지에서 FP 율이 매우 높아 단독 사용 비권장."
        ),
    )
    parser.add_argument("--deps", action="store_true", help="의존성 재귀 분석 활성화")
    parser.add_argument("--sandbox", action="store_true", help="Docker 샌드박스 활성화")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = run_pipeline(
        args.package,
        Ecosystem(args.ecosystem),
        version=args.version,
        llm_mode=args.llm,
        enable_deps=args.deps,
        enable_sandbox=args.sandbox,
    )

    if args.json:
        print(report.to_json())
    else:
        print(format_report(report))


if __name__ == "__main__":
    main()
