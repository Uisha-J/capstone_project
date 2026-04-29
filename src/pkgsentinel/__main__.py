"""
`python -m detector <package>` 진입점.
"""
from .pipeline import format_report, run_pipeline
from .schema import Ecosystem


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="detector",
        description="Package Threat Detection Engine V2",
    )
    parser.add_argument("package")
    parser.add_argument("--ecosystem", "-e", choices=["PyPI", "npm"], default="PyPI")
    parser.add_argument("--version", "-v", default=None)
    parser.add_argument("--llm", choices=["stub", "claude"], default="stub")
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
