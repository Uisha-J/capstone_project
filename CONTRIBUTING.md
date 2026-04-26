# Contributing to pkgsentinel

Thanks for your interest!

## Development setup

```bash
git clone https://github.com/Uisha-J/capstone_project.git pkgsentinel
cd pkgsentinel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Set the encrypted DB passphrase before running tests:

```bash
export AISLOP_DB_KEY="your-dev-passphrase"
```

## Running tests

```bash
pytest                              # all tests
pytest tests/test_agentic.py        # one file
pytest -m "not slow"                # skip long-running
```

## Code style

We use `ruff` for linting + formatting:

```bash
ruff check src tests
ruff format src tests
```

Type checking (optional, gradual):

```bash
mypy src
```

## Commit conventions

- One concern per commit
- Imperative mood: "Add X", "Fix Y", "Refactor Z"
- For new detection rules, cite the source paper / standard in the commit body

## Adding a new detection rule

If you add a new rule (R5, R6, ... or new indicator), please:

1. Add the rule signature in the appropriate module under `src/pkgsentinel/agentic/` or `src/pkgsentinel/stages/`
2. Add at least one passing + one failing test in `tests/`
3. Cite the source paper / vendor advisory in the docstring
4. Update `docs/aislopsq/spec/RULES.md` if it's an AISLOPSQ R-rule

## Reporting issues

- **Security vulnerabilities**: see [`SECURITY.md`](SECURITY.md)
- **Bugs / feature requests**: GitHub Issues

## License

By contributing, you agree your contributions will be licensed under the
project's Apache License 2.0.
