# pkgsentinel

> Supply-chain attack detection engine for PyPI / npm.
> Detects AI-hallucinated (slopsquatting) and traditionally malicious packages
> through static analysis + multi-agent LLM verification + real-time monitoring.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![Status](https://img.shields.io/badge/status-research%20preview-orange.svg)

---

## What it does

`pkgsentinel` analyzes a package on PyPI / npm **without installing it**, using
multiple defense layers that span the supply-chain attack surface:

| Layer | Role |
|---|---|
| **Layer 0** — registry / threat-intel | Encrypted DB lookup against 220k+ known-malicious advisories (OSV/GHSA) |
| **Layer 1** — source extraction + agentic gate | Memory-streamed archive analysis + AISLOPSQ classification for AI-agent packages |
| **Layer 2** — behavior sequence | Cerebro 4-dimension API call extraction (Python AST + tree-sitter JS) |
| **Layer 3** — pattern matching | 47 malicious indicators × 7 categories + sequence pattern mining + taint slicing + MITRE ATT&CK embedding match |
| **Layer 4** — LLM dual-check | Multi-agent verification (semantic / version-diff / dependency) with consensus voting |
| **Layer 5** — additional analysis | Recursive dependency, binary inspection, optional sandbox execution |
| **Layer 6** — verdict + standard outputs | CycloneDX 1.5 VEX, STIX 2.1 / TAXII 2.1, HMAC-signed webhooks, Falco rules + Tetragon TracingPolicy |

Resulting verdict is one of: `MALICIOUS / HIGH_RISK / SUSPICIOUS / AGENTIC / CLEAN / ERROR / CANNOT_ANALYZE`.

---

## Why it exists

Existing supply-chain scanners (Trivy / Grype / OSV-Scanner) optimize for
known-CVE matching against version metadata. They miss two emerging threat
classes:

1. **Slopsquatting** — LLMs hallucinate non-existent package names; attackers
   pre-register those names with malicious payloads.
2. **Agentic packages** — LangChain / AutoGen / CrewAI-style libraries whose
   *legitimate behavior* (tool use, shell, code-exec) overlaps with malicious
   patterns, producing massive false positives in classical scanners.

`pkgsentinel` addresses both with new mechanisms:

- **AISLOPSQ Manifest** — a proposed standard (this project) for agentic
  packages to declare their capability boundaries in `pyproject.toml` /
  `package.json`. The scanner cross-checks declared vs. detected capabilities
  to catch dishonest manifests.
- **Trust by Verification** — popular packages are not whitelisted; they are
  prioritized for *more frequent* scanning, since they are higher-value APT
  targets (event-stream, ua-parser-js, XZ, etc.).
- **Encrypted threat DB** — SQLCipher AES-256 with three integrity layers
  (sha256 / Merkle root / row-HMAC) against tampered local caches.

---

## Quick start

### Install (editable)

```bash
git clone https://github.com/Uisha-J/capstone_project.git pkgsentinel
cd pkgsentinel
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Initialize the encrypted DB

```bash
export AISLOP_DB_KEY="your-strong-passphrase"        # or write to ~/.aislopsquatting/db.key
python -m pkgsentinel.db.threat_db --init
python -m pkgsentinel.feeds.refresh --all            # ingests OSV / popular / IoC feeds
```

### Analyze a package (offline mode, no LLM cost)

```python
from pkgsentinel.pipeline import run_pipeline
from pkgsentinel.schema import Ecosystem

report = run_pipeline(
    package="requests",
    ecosystem=Ecosystem.PYPI,
    llm_mode="stub",            # 'claude' for paid LLM
    integrity_mode="strict",    # 'paranoid' adds Merkle + HMAC
)
print(report.verdict.value, len(report.evidence), "evidence items")
```

### Real-time monitoring (cron)

```cron
*/10 * * * *  python -m pkgsentinel.monitor.cron_main watch-pypi
*/5  * * * *  python -m pkgsentinel.monitor.cron_main watch-npm  --limit 200
*/5  * * * *  python -m pkgsentinel.monitor.cron_main worker     --max 5
0 3  * * *    python -m pkgsentinel.monitor.cron_main refresh-feeds
```

Detection signals are emitted to:
- `AISLOP_STIX_OUT_DIR/` — STIX 2.1 bundles
- `AISLOP_FALCO_OUT_DIR/` — Falco rule + Tetragon `TracingPolicy` YAML
- `AISLOP_WEBHOOK_URL` — HMAC-SHA256 signed POST

---

## Project status

Research preview. Tested with 13 internal test suites (100+ cases) covering
encrypted DB integrity, agentic classification, real-time pipeline, and
classical malicious-pattern detection. **Not yet evaluated on Datadog /
Backstabber benchmarks** — that's the next milestone.

This started as an undergraduate capstone project and is published under
Apache 2.0.

---

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — pipeline overview
- [`docs/aislopsq/`](docs/aislopsq/) — AISLOPSQ Manifest specification, decision
  tree, R1-R4 rule catalogue, and paper cards (Chhabra 2025, Beurer-Kellner 2025,
  Shi 2025, Nasr 2025, Meta Rule of Two 2025)
- [`docs/case-studies/`](docs/case-studies/) — analyses of real supply-chain
  incidents (event-stream 2018, ua-parser 2021, XZ 2024, …)
- [`docs/references/`](docs/references/) — 59-entry reference index (papers,
  frameworks, industry reports, related projects)

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Citing

If you use `pkgsentinel` or its AISLOPSQ Manifest specification in academic
work, please cite the rule sources documented in `docs/aislopsq/papers/`.
