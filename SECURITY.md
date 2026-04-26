# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in `pkgsentinel`, **please do not open
a public issue**. Instead, contact the maintainer privately via GitHub Security
Advisories on this repository (`Security` → `Report a vulnerability`).

We aim to acknowledge reports within 72 hours and provide an initial assessment
within 7 days.

## Threat model

`pkgsentinel` is itself a security tool. Its threat model:

| Concern | Defense |
|---|---|
| **DB tampering** | SQLCipher AES-256, file-level integrity (sha256 + Merkle root + row-HMAC in paranoid mode) |
| **Feed poisoning** | HTTPS-only, sha256 verification of feed downloads, source attribution per row |
| **Cache fooling** | 6-trigger invalidation; in `strict` mode every cache lookup re-downloads + recomputes archive sha256 |
| **Webhook replay / forgery** | HMAC-SHA256 + timestamp window (±5 min) |
| **Secret leak** | `.gitignore` excludes `.env`, DB files, key files; passphrase resolved via env / keyfile / OS keyring |
| **Malicious package side-effects during analysis** | Memory-only archive streaming, no install, optional sandbox stage |

## Out of scope

- Runtime endpoint detection (EDR). `pkgsentinel` outputs Falco / Tetragon
  policies but does not run them.
- Active blocking. Block decisions are delegated to mirror proxies, CI, or
  EDR — `pkgsentinel` is a detection + signal source.
- LLM provider data residency. When `llm_mode='claude'` or `'openai'` is set,
  source snippets are sent to the provider's API per their terms of service.

## Supported versions

Current is a research preview (0.x). No guarantees on upgrade compatibility
between minor versions until 1.0.
