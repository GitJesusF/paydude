# Security Policy

## Supported versions

This project tracks a single line of development; only the latest `main` receives fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
the repository's **Security** tab → **"Report a vulnerability."** The report stays private to the maintainer.

Helpful details to include:

- the affected component or endpoint, and the version (commit SHA or tag),
- steps to reproduce, or a proof of concept,
- the impact you observed.

## What to expect

This is a personal project, not a production service, so there is no formal SLA. Reports are
welcome, and will be acknowledged and addressed on a best-effort basis.

## Existing automated coverage

Every change is already gated in CI on:

- **SCA** — OWASP Dependency-Check (fails on CVSS >= 7),
- **SAST** — SpotBugs + FindSecBugs,
- **SBOM** — CycloneDX,
- **Container image** — Trivy (fails on HIGH/CRITICAL).

Findings that go beyond what those catch — logic flaws in authentication, money movement,
idempotency, or rate limiting — are the most valuable to report.
