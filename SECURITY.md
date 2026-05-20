# Security Policy

Kura is a template for storing sensitive, regulated data. We take security
issues seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, including steps to reproduce and, if possible, a
   proof of concept.

We aim to acknowledge a report within **3 business days** and to provide an
initial assessment within **10 business days**. We will keep you informed as
we work on a fix and will credit you in the advisory unless you prefer to
remain anonymous.

## Supported versions

Kura is pre-1.0 and under active development. Security fixes are applied to
the `main` branch. Until a stable release line exists, we do not backport
fixes to tagged releases.

## Scope

This policy covers the Kura codebase in this repository: the core
enforcement library (`internal/`) and the CLI, HTTP API, dashboard, and MCP
adapters built on top of it.

Because Kura is a deployment *template*, the security of any concrete
deployment also depends on how it is configured and operated (secrets
management, network exposure, database hardening, cloud IAM). Issues that
are purely a property of a downstream deployment's configuration — rather
than a flaw in this template — are out of scope, though we welcome
documentation improvements that help operators avoid such mistakes.
