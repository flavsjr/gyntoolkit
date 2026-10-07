# Security Policy

## Purpose and scope

GynToolkit is a security toolkit intended **exclusively** for authorized security
testing, security research, CTFs and controlled lab environments. This policy
covers vulnerabilities **in GynToolkit itself** (the code in this repository) —
not vulnerabilities you find in third-party systems while using the tool.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅        |
| < 2.0   | ❌        |

## Reporting a vulnerability

If you discover a security issue in GynToolkit (e.g. a command injection in a
module, unsafe deserialization, a path traversal in the exporter):

1. **Do not open a public issue** for sensitive reports.
2. Use **GitHub Security Advisories** — the "Report a vulnerability" button under
   the repository's **Security** tab — or contact the maintainers privately.
3. Include: affected version, a minimal reproduction, impact, and any suggested fix.

We prefer **responsible / coordinated disclosure**. We aim to acknowledge reports
within a reasonable timeframe and to credit reporters who wish to be named.

## Out of scope

- Findings in systems you tested **with** GynToolkit (those belong to that system's owner).
- Reports that require using the tool against targets without authorization.
- The intentionally weak credentials in `lab/` — they are mock services by design.

## Responsible use

Using GynToolkit against systems or networks without **explicit authorization** is
illegal in most jurisdictions and strictly prohibited. See the project
[Disclaimer](README.md#disclaimer).
