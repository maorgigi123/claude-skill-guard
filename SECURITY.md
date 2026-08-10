# Security Policy

## Supported Versions

Only the latest published version of `claude-skill-guard` on npm receives
security fixes.

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Instead, report it privately using one of:

- [GitHub Security Advisories](https://github.com/maorgigi123/claude-skill-guard/security/advisories/new) for this repository
- Email: maorgigim1509@gmail.com

Include a description of the issue, steps to reproduce, and its potential
impact. You should receive a response within a few days.

## Scope

`claude-skill-guard` is a static analysis tool: it reads files from disk and
matches them against regex-based rules. It does not execute the content it
scans. Relevant vulnerability classes include:

- Regular expression denial of service (ReDoS) in detection rules
- Path traversal or unsafe file handling during a scan
- Arbitrary code execution triggered merely by scanning a malicious input
  file or `.skillguardrc.json`

False negatives (a genuinely risky pattern that isn't detected) are welcome
as regular [GitHub issues](https://github.com/maorgigi123/claude-skill-guard/issues) rather than security reports, since the tool is
best-effort static analysis, not a security guarantee.
