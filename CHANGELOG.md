# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1.5] - 2026-08-10

### Added

- Inline suppression comments: `skill-guard-disable-line` and
  `skill-guard-disable-next-line`, each optionally scoped to a single rule
  id (e.g. `skill-guard-disable-next-line rm-rf`), for waiving individual
  findings without editing source.
- `--ignore-rule <ruleId>` CLI flag (repeatable) to skip a detection rule
  entirely.
- Optional `.skillguardrc.json` config file, auto-discovered in the scanned
  directory (or CWD), supporting `ignoreRules` and `ignorePaths`. CLI flags
  always take precedence. Disable auto-loading with `--no-config`.
- `SECURITY.md` describing how to report a vulnerability in the tool.
- Expanded npm keywords for discoverability (`mcp`, `ai-security`,
  `llm-security`, `prompt-injection`, `sast`, `agent-security`, `anthropic`,
  `claude-code`).
- README badges (npm version, downloads, CI status, license).

## [1.1.1] - [1.1.4]

Republished under new version numbers to work around npm registry version
conflicts; no functional changes beyond 1.1.0.

## [1.1.0] - 2026-08-08

### Added

- New detection rules: `powershell-download-cradle`, `npm-install-run`,
  `secret-exfil-print`, `crypto-miner`.
- `--fail-on <severity>` CLI flag to control which severity threshold
  triggers a non-zero exit code (default: `critical`, matching prior
  behavior).
- `--severity <level>` CLI flag to filter reported findings to a minimum
  severity.
- Support for scanning multiple paths in a single `scan` invocation.
- `LICENSE` file (MIT), `CHANGELOG.md`, and a GitHub Actions CI workflow
  running the test suite on Node 18.x and 20.x.

## [1.0.3] - 2026-06-18

### Fixed

- Non-deterministic CLI exit code caused by stdout not being fully flushed
  before `process.exit`.

## [1.0.2] - 2026-06-18

### Fixed

- Critical scan bug and version drift between `package.json` and the
  published package.

### Added

- Additional detection rules and test coverage.

## [1.0.1] - 2026-06-18

Initial patch release.

## [1.0.0] - 2026-06-18

Initial release: security scanner for Claude Skills with regex-based
detection rules, terminal and JSON reporting, and a 0-10 risk score.
