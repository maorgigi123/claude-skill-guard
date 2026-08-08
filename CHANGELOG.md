# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
