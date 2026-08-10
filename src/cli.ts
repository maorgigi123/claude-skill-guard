#!/usr/bin/env node
/**
 * skill-guard CLI entry point.
 */

import fs from "fs";
import path from "path";
import { Command } from "commander";
import { scanMany, filterBySeverity, countBySeverity, computeRiskScore } from "./scanner";
import { renderReport, toJson } from "./reporter";
import { loadConfig } from "./config";
import { Severity } from "./types";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as string[]).includes(value);
}

/** Read the version from package.json so it can never drift from the published version. */
function readVersion(): string {
  try {
    const pkgPath = path.join(__dirname, "..", "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * Write a string to stdout and resolve only once it has been fully flushed.
 *
 * Setting `process.exitCode` and letting the event loop drain is unreliable
 * for large writes to a TTY: Node can exit before the buffered output (and the
 * intended code) takes effect. Awaiting the drain first makes the exit code
 * deterministic across TTY, pipe, and file redirection.
 */
function writeStdout(text: string): Promise<void> {
  return new Promise((resolve) => {
    process.stdout.write(text, () => resolve());
  });
}

const program = new Command();

program
  .name("skill-guard")
  .description("A security scanner for Claude Skills")
  .version(readVersion());

program
  .command("scan")
  .description("Scan one or more files or directories for risky patterns")
  .argument("<paths...>", "files or directories to scan")
  .option("--json", "output findings as JSON")
  .option(
    "--fail-on <severity>",
    "minimum severity that causes a non-zero exit code (low|medium|high|critical)",
    "critical",
  )
  .option(
    "--severity <severity>",
    "only report findings at or above this severity (low|medium|high|critical)",
  )
  .option(
    "--ignore-rule <ruleId>",
    "skip a detection rule by id (repeatable)",
    (value: string, previous: string[]) => previous.concat([value]),
    [] as string[],
  )
  .option(
    "--no-config",
    "don't auto-load a .skillguardrc.json config file",
  )
  .action(
    async (
      targets: string[],
      options: {
        json?: boolean;
        failOn: string;
        severity?: string;
        ignoreRule: string[];
        config: boolean;
      },
    ) => {
      try {
        if (!isSeverity(options.failOn)) {
          throw new Error(
            `invalid --fail-on value "${options.failOn}" (expected one of: ${SEVERITIES.join(", ")})`,
          );
        }
        if (options.severity !== undefined && !isSeverity(options.severity)) {
          throw new Error(
            `invalid --severity value "${options.severity}" (expected one of: ${SEVERITIES.join(", ")})`,
          );
        }

        const fileConfig = options.config
          ? loadConfig(targets.length === 1 ? targets[0] : undefined)
          : {};
        const ignoreRules = [...(fileConfig.ignoreRules ?? []), ...options.ignoreRule];
        const ignorePaths = fileConfig.ignorePaths ?? [];

        let result = await scanMany(targets, { ignoreRules, ignorePaths });

        if (options.severity !== undefined) {
          const findings = filterBySeverity(result.findings, options.severity);
          result = {
            ...result,
            findings,
            counts: countBySeverity(findings),
            riskScore: computeRiskScore(countBySeverity(findings)),
          };
        }

        const output = options.json ? toJson(result) : renderReport(result);
        await writeStdout(output + "\n");

        // Exit non-zero when any finding meets or exceeds the --fail-on threshold.
        const failThreshold = SEVERITIES.indexOf(options.failOn);
        const worstFound = SEVERITIES.reduce(
          (worst, sev, i) => (result.counts[sev] > 0 ? Math.max(worst, i) : worst),
          -1,
        );
        process.exit(worstFound >= failThreshold ? 1 : 0);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        process.stderr.write(`skill-guard: error: ${message}\n`);
        process.exit(2);
      }
    },
  );

program.parseAsync(process.argv);
