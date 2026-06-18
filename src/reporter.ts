/**
 * The reporter: renders scan results either as a human-friendly terminal
 * report or as JSON.
 */

import path from "path";
import { Finding, ScanResult, Severity } from "./types";

// Minimal ANSI styling without external dependencies. Colors are disabled
// automatically when stdout is not a TTY or NO_COLOR is set.
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

const c = {
  reset: wrap("\x1b[0m"),
  bold: wrap("\x1b[1m"),
  dim: wrap("\x1b[2m"),
  red: wrap("\x1b[31m"),
  green: wrap("\x1b[32m"),
  yellow: wrap("\x1b[33m"),
  blue: wrap("\x1b[34m"),
  magenta: wrap("\x1b[35m"),
  cyan: wrap("\x1b[36m"),
  gray: wrap("\x1b[90m"),
};

function wrap(code: string): (s: string) => string {
  return (s: string) => (useColor ? `${code}${s}\x1b[0m` : s);
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

function severityLabel(sev: Severity): string {
  switch (sev) {
    case "critical":
      return c.red(c.bold("CRITICAL"));
    case "high":
      return c.red("HIGH");
    case "medium":
      return c.yellow("MEDIUM");
    case "low":
      return c.blue("LOW");
  }
}

function riskColor(score: number): (s: string) => string {
  if (score >= 8) return c.red;
  if (score >= 5) return c.yellow;
  if (score >= 2) return c.cyan;
  return c.green;
}

/** Produce the JSON representation of a scan result. */
export function toJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/** Render a full terminal report for a scan result. */
export function renderReport(result: ScanResult): string {
  const out: string[] = [];
  const root = path.resolve(result.path);

  out.push("");
  out.push(c.bold(c.cyan("  skill-guard")) + c.dim("  security scan"));
  out.push(c.gray("  " + "─".repeat(50)));
  out.push(`  ${c.dim("Path:")}  ${result.path}`);
  out.push(`  ${c.dim("Files scanned:")}  ${result.filesScanned}`);
  out.push(`  ${c.dim("Findings:")}  ${result.findings.length}`);
  out.push("");

  if (result.findings.length === 0) {
    out.push("  " + c.green("✓ No issues found."));
  } else {
    const grouped = groupByFile(result.findings);
    for (const [file, findings] of grouped) {
      const rel = relativize(root, file);
      out.push("  " + c.bold(c.magenta(rel)));
      for (const f of findings) {
        out.push(
          `    ${c.dim("L" + f.line)}  [${severityLabel(f.severity)}] ` +
            `${c.bold(f.title)} ${c.gray("(" + f.ruleId + ")")}`,
        );
        out.push(`        ${c.dim("match:")} ${c.yellow(f.match)}`);
        out.push(`        ${c.gray(f.description)}`);
      }
      out.push("");
    }
  }

  // Severity summary line.
  const summary = SEVERITY_ORDER.map(
    (sev) => `${severityLabel(sev)}: ${result.counts[sev]}`,
  ).join("   ");
  out.push(c.gray("  " + "─".repeat(50)));
  out.push("  " + summary);

  const rc = riskColor(result.riskScore);
  out.push(
    "  " +
      c.bold("Risk score: ") +
      rc(c.bold(`${result.riskScore.toFixed(1)} / 10`)) +
      "  " +
      rc(riskBar(result.riskScore)),
  );
  out.push("");

  return out.join("\n");
}

function riskBar(score: number): string {
  const filled = Math.round((score / 10) * 20);
  return "[" + "█".repeat(filled) + "░".repeat(20 - filled) + "]";
}

function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = map.get(f.file) ?? [];
    arr.push(f);
    map.set(f.file, arr);
  }
  return map;
}

function relativize(root: string, file: string): string {
  const rel = path.relative(root, file);
  return rel === "" ? path.basename(file) : rel;
}
