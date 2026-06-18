/**
 * The scanner: walks a path, reads supported files, and runs the rule
 * engine against each line to produce findings and a risk score.
 */

import fs from "fs";
import path from "path";
import fg from "fast-glob";
import { rules } from "./rules";
import { Finding, ScanResult, Severity } from "./types";

/** File extensions that are scanned. */
export const SCANNED_EXTENSIONS = [
  "md",
  "markdown",
  "txt",
  "js",
  "ts",
  "json",
  "sh",
  "py",
  "yml",
  "yaml",
];

/** Directories that are always ignored. */
export const IGNORED_DIRS = ["node_modules", "dist", ".git"];

/** Severity weights used when computing the risk score. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  low: 1,
  medium: 3,
  high: 6,
  critical: 10,
};

/** Maximum number of characters kept from a matched string for display. */
const MATCH_MAX_LEN = 200;

/**
 * Discover all scannable files under a path. If the path is a single file
 * with a supported extension, just that file is returned.
 */
export async function findFiles(target: string): Promise<string[]> {
  const stat = fs.existsSync(target) ? fs.statSync(target) : undefined;

  if (stat?.isFile()) {
    return [path.resolve(target)];
  }

  const root = stat?.isDirectory() ? target : path.dirname(target);
  const extGlob = `**/*.{${SCANNED_EXTENSIONS.join(",")}}`;

  const entries = await fg(extGlob, {
    cwd: root,
    absolute: true,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    ignore: IGNORED_DIRS.map((d) => `**/${d}/**`),
  });

  return entries;
}

/** Run all rules against a single file's content. */
export function scanContent(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) continue;

    for (const rule of rules) {
      const m = rule.pattern.exec(line);
      if (m) {
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          file: filePath,
          line: i + 1,
          match: truncate(m[0].trim(), MATCH_MAX_LEN),
          description: rule.description,
        });
      }
    }
  }

  return findings;
}

/**
 * Scan a path (file or directory) and return aggregated results.
 */
export async function scan(target: string): Promise<ScanResult> {
  const files = await findFiles(target);
  const findings: Finding[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf8");
    } catch {
      // Unreadable or binary file — skip it.
      continue;
    }
    findings.push(...scanContent(file, content));
  }

  findings.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));

  const counts = countBySeverity(findings);
  const riskScore = computeRiskScore(counts);

  return {
    path: target,
    filesScanned: files.length,
    findings,
    counts,
    riskScore,
  };
}

/** Tally findings by severity. */
export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/**
 * Compute a risk score from 0 to 10 based on the weighted finding counts.
 *
 * A single critical finding alone yields the maximum score. Otherwise the
 * weighted total is mapped onto the 0-10 range with diminishing returns so
 * that many low-severity hits don't trivially saturate the score.
 */
export function computeRiskScore(counts: Record<Severity, number>): number {
  if (counts.critical > 0) return 10;

  const weighted =
    counts.low * SEVERITY_WEIGHT.low +
    counts.medium * SEVERITY_WEIGHT.medium +
    counts.high * SEVERITY_WEIGHT.high +
    counts.critical * SEVERITY_WEIGHT.critical;

  if (weighted === 0) return 0;

  // Logarithmic-ish mapping: saturates toward 10 without ever quite hitting
  // it unless a critical is present.
  const score = 10 * (1 - Math.exp(-weighted / 12));
  return Math.round(Math.min(9.9, score) * 10) / 10;
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "…" : s;
}
