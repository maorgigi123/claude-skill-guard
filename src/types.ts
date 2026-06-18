/**
 * Shared type definitions for skill-guard.
 */

export type Severity = "low" | "medium" | "high" | "critical";

/**
 * A single regex-based detection rule.
 */
export interface Rule {
  /** Stable identifier, e.g. "rm-rf". */
  id: string;
  /** Human-readable short title. */
  title: string;
  /** Severity assigned to any match. */
  severity: Severity;
  /** The regex used to detect the pattern. Should NOT be global; matching is done per-line. */
  pattern: RegExp;
  /**
   * When true, the rule is matched against the whole file content rather than
   * line-by-line, so patterns can span multiple lines. The reported line is
   * derived from the match offset. Defaults to false.
   */
  multiline?: boolean;
  /** Explanation of why this pattern is risky. */
  description: string;
}

/**
 * A single detection produced by running a rule against a file.
 */
export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  /** Path to the file (as provided/resolved during the scan). */
  file: string;
  /** 1-based line number where the match occurred. */
  line: number;
  /** The matched text (truncated for display safety). */
  match: string;
  description: string;
}

/**
 * Aggregated result of a scan over a path.
 */
export interface ScanResult {
  /** Root path that was scanned. */
  path: string;
  /** Number of files that were read and scanned. */
  filesScanned: number;
  /** All findings, ordered by file then line. */
  findings: Finding[];
  /** Count of findings per severity. */
  counts: Record<Severity, number>;
  /** Risk score from 0 to 10. */
  riskScore: number;
}
