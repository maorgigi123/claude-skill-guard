/**
 * Public programmatic API for skill-guard.
 */

export * from "./types";
export { rules, getRule } from "./rules";
export {
  scan,
  scanContent,
  findFiles,
  computeRiskScore,
  countBySeverity,
  SCANNED_EXTENSIONS,
  IGNORED_DIRS,
} from "./scanner";
export { renderReport, toJson } from "./reporter";
