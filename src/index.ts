/**
 * Public programmatic API for skill-guard.
 */

export * from "./types";
export { rules, getRule } from "./rules";
export {
  scan,
  scanMany,
  scanContent,
  findFiles,
  computeRiskScore,
  countBySeverity,
  filterBySeverity,
  SCANNED_EXTENSIONS,
  IGNORED_DIRS,
} from "./scanner";
export { renderReport, toJson } from "./reporter";
