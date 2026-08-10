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
  ScanOptions,
} from "./scanner";
export { renderReport, toJson } from "./reporter";
export { loadConfig, SkillGuardConfig } from "./config";
