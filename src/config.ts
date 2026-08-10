/**
 * Optional `.skillguardrc.json` config file support.
 *
 * The file is looked up first in the scanned target (if it's a directory)
 * and then in the current working directory. CLI flags always take
 * precedence over config file values.
 */

import fs from "fs";
import path from "path";

export interface SkillGuardConfig {
  ignoreRules?: string[];
  ignorePaths?: string[];
}

const CONFIG_FILENAME = ".skillguardrc.json";

/** Load and parse a `.skillguardrc.json` from `dir`, if present. */
function readConfigFile(dir: string): SkillGuardConfig | undefined {
  const file = path.join(dir, CONFIG_FILENAME);
  if (!fs.existsSync(file)) return undefined;

  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `failed to parse ${file}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new Error(`${file} must contain a JSON object`);
  }

  const obj = parsed as Record<string, unknown>;
  const config: SkillGuardConfig = {};

  if (obj.ignoreRules !== undefined) {
    if (!Array.isArray(obj.ignoreRules) || !obj.ignoreRules.every((v) => typeof v === "string")) {
      throw new Error(`${file}: "ignoreRules" must be an array of strings`);
    }
    config.ignoreRules = obj.ignoreRules;
  }

  if (obj.ignorePaths !== undefined) {
    if (!Array.isArray(obj.ignorePaths) || !obj.ignorePaths.every((v) => typeof v === "string")) {
      throw new Error(`${file}: "ignorePaths" must be an array of strings`);
    }
    config.ignorePaths = obj.ignorePaths;
  }

  return config;
}

/**
 * Discover a `.skillguardrc.json`, checking `searchDir` (typically the
 * scanned target, if it's a directory) before falling back to the current
 * working directory. Returns an empty config if none is found.
 */
export function loadConfig(searchDir?: string): SkillGuardConfig {
  const dirs = [searchDir, process.cwd()].filter(
    (d): d is string => typeof d === "string" && fs.existsSync(d) && fs.statSync(d).isDirectory(),
  );

  for (const dir of dirs) {
    const config = readConfigFile(dir);
    if (config) return config;
  }

  return {};
}
