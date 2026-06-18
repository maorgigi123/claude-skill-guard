#!/usr/bin/env node
/**
 * skill-guard CLI entry point.
 */

import fs from "fs";
import path from "path";
import { Command } from "commander";
import { scan } from "./scanner";
import { renderReport, toJson } from "./reporter";

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

const program = new Command();

program
  .name("skill-guard")
  .description("A security scanner for Claude Skills")
  .version(readVersion());

program
  .command("scan")
  .description("Scan a file or directory for risky patterns")
  .argument("<path>", "file or directory to scan")
  .option("--json", "output findings as JSON")
  .action(async (target: string, options: { json?: boolean }) => {
    try {
      const result = await scan(target);

      if (options.json) {
        process.stdout.write(toJson(result) + "\n");
      } else {
        process.stdout.write(renderReport(result) + "\n");
      }

      // Exit non-zero when any critical finding exists.
      if (result.counts.critical > 0) {
        process.exitCode = 1;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`skill-guard: error: ${message}\n`);
      process.exitCode = 2;
    }
  });

program.parseAsync(process.argv);
