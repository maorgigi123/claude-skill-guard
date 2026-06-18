#!/usr/bin/env node
/**
 * skill-guard CLI entry point.
 */

import { Command } from "commander";
import { scan } from "./scanner";
import { renderReport, toJson } from "./reporter";

const program = new Command();

program
  .name("skill-guard")
  .description("A security scanner for Claude Skills")
  .version("1.0.0");

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
