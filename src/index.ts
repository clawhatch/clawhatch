#!/usr/bin/env node

/**
 * Clawhatch CLI — Security scanner for OpenClaw AI agents.
 *
 * Usage:
 *   npx clawhatch scan                     # Basic scan
 *   npx clawhatch scan --workspace .       # Include workspace files
 *   npx clawhatch scan --json              # Machine-readable output
 *   npx clawhatch scan --fix               # Auto-fix safe issues
 *   npx clawhatch scan --deep              # Deep scan (full session logs)
 *   npx clawhatch scan --share             # Share anonymized results
 *   npx clawhatch threats                  # View community threat feed
 *   npx clawhatch subscribe --webhook URL  # Subscribe to alerts
 */

import { Command } from "commander";
import chalk from "chalk";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { scan } from "./scanner.js";
import { reportFindings, reportJson } from "./reporter.js";
import { generateHtmlReport } from "./reporter-html.js";
import { applyFixes } from "./fixer.js";
import { sanitizeFindings } from "./sanitize.js";
import { initSecureConfig } from "./init.js";
import { anonymizeScanResult, uploadThreatReport } from "./telemetry.js";
import { DEFAULT_API_URL, fetchThreatFeed, formatThreatFeed, checkAgainstFeed } from "./threat-feed.js";
import { loadNotifyConfig, saveNotifyConfig, buildAlerts, sendWebhookAlert, sendTestAlert } from "./notify.js";

const program = new Command();

program
  .name("clawhatch")
  .description("Security scanner for OpenClaw AI agents")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan your OpenClaw installation for security issues")
  .option("-p, --path <path>", "OpenClaw installation path", "~/.openclaw")
  .option("-w, --workspace <path>", "Workspace path (for SOUL.md, skills, etc.)")
  .option("--json", "Output JSON instead of formatted text")
  .option("--format <format>", "Output format: text, json, html", "text")
  .option("--fix", "Auto-apply safe fixes (prompts for behavioral changes)")
  .option("--deep", "Deep scan — full session log analysis (slower)")
  .option("--share", "Anonymize and share results with community threat feed")
  .option("--upload", "Alias for --share")
  .action(async (options) => {
    // --json flag is an alias for --format json
    const format: string = options.json ? "json" : options.format;
    const shouldShare = !!(options.share || options.upload);

    if (format === "text") {
      console.log(chalk.cyan("\n  Clawhatch Security Scanner v0.1.0\n"));
    }

    const result = await scan({
      openclawPath: options.path,
      workspacePath: options.workspace,
      autoFix: !!options.fix,
      deep: !!options.deep,
      json: format === "json",
      upload: shouldShare,
    });

    // Output results
    if (format === "json") {
      // Sanitize before JSON output
      result.findings = sanitizeFindings(result.findings);
      result.suggestions = sanitizeFindings(result.suggestions);
      reportJson(result);
    } else if (format === "html") {
      const html = generateHtmlReport(result);
      const outPath = resolve(process.cwd(), "clawhatch-report.html");
      await writeFile(outPath, html, "utf-8");
      console.log(chalk.green(`\n  HTML report written to ${outPath}\n`));
    } else {
      reportFindings(result);
    }

    // Auto-fix if requested
    if (options.fix && result.findings.some((f) => f.autoFixable)) {
      const configPath = result.findings.find((f) => f.file)?.file ?? null;
      const { findOpenClawDir } = await import("./discover.js");
      const openclawDir = await findOpenClawDir(options.path);
      if (openclawDir) {
        await applyFixes(result.findings, configPath, openclawDir);
      }
    }

    // Community threat intelligence
    if (shouldShare) {
      const report = anonymizeScanResult(result);
      if (format !== "json") {
        console.log(chalk.dim("\n  Sharing anonymized results with community..."));
      }
      const uploadResult = await uploadThreatReport(report, DEFAULT_API_URL);
      if (uploadResult.success) {
        if (format !== "json") {
          console.log(chalk.green("  Shared with community threat feed."));
        }
      } else {
        if (format !== "json") {
          console.log(chalk.yellow(`  Could not share: ${uploadResult.error}`));
        }
      }
    }

    // Check against community feed and send webhook alerts
    const { findOpenClawDir } = await import("./discover.js");
    const openclawDir = await findOpenClawDir(options.path);
    if (openclawDir) {
      const notifyConfig = await loadNotifyConfig(openclawDir);
      if (notifyConfig?.notify?.webhookUrl) {
        const feed = await fetchThreatFeed(notifyConfig.apiUrl ?? DEFAULT_API_URL);

        // Show community cross-reference warnings
        if (feed && format === "text") {
          const warnings = checkAgainstFeed(result, feed);
          if (warnings.length > 0) {
            console.log(chalk.bold.yellow("\n  Community Threat Warnings"));
            for (const w of warnings) {
              console.log(chalk.yellow(`    ! ${w}`));
            }
          }
        }

        // Send webhook alerts
        const threshold = notifyConfig.notify.threshold ?? "HIGH";
        const alerts = buildAlerts(result, feed, threshold);
        if (alerts.length > 0) {
          const sent = await sendWebhookAlert(
            notifyConfig.notify.webhookUrl,
            alerts,
            result.score,
          );
          if (format !== "json") {
            if (sent) {
              console.log(chalk.green(`  Sent ${alerts.length} alert(s) to webhook.`));
            } else {
              console.log(chalk.yellow("  Failed to send webhook alerts."));
            }
          }
        }
      }
    }

    // Exit code: 1 if critical findings, 0 otherwise
    const hasCritical = result.findings.some(
      (f) => f.severity === "CRITICAL"
    );
    process.exit(hasCritical ? 1 : 0);
  });

program
  .command("init")
  .description("Generate a secure baseline OpenClaw configuration")
  .option("-p, --path <path>", "Target directory", "~/.openclaw")
  .action(async (options) => {
    console.log(chalk.cyan("\n  Clawhatch Config Generator v0.1.0\n"));

    // FIX: Use os.homedir() for reliable cross-platform ~ expansion
    // process.env.HOME is undefined on Windows; USERPROFILE may have spaces
    const { homedir } = await import("node:os");
    const { join } = await import("node:path");
    const targetDir = options.path.startsWith("~")
      ? join(homedir(), options.path.slice(1))
      : options.path;

    const result = await initSecureConfig(targetDir);

    console.log("");
    if (result.created.length > 0) {
      console.log(
        chalk.green(`  Created ${result.created.length} file(s) in ${targetDir}`)
      );
    }
    if (result.skipped.length > 0) {
      console.log(
        chalk.yellow(
          `  Skipped ${result.skipped.length} file(s) (already exist)`
        )
      );
    }

    console.log(chalk.cyan("\n  Next steps:"));
    console.log(
      chalk.white("    1. Set OPENCLAW_AUTH_TOKEN in .env (use the command in the file)")
    );
    console.log(
      chalk.white("    2. Add your API keys to .env")
    );
    console.log(
      chalk.white("    3. Run: clawhatch scan -p " + targetDir + "\n")
    );
  });

program
  .command("threats")
  .description("View the community threat intelligence feed")
  .option("--api-url <url>", "API endpoint", DEFAULT_API_URL)
  .action(async (options) => {
    console.log(chalk.dim("\n  Fetching community threat feed...\n"));

    const feed = await fetchThreatFeed(options.apiUrl);
    if (!feed) {
      console.log(
        chalk.yellow("  Could not reach the community feed. Try again later.\n")
      );
      process.exit(0);
    }

    console.log(formatThreatFeed(feed));
  });

program
  .command("subscribe")
  .description("Subscribe to community threat alerts via webhook")
  .option("--webhook <url>", "Discord, Slack, or generic webhook URL")
  .option("--threshold <severity>", "Minimum severity to alert on", "HIGH")
  .option("-p, --path <path>", "OpenClaw installation path", "~/.openclaw")
  .action(async (options) => {
    if (!options.webhook) {
      console.error(chalk.red("\n  --webhook <url> is required.\n"));
      console.log(chalk.dim("  Examples:"));
      console.log(chalk.dim("    clawhatch subscribe --webhook https://discord.com/api/webhooks/..."));
      console.log(chalk.dim("    clawhatch subscribe --webhook https://hooks.slack.com/services/..."));
      console.log(chalk.dim("    clawhatch subscribe --threshold CRITICAL\n"));
      process.exit(1);
    }

    const { homedir } = await import("node:os");
    const { join } = await import("node:path");
    const openclawDir = options.path.startsWith("~")
      ? join(homedir(), options.path.slice(1))
      : options.path;

    const threshold = options.threshold.toUpperCase();
    const valid = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    if (!valid.includes(threshold)) {
      console.error(chalk.red(`\n  Invalid threshold: ${threshold}`));
      console.error(chalk.dim(`  Valid: ${valid.join(", ")}\n`));
      process.exit(1);
    }

    // Save webhook config
    await saveNotifyConfig(openclawDir, {
      notify: {
        webhookUrl: options.webhook,
        threshold,
      },
    });

    console.log(chalk.dim("\n  Sending test alert..."));
    const ok = await sendTestAlert(options.webhook);

    if (ok) {
      console.log(chalk.green("  Webhook confirmed! You will receive alerts here."));
    } else {
      console.log(chalk.yellow("  Could not reach webhook. Check the URL and try again."));
    }

    console.log(chalk.dim(`  Threshold: ${threshold} and above`));
    console.log(chalk.dim(`  Config saved to: ${openclawDir}/clawhatch.json\n`));
  });

program.parse();
