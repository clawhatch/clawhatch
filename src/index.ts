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
import { reportFindings, reportJson, reportQuiet } from "./reporter.js";
import { generateHtmlReport } from "./reporter-html.js";
import { applyFixes } from "./fixer.js";
import { sanitizeFindings, redactPaths } from "./sanitize.js";
import { initSecureConfig } from "./init.js";
import { anonymizeScanResult, uploadThreatReport } from "./telemetry.js";
import { DEFAULT_API_URL, fetchThreatFeed, formatThreatFeed, checkAgainstFeed } from "./threat-feed.js";
import { loadNotifyConfig, saveNotifyConfig, buildAlerts, sendWebhookAlert, sendTestAlert } from "./notify.js";

const program = new Command();

program
  .name("clawhatch")
  .description("Security scanner for OpenClaw AI agents")
  .version("0.2.1");

program
  .command("scan")
  .description("Scan your OpenClaw installation for security issues")
  .option("-p, --path <path>", "OpenClaw installation path", "~/.openclaw")
  .option("-w, --workspace <path>", "Workspace path (for SOUL.md, skills, etc.)")
  .option("--json", "Output JSON instead of formatted text")
  .option("--quiet", "Only output score and grade (no details)")
  .option("--format <format>", "Output format: text, json, html", "text")
  .option("--fix", "Auto-apply safe fixes (prompts for behavioral changes)")
  .option("--deep", "Deep scan — full session log analysis (slower)")
  .option("--share", "Anonymize and share results with community threat feed")
  .option("--upload", "Alias for --share")
  .option("--redact-paths", "Redact file paths in output (for sharing results)")
  .action(async (options) => {
    // --json flag is an alias for --format json
    // --quiet flag overrides format
    const format: string = options.quiet ? "quiet" : (options.json ? "json" : options.format);
    const shouldShare = !!(options.share || options.upload);

    if (format === "text") {
      console.log(chalk.cyan("\n  Clawhatch Security Scanner v0.2.1\n"));
    }

    const result = await scan({
      openclawPath: options.path,
      workspacePath: options.workspace,
      autoFix: !!options.fix,
      deep: !!options.deep,
      json: format === "json",
      upload: shouldShare,
    });

    // Apply path redaction if requested
    if (options.redactPaths) {
      result.findings = redactPaths(result.findings);
      result.suggestions = redactPaths(result.suggestions);
    }

    // Output results
    if (format === "quiet") {
      reportQuiet(result);
    } else if (format === "json") {
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
      if (format !== "json" && format !== "quiet") {
        console.log(chalk.dim("\n  Sharing anonymized results with community..."));
      }
      const uploadResult = await uploadThreatReport(report, DEFAULT_API_URL);
      if (uploadResult.success) {
        if (format !== "json" && format !== "quiet") {
          console.log(chalk.green("  Shared with community threat feed."));
        }
      } else {
        if (format !== "json" && format !== "quiet") {
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
          if (format !== "json" && format !== "quiet") {
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
    console.log(chalk.cyan("\n  Clawhatch Config Generator v0.2.1\n"));

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

program
  .command("monitor")
  .description("Monitor your OpenClaw installation on a schedule")
  .option("--start", "Start scheduled monitoring")
  .option("--stop", "Stop scheduled monitoring")
  .option("--status", "Show monitoring status and scan history")
  .option("--report", "Generate a trend report")
  .option("-p, --path <path>", "OpenClaw installation path", "~/.openclaw")
  .option("--schedule <schedule>", "Schedule (daily, hourly, etc.)", "daily")
  .action(async (options) => {
    const {
      loadMonitorConfig,
      saveMonitorConfig,
      checkLicense,
      showUpsell,
      loadHistory,
      getLastScan,
      compareScanResults,
      generateTrendReport,
      formatTimestamp,
      formatDuration,
      getHistorySize,
      formatBytes,
      saveToHistory,
    } = await import("./monitor.js");

    // --start: Enable monitoring
    if (options.start) {
      const license = await checkLicense();
      
      if (license.tier === "free") {
        console.log(chalk.yellow("\n  ⚠️  Scheduled monitoring is a paid feature.\n"));
        showUpsell();
        process.exit(1);
      }

      const config = await loadMonitorConfig();
      config.enabled = true;
      config.schedule = options.schedule;
      config.lastRun = new Date().toISOString();
      await saveMonitorConfig(config);

      console.log(chalk.green("\n  ✓ Monitoring started"));
      console.log(chalk.dim(`    Schedule: ${config.schedule}`));
      console.log(chalk.dim(`    Config: ~/.clawhatch/config.json\n`));
      process.exit(0);
    }

    // --stop: Disable monitoring
    if (options.stop) {
      const config = await loadMonitorConfig();
      config.enabled = false;
      await saveMonitorConfig(config);

      console.log(chalk.yellow("\n  Monitoring stopped\n"));
      process.exit(0);
    }

    // --status: Show current status and history
    if (options.status) {
      const config = await loadMonitorConfig();
      const license = await checkLicense();
      const history = await loadHistory();
      const historySize = await getHistorySize();

      console.log(chalk.cyan("\n  Clawhatch Monitor Status\n"));
      
      console.log(chalk.bold("  License"));
      console.log(`    Tier: ${license.tier === "paid" ? chalk.green("Paid") : chalk.dim("Free")}`);
      if (license.tier === "free") {
        console.log(chalk.dim("    (Scheduled monitoring requires paid tier)"));
      }
      
      console.log("");
      console.log(chalk.bold("  Monitoring"));
      console.log(`    Status: ${config.enabled ? chalk.green("Enabled") : chalk.dim("Disabled")}`);
      if (config.enabled) {
        console.log(`    Schedule: ${config.schedule}`);
        if (config.lastRun) {
          console.log(`    Last run: ${formatTimestamp(config.lastRun)}`);
        }
      }
      
      console.log("");
      console.log(chalk.bold("  History"));
      console.log(`    Scans: ${history.length}`);
      console.log(`    Storage: ${formatBytes(historySize)}`);
      console.log(`    Location: ~/.clawhatch/history/`);
      
      if (history.length > 0) {
        console.log("");
        console.log(chalk.bold("  Recent Scans"));
        const recent = history.slice(0, 10);
        for (const entry of recent) {
          const scoreColor = entry.score >= 80 ? chalk.green : entry.score >= 60 ? chalk.yellow : chalk.red;
          console.log(`    ${formatTimestamp(entry.timestamp)}: Score ${scoreColor(entry.score.toString())}/100 (${entry.findings.length} findings, ${formatDuration(entry.duration)})`);
        }
        
        if (history.length > 10) {
          console.log(chalk.dim(`    ... and ${history.length - 10} more`));
        }
      }
      
      console.log("");
      
      if (license.tier === "free") {
        showUpsell();
      }
      
      process.exit(0);
    }

    // --report: Generate trend report
    if (options.report) {
      const license = await checkLicense();
      
      if (license.tier === "free") {
        console.log(chalk.yellow("\n  ⚠️  Trend reports are a paid feature.\n"));
        showUpsell();
        process.exit(1);
      }

      const report = await generateTrendReport();
      
      if (!report) {
        console.log(chalk.yellow("\n  Not enough data for a trend report."));
        console.log(chalk.dim("  Run at least 2 scans to generate trends.\n"));
        process.exit(0);
      }

      console.log(chalk.cyan("\n  Clawhatch Trend Report\n"));
      
      console.log(chalk.bold("  Period"));
      console.log(`    From: ${formatTimestamp(report.periodStart)}`);
      console.log(`    To:   ${formatTimestamp(report.periodEnd)}`);
      console.log(`    Scans: ${report.scans}`);
      
      console.log("");
      console.log(chalk.bold("  Score Trends"));
      console.log(`    Current:  ${report.scoreCurrent}/100`);
      console.log(`    Average:  ${report.scoreAverage}/100`);
      console.log(`    Range:    ${report.scoreMin}–${report.scoreMax}`);
      
      const trendIcon = report.trend === "improving" ? "📈" : report.trend === "declining" ? "📉" : "➡️";
      const trendColor = report.trend === "improving" ? chalk.green : report.trend === "declining" ? chalk.red : chalk.dim;
      console.log(`    Trend:    ${trendIcon} ${trendColor(report.trend.toUpperCase())}`);
      
      console.log("");
      console.log(chalk.bold("  Issue Changes"));
      console.log(`    New issues:        ${chalk.red(report.newIssues.length.toString())}`);
      console.log(`    Resolved issues:   ${chalk.green(report.resolvedIssues.length.toString())}`);
      console.log(`    Persistent issues: ${chalk.yellow(report.persistentIssues.length.toString())}`);
      
      if (report.newIssues.length > 0) {
        console.log("");
        console.log(chalk.bold.red("  New Issues"));
        for (const issue of report.newIssues.slice(0, 5)) {
          const severityColor = issue.severity === "CRITICAL" ? chalk.red : issue.severity === "HIGH" ? chalk.yellow : chalk.dim;
          console.log(`    ${severityColor("●")} ${issue.title}`);
        }
        if (report.newIssues.length > 5) {
          console.log(chalk.dim(`    ... and ${report.newIssues.length - 5} more`));
        }
      }
      
      if (report.resolvedIssues.length > 0) {
        console.log("");
        console.log(chalk.bold.green("  Resolved Issues"));
        for (const issue of report.resolvedIssues.slice(0, 5)) {
          console.log(`    ${chalk.green("✓")} ${issue.title}`);
        }
        if (report.resolvedIssues.length > 5) {
          console.log(chalk.dim(`    ... and ${report.resolvedIssues.length - 5} more`));
        }
      }
      
      console.log("");
      process.exit(0);
    }

    // Default: Run a manual scan and compare to last
    console.log(chalk.cyan("\n  Clawhatch Monitor — Manual Scan\n"));
    
    const result = await scan({
      openclawPath: options.path,
      autoFix: false,
      deep: false,
      json: false,
      upload: false,
    });

    // Get previous scan before saving
    const previousScan = await getLastScan();
    
    // Save to history
    const historyPath = await saveToHistory(result);
    console.log(chalk.dim(`  Saved to: ${historyPath}`));
    
    // Compare to last scan
    if (previousScan) {
      const comparison = compareScanResults(result, previousScan);
      
      console.log("");
      console.log(chalk.bold("  Changes Since Last Scan"));
      
      const deltaIcon = comparison.scoreDelta > 0 ? "📈" : comparison.scoreDelta < 0 ? "📉" : "➡️";
      const deltaColor = comparison.scoreDelta > 0 ? chalk.green : comparison.scoreDelta < 0 ? chalk.red : chalk.dim;
      const deltaSign = comparison.scoreDelta > 0 ? "+" : "";
      console.log(`    Score: ${result.score}/100 ${deltaIcon} ${deltaColor(deltaSign + comparison.scoreDelta.toString())}`);
      
      if (comparison.newIssues.length > 0) {
        console.log(`    ${chalk.red("New issues:")} ${comparison.newIssues.length}`);
        for (const issue of comparison.newIssues.slice(0, 3)) {
          const severityColor = issue.severity === "CRITICAL" ? chalk.red : issue.severity === "HIGH" ? chalk.yellow : chalk.dim;
          console.log(`      ${severityColor("●")} ${issue.title}`);
        }
        if (comparison.newIssues.length > 3) {
          console.log(chalk.dim(`      ... and ${comparison.newIssues.length - 3} more`));
        }
      }
      
      if (comparison.resolvedIssues.length > 0) {
        console.log(`    ${chalk.green("Resolved issues:")} ${comparison.resolvedIssues.length}`);
        for (const issue of comparison.resolvedIssues.slice(0, 3)) {
          console.log(`      ${chalk.green("✓")} ${issue.title}`);
        }
        if (comparison.resolvedIssues.length > 3) {
          console.log(chalk.dim(`      ... and ${comparison.resolvedIssues.length - 3} more`));
        }
      }
      
      if (comparison.newIssues.length === 0 && comparison.resolvedIssues.length === 0) {
        console.log(chalk.dim("    No changes"));
      }
    } else {
      console.log("");
      console.log(chalk.dim("  First scan — no comparison available"));
    }
    
    reportFindings(result);
    
    const license = await checkLicense();
    if (license.tier === "free") {
      showUpsell();
    }
    
    process.exit(0);
  });

program.parse();
