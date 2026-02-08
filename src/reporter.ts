/**
 * Terminal output reporter.
 *
 * Formats scan results as colored terminal output.
 * Separates high-confidence "Findings" from low-confidence "Suggestions".
 */

import chalk from "chalk";
import { Severity, type Finding, type ScanResult } from "./types.js";
import { getScoreGrade } from "./scoring.js";

const SEVERITY_ICONS: Record<Severity, string> = {
  [Severity.Critical]: chalk.red("!!"),
  [Severity.High]: chalk.yellow("!"),
  [Severity.Medium]: chalk.cyan("~"),
  [Severity.Low]: chalk.dim("-"),
};

const SEVERITY_LABELS: Record<Severity, string> = {
  [Severity.Critical]: chalk.red.bold("CRITICAL"),
  [Severity.High]: chalk.yellow.bold("HIGH"),
  [Severity.Medium]: chalk.cyan("MEDIUM"),
  [Severity.Low]: chalk.dim("LOW"),
};

function formatFinding(finding: Finding, index: number): string {
  const icon = SEVERITY_ICONS[finding.severity];
  const lines: string[] = [];

  lines.push(`  ${icon} ${chalk.white.bold(finding.title)}`);
  lines.push(`     ${chalk.dim(finding.description)}`);
  lines.push(`     ${chalk.dim("Risk:")} ${finding.risk}`);
  lines.push(`     ${chalk.dim("Fix:")} ${finding.remediation}`);

  if (finding.file) {
    const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    lines.push(`     ${chalk.dim("File:")} ${loc}`);
  }

  if (finding.autoFixable) {
    lines.push(`     ${chalk.green("Auto-fixable with --fix")}`);
  }

  return lines.join("\n");
}

function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const groups = new Map<Severity, Finding[]>();
  const order = [Severity.Critical, Severity.High, Severity.Medium, Severity.Low];

  for (const sev of order) {
    groups.set(sev, []);
  }

  for (const f of findings) {
    groups.get(f.severity)!.push(f);
  }

  return groups;
}

export function reportFindings(result: ScanResult): void {
  const { grade, label, color } = getScoreGrade(result.score);
  const colorFn = chalk[color] as (s: string) => string;

  // Header
  console.log("");
  console.log(
    chalk.cyan.bold(
      "  Clawhatch Security Scan"
    )
  );
  console.log(chalk.dim("  " + "=".repeat(50)));
  console.log("");

  // Score
  console.log(
    `  ${chalk.dim("Security Score:")} ${colorFn(
      `${result.score}/100`
    )} ${colorFn(`(${grade} — ${label})`)}`
  );
  console.log("");

  // Metadata
  console.log(chalk.dim(`  Platform: ${result.platform}`));
  if (result.openclawVersion) {
    console.log(chalk.dim(`  OpenClaw: ${result.openclawVersion}`));
  }
  console.log(
    chalk.dim(
      `  Checks: ${result.checksRun} run, ${result.checksPassed} passed, ${result.findings.length} findings`
    )
  );
  console.log(chalk.dim(`  Duration: ${result.duration}ms`));
  console.log(chalk.dim(`  Scanned: ${result.filesScanned} files`));
  console.log("");
  console.log(chalk.dim("  " + "-".repeat(50)));

  // Findings (high/medium confidence)
  if (result.findings.length === 0) {
    console.log("");
    console.log(chalk.green.bold("  No security findings! Your setup looks solid."));
  } else {
    const grouped = groupBySeverity(result.findings);

    for (const [severity, findings] of grouped) {
      if (findings.length === 0) continue;

      console.log("");
      console.log(
        `  ${SEVERITY_LABELS[severity]} (${findings.length} finding${findings.length > 1 ? "s" : ""})`
      );
      console.log("");

      for (let i = 0; i < findings.length; i++) {
        console.log(formatFinding(findings[i], i));
        if (i < findings.length - 1) console.log("");
      }
    }
  }

  // Suggestions (low confidence)
  if (result.suggestions.length > 0) {
    console.log("");
    console.log(chalk.dim("  " + "-".repeat(50)));
    console.log("");
    console.log(
      chalk.dim.bold(
        `  SUGGESTIONS (${result.suggestions.length} — lower confidence, review manually)`
      )
    );
    console.log("");

    for (const s of result.suggestions) {
      console.log(`  ${chalk.dim("~")} ${chalk.dim(s.title)}`);
      console.log(`     ${chalk.dim(s.remediation)}`);
    }
  }

  // Footer
  console.log("");
  console.log(chalk.dim("  " + "=".repeat(50)));
  console.log("");

  const autoFixCount = result.findings.filter((f) => f.autoFixable).length;
  if (autoFixCount > 0) {
    console.log(
      chalk.green(`  ${autoFixCount} issue(s) can be auto-fixed. Run with --fix`)
    );
  }
  console.log(chalk.dim("  Run with --json for machine-readable output"));
  console.log(chalk.dim("  Run with --deep for thorough session log scanning"));
  console.log(chalk.dim("  Run with --share to contribute to community threat feed"));
  console.log("");
  console.log(chalk.cyan("  📊 Community threats: ") + chalk.underline("https://clawhatch.com"));
  console.log(chalk.cyan("  📖 Full docs: ") + chalk.underline("https://clawhatch.com/docs"));
  console.log("");
}

export function reportJson(result: ScanResult): void {
  // Output clean JSON for piping to other tools
  const output = {
    ...result,
    // Flatten for convenience
    summary: {
      score: result.score,
      grade: getScoreGrade(result.score).grade,
      label: getScoreGrade(result.score).label,
      critical: result.findings.filter((f) => f.severity === Severity.Critical).length,
      high: result.findings.filter((f) => f.severity === Severity.High).length,
      medium: result.findings.filter((f) => f.severity === Severity.Medium).length,
      low: result.findings.filter((f) => f.severity === Severity.Low).length,
      suggestions: result.suggestions.length,
      autoFixable: result.findings.filter((f) => f.autoFixable).length,
    },
  };

  console.log(JSON.stringify(output, null, 2));
}

export function reportQuiet(result: ScanResult): void {
  // Quiet mode: only output score and grade (for CI/CD scripting)
  const { grade, label } = getScoreGrade(result.score);
  console.log(`${result.score}/100 ${grade} (${label})`);
}
