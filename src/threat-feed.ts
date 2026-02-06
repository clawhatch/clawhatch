/**
 * Threat feed client — fetches community threat intelligence and formats
 * it for terminal display. Cross-references local scan results against
 * community-wide trends.
 */

import chalk from "chalk";
import type { ScanResult, ThreatFeed, ThreatFeedEntry } from "./types.js";

export const DEFAULT_API_URL = "https://api.clawhatch.com";

/** Fetch the community threat feed. Returns null on any failure. */
export async function fetchThreatFeed(
  apiUrl: string,
): Promise<ThreatFeed | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`${apiUrl}/v1/feed`, {
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!res.ok) return null;
    return (await res.json()) as ThreatFeed;
  } catch {
    return null;
  }
}

/** Format a number with commas (e.g. 1234 -> "1,234"). */
function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

/** Colorize a severity label with chalk. */
function colorSeverity(severity: string): string {
  const s = severity.toUpperCase();
  switch (s) {
    case "CRITICAL":
      return chalk.red.bold(s.padEnd(8));
    case "HIGH":
      return chalk.yellow.bold(s.padEnd(8));
    case "MEDIUM":
      return chalk.cyan(s.padEnd(8));
    case "LOW":
      return chalk.dim(s.padEnd(8));
    default:
      return s.padEnd(8);
  }
}

/** Render a frequency bar like "######----" (10 chars wide). */
function frequencyBar(frequency: number): string {
  const width = 10;
  const filled = Math.round(frequency * width);
  const empty = width - filled;
  return "#".repeat(filled) + "-".repeat(empty);
}

/** How long ago a timestamp was in human terms. */
function timeAgo(isoDate: string): string {
  const diff = Date.now() - new Date(isoDate).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/** Format a ThreatFeed as a chalk-colored terminal string. */
export function formatThreatFeed(feed: ThreatFeed): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold.cyan("Clawhatch Community Threat Intelligence"));
  lines.push(chalk.cyan("========================================"));
  lines.push("");

  // Community Stats
  lines.push(chalk.bold("Community Stats"));
  lines.push(`  Total Scans: ${formatNumber(feed.totalScans)}`);
  lines.push(`  Active Instances: ${formatNumber(feed.totalInstances)}`);
  lines.push(`  Average Score: ${feed.communityScore}/100`);
  lines.push("");

  // Top Threats
  if (feed.topThreats.length > 0) {
    lines.push(chalk.bold("Top Threats"));
    for (const t of feed.topThreats) {
      const pct = Math.round(t.frequency * 100);
      const bar = frequencyBar(t.frequency);
      const trending = t.trending
        ? "  " + chalk.red("trending")
        : "";
      lines.push(
        `  ${colorSeverity(t.severity)}  ${t.id.padEnd(14)}  ${t.title.padEnd(24)}  ${bar}  ${String(pct).padStart(3)}%${trending}`,
      );
    }
    lines.push("");
  }

  // New Threats (last 24h)
  if (feed.newThreats.length > 0) {
    lines.push(chalk.bold("New Threats (last 24h)"));
    for (const t of feed.newThreats) {
      const ago = timeAgo(t.firstSeen);
      lines.push(
        `  ${colorSeverity(t.severity)}  ${t.id.padEnd(14)}  ${t.title}  ${chalk.dim(`First seen: ${ago}`)}`,
      );
    }
    lines.push("");
  }

  // Advisories
  if (feed.advisories.length > 0) {
    lines.push(chalk.bold("Advisories"));
    for (const a of feed.advisories) {
      lines.push(
        `  ${chalk.yellow("!")} [${a.id}] ${a.title}`,
      );
      if (a.affectedChecks.length > 0) {
        lines.push(
          `    ${chalk.dim("Affects: " + a.affectedChecks.join(", "))}`,
        );
      }
    }
    lines.push("");
  }

  return lines.join("\n");
}

/** Cross-reference local scan findings against the community feed. */
export function checkAgainstFeed(
  result: ScanResult,
  feed: ThreatFeed,
): string[] {
  const warnings: string[] = [];
  const threatMap = new Map<string, ThreatFeedEntry>();
  for (const t of feed.topThreats) {
    threatMap.set(t.id, t);
  }

  for (const finding of result.findings) {
    const threat = threatMap.get(finding.id);
    if (!threat) continue;

    const pct = Math.round(threat.frequency * 100);
    if (threat.trending) {
      warnings.push(
        `${finding.id} is trending - affects ${pct}% of the community`,
      );
    } else if (threat.frequency > 0.3) {
      warnings.push(
        `${finding.id} affects ${pct}% of the community`,
      );
    }
  }

  return warnings;
}
