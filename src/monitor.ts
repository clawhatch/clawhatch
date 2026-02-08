/**
 * Clawhatch Monitor — Scheduled scanning and trend analysis.
 * 
 * - Stores scan results in ~/.clawhatch/history/ as timestamped JSON files
 * - Compares current scan to previous to detect changes
 * - Generates trend reports showing score history and issue deltas
 */

import { readFile, writeFile, readdir, mkdir, stat } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { existsSync } from "node:fs";
import type { 
  ScanResult, 
  Finding, 
  MonitorConfig, 
  HistoryEntry, 
  TrendReport, 
  ComparisonResult 
} from "./types.js";

/**
 * Get the Clawhatch config directory (~/.clawhatch/)
 */
export function getClawhatchDir(): string {
  return join(homedir(), ".clawhatch");
}

/**
 * Get the history directory (~/.clawhatch/history/)
 */
export function getHistoryDir(): string {
  return join(getClawhatchDir(), "history");
}

/**
 * Get the config file path (~/.clawhatch/config.json)
 */
export function getConfigPath(): string {
  return join(getClawhatchDir(), "config.json");
}

/**
 * Get the license key file path (~/.clawhatch/license.key)
 */
export function getLicenseKeyPath(): string {
  return join(getClawhatchDir(), "license.key");
}

/**
 * Ensure ~/.clawhatch/ and history/ directories exist
 */
export async function ensureDirectories(): Promise<void> {
  const dirs = [getClawhatchDir(), getHistoryDir()];
  for (const dir of dirs) {
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true });
    }
  }
}

/**
 * Load monitoring config from ~/.clawhatch/config.json
 */
export async function loadMonitorConfig(): Promise<MonitorConfig> {
  const configPath = getConfigPath();
  
  if (!existsSync(configPath)) {
    // Default config
    return {
      enabled: false,
      schedule: "daily",
      alertOnScoreChange: true,
      scoreChangeThreshold: 5,
    };
  }
  
  try {
    const content = await readFile(configPath, "utf-8");
    const config = JSON.parse(content);
    return {
      enabled: config.enabled ?? false,
      schedule: config.schedule ?? "daily",
      lastRun: config.lastRun,
      licenseKey: config.licenseKey,
      alertOnScoreChange: config.alertOnScoreChange ?? true,
      scoreChangeThreshold: config.scoreChangeThreshold ?? 5,
    };
  } catch (err) {
    throw new Error(`Failed to load monitor config: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Save monitoring config to ~/.clawhatch/config.json
 */
export async function saveMonitorConfig(config: MonitorConfig): Promise<void> {
  await ensureDirectories();
  const configPath = getConfigPath();
  await writeFile(configPath, JSON.stringify(config, null, 2), "utf-8");
}

/**
 * Check if a valid license key exists
 * Returns: { valid: boolean, tier: 'free' | 'paid' }
 */
export async function checkLicense(): Promise<{ valid: boolean; tier: "free" | "paid" }> {
  const licensePath = getLicenseKeyPath();
  
  if (!existsSync(licensePath)) {
    return { valid: false, tier: "free" };
  }
  
  try {
    const key = (await readFile(licensePath, "utf-8")).trim();
    
    // Placeholder validation: For now, any non-empty key is "valid"
    // In production, this would call an API to verify the license
    if (key.length > 0) {
      return { valid: true, tier: "paid" };
    }
    
    return { valid: false, tier: "free" };
  } catch {
    return { valid: false, tier: "free" };
  }
}

/**
 * Show a tasteful upsell message for free tier users
 */
export function showUpsell(): void {
  console.log("");
  console.log("  💡 Want automated monitoring?");
  console.log("     • Scheduled scans (daily/hourly)");
  console.log("     • Score history & trend reports");
  console.log("     • Change alerts");
  console.log("");
  console.log("     Visit clawhatch.com/pricing");
  console.log("");
}

/**
 * Save a scan result to history (~/.clawhatch/history/YYYY-MM-DD_HHmmss.json)
 */
export async function saveToHistory(result: ScanResult): Promise<string> {
  await ensureDirectories();
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").split(".")[0];
  const filename = `${timestamp}.json`;
  const filepath = join(getHistoryDir(), filename);
  
  const entry: HistoryEntry = {
    timestamp: result.timestamp,
    score: result.score,
    findings: result.findings,
    duration: result.duration,
    checksRun: result.checksRun,
  };
  
  await writeFile(filepath, JSON.stringify(entry, null, 2), "utf-8");
  return filepath;
}

/**
 * Load all history entries, sorted by timestamp (newest first)
 */
export async function loadHistory(): Promise<HistoryEntry[]> {
  const historyDir = getHistoryDir();
  
  if (!existsSync(historyDir)) {
    return [];
  }
  
  const files = await readdir(historyDir);
  const jsonFiles = files.filter(f => f.endsWith(".json")).sort().reverse();
  
  const entries: HistoryEntry[] = [];
  for (const file of jsonFiles) {
    try {
      const content = await readFile(join(historyDir, file), "utf-8");
      const entry = JSON.parse(content) as HistoryEntry;
      entries.push(entry);
    } catch {
      // Skip invalid files
    }
  }
  
  return entries;
}

/**
 * Get the most recent history entry
 */
export async function getLastScan(): Promise<HistoryEntry | null> {
  const history = await loadHistory();
  return history.length > 0 ? history[0] : null;
}

/**
 * Compare two scan results and identify changes
 */
export function compareScanResults(current: ScanResult, previous: HistoryEntry): ComparisonResult {
  const currentIds = new Set(current.findings.map(f => f.id));
  const previousIds = new Set(previous.findings.map(f => f.id));
  
  // New issues: in current but not in previous
  const newIssues = current.findings.filter(f => !previousIds.has(f.id));
  
  // Resolved issues: in previous but not in current
  const resolvedIssues = previous.findings.filter(f => !currentIds.has(f.id));
  
  // Unchanged issues: in both
  const unchangedIssues = current.findings.filter(f => previousIds.has(f.id));
  
  const scoreDelta = current.score - previous.score;
  
  return {
    newIssues,
    resolvedIssues,
    unchangedIssues,
    scoreChange: current.score,
    scoreDelta,
  };
}

/**
 * Generate a trend report from history
 */
export async function generateTrendReport(): Promise<TrendReport | null> {
  const history = await loadHistory();
  
  if (history.length < 2) {
    return null; // Need at least 2 scans for trends
  }
  
  const scores = history.map(h => h.score);
  const current = history[0];
  const oldest = history[history.length - 1];
  
  // Calculate trend
  let trend: "improving" | "declining" | "stable" = "stable";
  const scoreDiff = current.score - oldest.score;
  
  if (scoreDiff > 5) {
    trend = "improving";
  } else if (scoreDiff < -5) {
    trend = "declining";
  }
  
  // Compare current to oldest to find new/resolved issues
  const currentIds = new Set(current.findings.map(f => f.id));
  const oldestIds = new Set(oldest.findings.map(f => f.id));
  
  const newIssues = current.findings.filter(f => !oldestIds.has(f.id));
  const resolvedIssues = oldest.findings.filter(f => !currentIds.has(f.id));
  const persistentIssues = current.findings.filter(f => oldestIds.has(f.id));
  
  return {
    periodStart: oldest.timestamp,
    periodEnd: current.timestamp,
    scans: history.length,
    scoreMin: Math.min(...scores),
    scoreMax: Math.max(...scores),
    scoreAverage: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
    scoreCurrent: current.score,
    trend,
    newIssues,
    resolvedIssues,
    persistentIssues,
  };
}

/**
 * Calculate how long until next scheduled run
 * Returns milliseconds until next run, or null if not scheduled
 */
export function getNextRunDelay(schedule: string, lastRun?: string): number | null {
  const now = Date.now();
  
  if (schedule === "daily") {
    const oneDay = 24 * 60 * 60 * 1000;
    
    if (!lastRun) {
      return 0; // Run immediately if never run before
    }
    
    const lastRunTime = new Date(lastRun).getTime();
    const nextRun = lastRunTime + oneDay;
    
    if (nextRun <= now) {
      return 0; // Overdue, run immediately
    }
    
    return nextRun - now;
  }
  
  // For other schedules, return null (not implemented yet)
  return null;
}

/**
 * Check if monitoring is due to run
 */
export async function isDueToRun(): Promise<boolean> {
  const config = await loadMonitorConfig();
  
  if (!config.enabled) {
    return false;
  }
  
  const delay = getNextRunDelay(config.schedule, config.lastRun);
  return delay === 0;
}

/**
 * Format a timestamp for display
 */
export function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Format duration in milliseconds to human-readable string
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  if (ms < 60000) {
    return `${(ms / 1000).toFixed(1)}s`;
  }
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

/**
 * Get history size (total size of all history files in bytes)
 */
export async function getHistorySize(): Promise<number> {
  const historyDir = getHistoryDir();
  
  if (!existsSync(historyDir)) {
    return 0;
  }
  
  const files = await readdir(historyDir);
  let totalSize = 0;
  
  for (const file of files) {
    try {
      const stats = await stat(join(historyDir, file));
      totalSize += stats.size;
    } catch {
      // Skip files we can't stat
    }
  }
  
  return totalSize;
}

/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
