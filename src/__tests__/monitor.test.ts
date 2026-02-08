/**
 * Tests for monitoring module
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { existsSync } from "node:fs";
import type { ScanResult, Finding, HistoryEntry } from "../types.js";
import {
  ensureDirectories,
  loadMonitorConfig,
  saveMonitorConfig,
  checkLicense,
  saveToHistory,
  loadHistory,
  getLastScan,
  compareScanResults,
  generateTrendReport,
  formatTimestamp,
  formatDuration,
  formatBytes,
} from "../monitor.js";

// Mock Clawhatch directory for testing
const testDir = join(tmpdir(), `clawhatch-test-${Date.now()}`);

// Override the directory functions for testing
const originalHomedir = process.env.HOME || process.env.USERPROFILE || "";

async function setupTestEnv() {
  process.env.HOME = testDir;
  process.env.USERPROFILE = testDir;
  
  if (existsSync(testDir)) {
    await rm(testDir, { recursive: true, force: true });
  }
  await mkdir(testDir, { recursive: true });
}

async function cleanupTestEnv() {
  if (existsSync(testDir)) {
    await rm(testDir, { recursive: true, force: true });
  }
  process.env.HOME = originalHomedir;
  process.env.USERPROFILE = originalHomedir;
}

// Mock scan result
const mockScanResult: ScanResult = {
  timestamp: new Date().toISOString(),
  openclawVersion: "1.0.0",
  score: 75,
  findings: [
    {
      id: "TEST-001",
      severity: "CRITICAL" as any,
      confidence: "high",
      category: "test",
      title: "Test Finding",
      description: "Test description",
      risk: "Test risk",
      remediation: "Test fix",
      autoFixable: false,
    },
  ],
  suggestions: [],
  filesScanned: 10,
  checksRun: 100,
  checksPassed: 90,
  duration: 123,
  platform: "linux" as NodeJS.Platform,
};

test("ensureDirectories creates config and history directories", async () => {
  await setupTestEnv();
  
  await ensureDirectories();
  
  const clawhatchDir = join(testDir, ".clawhatch");
  const historyDir = join(clawhatchDir, "history");
  
  assert.ok(existsSync(clawhatchDir), "Config directory should exist");
  assert.ok(existsSync(historyDir), "History directory should exist");
  
  await cleanupTestEnv();
});

test("loadMonitorConfig returns default config when file doesn't exist", async () => {
  await setupTestEnv();
  
  const config = await loadMonitorConfig();
  
  assert.equal(config.enabled, false);
  assert.equal(config.schedule, "daily");
  assert.equal(config.alertOnScoreChange, true);
  assert.equal(config.scoreChangeThreshold, 5);
  
  await cleanupTestEnv();
});

test("saveMonitorConfig and loadMonitorConfig work together", async () => {
  await setupTestEnv();
  
  const config = {
    enabled: true,
    schedule: "hourly",
    lastRun: "2026-02-07T12:00:00Z",
    licenseKey: "test-key",
    alertOnScoreChange: false,
    scoreChangeThreshold: 10,
  };
  
  await saveMonitorConfig(config);
  const loaded = await loadMonitorConfig();
  
  assert.equal(loaded.enabled, true);
  assert.equal(loaded.schedule, "hourly");
  assert.equal(loaded.lastRun, "2026-02-07T12:00:00Z");
  assert.equal(loaded.licenseKey, "test-key");
  assert.equal(loaded.alertOnScoreChange, false);
  assert.equal(loaded.scoreChangeThreshold, 10);
  
  await cleanupTestEnv();
});

test("checkLicense returns free tier when no license exists", async () => {
  await setupTestEnv();
  
  const license = await checkLicense();
  
  assert.equal(license.valid, false);
  assert.equal(license.tier, "free");
  
  await cleanupTestEnv();
});

test("checkLicense returns paid tier when valid license exists", async () => {
  await setupTestEnv();
  
  const licensePath = join(testDir, ".clawhatch", "license.key");
  await ensureDirectories();
  await writeFile(licensePath, "VALID-LICENSE-KEY", "utf-8");
  
  const license = await checkLicense();
  
  assert.equal(license.valid, true);
  assert.equal(license.tier, "paid");
  
  await cleanupTestEnv();
});

test("saveToHistory creates timestamped JSON file", async () => {
  await setupTestEnv();
  
  const filepath = await saveToHistory(mockScanResult);
  
  assert.ok(existsSync(filepath), "History file should exist");
  
  const content = await readFile(filepath, "utf-8");
  const entry = JSON.parse(content);
  
  assert.equal(entry.score, 75);
  assert.equal(entry.findings.length, 1);
  assert.equal(entry.checksRun, 100);
  
  await cleanupTestEnv();
});

test("loadHistory returns all history entries sorted by timestamp", async () => {
  await setupTestEnv();
  
  // Create multiple history entries
  await saveToHistory({ ...mockScanResult, score: 70 });
  // Wait a bit to ensure different timestamps
  await new Promise(resolve => setTimeout(resolve, 10));
  await saveToHistory({ ...mockScanResult, score: 80 });
  await new Promise(resolve => setTimeout(resolve, 10));
  await saveToHistory({ ...mockScanResult, score: 90 });
  
  const history = await loadHistory();
  
  assert.equal(history.length, 3);
  // Should be sorted newest first
  assert.equal(history[0].score, 90);
  assert.equal(history[1].score, 80);
  assert.equal(history[2].score, 70);
  
  await cleanupTestEnv();
});

test("getLastScan returns most recent entry", async () => {
  await setupTestEnv();
  
  await saveToHistory({ ...mockScanResult, score: 70 });
  await new Promise(resolve => setTimeout(resolve, 10));
  await saveToHistory({ ...mockScanResult, score: 85 });
  
  const lastScan = await getLastScan();
  
  assert.ok(lastScan !== null);
  assert.equal(lastScan!.score, 85);
  
  await cleanupTestEnv();
});

test("compareScanResults identifies new, resolved, and unchanged issues", async () => {
  await setupTestEnv();
  
  const oldFinding: Finding = {
    id: "OLD-001",
    severity: "HIGH" as any,
    confidence: "high",
    category: "test",
    title: "Old Finding",
    description: "Old description",
    risk: "Old risk",
    remediation: "Old fix",
    autoFixable: false,
  };
  
  const sharedFinding: Finding = {
    id: "SHARED-001",
    severity: "MEDIUM" as any,
    confidence: "high",
    category: "test",
    title: "Shared Finding",
    description: "Shared description",
    risk: "Shared risk",
    remediation: "Shared fix",
    autoFixable: false,
  };
  
  const newFinding: Finding = {
    id: "NEW-001",
    severity: "CRITICAL" as any,
    confidence: "high",
    category: "test",
    title: "New Finding",
    description: "New description",
    risk: "New risk",
    remediation: "New fix",
    autoFixable: false,
  };
  
  const previousScan: HistoryEntry = {
    timestamp: "2026-02-07T10:00:00Z",
    score: 60,
    findings: [oldFinding, sharedFinding],
    duration: 100,
    checksRun: 100,
  };
  
  const currentScan: ScanResult = {
    ...mockScanResult,
    score: 70,
    findings: [sharedFinding, newFinding],
  };
  
  const comparison = compareScanResults(currentScan, previousScan);
  
  assert.equal(comparison.newIssues.length, 1);
  assert.equal(comparison.newIssues[0].id, "NEW-001");
  
  assert.equal(comparison.resolvedIssues.length, 1);
  assert.equal(comparison.resolvedIssues[0].id, "OLD-001");
  
  assert.equal(comparison.unchangedIssues.length, 1);
  assert.equal(comparison.unchangedIssues[0].id, "SHARED-001");
  
  assert.equal(comparison.scoreDelta, 10);
  
  await cleanupTestEnv();
});

test("generateTrendReport calculates trends correctly", async () => {
  await setupTestEnv();
  
  // Create history with improving scores
  await saveToHistory({ ...mockScanResult, score: 60 });
  await new Promise(resolve => setTimeout(resolve, 10));
  await saveToHistory({ ...mockScanResult, score: 70 });
  await new Promise(resolve => setTimeout(resolve, 10));
  await saveToHistory({ ...mockScanResult, score: 80 });
  
  const report = await generateTrendReport();
  
  assert.ok(report !== null);
  assert.equal(report!.scans, 3);
  assert.equal(report!.scoreMin, 60);
  assert.equal(report!.scoreMax, 80);
  assert.equal(report!.scoreAverage, 70);
  assert.equal(report!.scoreCurrent, 80);
  assert.equal(report!.trend, "improving");
  
  await cleanupTestEnv();
});

test("formatTimestamp formats dates correctly", () => {
  const timestamp = "2026-02-07T12:30:45Z";
  const formatted = formatTimestamp(timestamp);
  
  assert.ok(formatted.includes("Feb"));
  assert.ok(formatted.includes("2026"));
});

test("formatDuration formats milliseconds correctly", () => {
  assert.equal(formatDuration(500), "500ms");
  assert.equal(formatDuration(1500), "1.5s");
  assert.equal(formatDuration(65000), "1m 5s");
});

test("formatBytes formats bytes correctly", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(1572864), "1.5 MB");
});
