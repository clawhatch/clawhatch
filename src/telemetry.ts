/**
 * Telemetry module — anonymizes scan results and uploads threat reports.
 * Only shares check IDs, severities, and categories. Never sends file paths,
 * descriptions, or remediation text.
 */

import { createHash } from "node:crypto";
import { hostname, userInfo } from "node:os";
import type { ScanResult, ThreatReport } from "./types.js";

/** Stable per-machine identifier (first 16 hex chars of SHA-256 of hostname:username). */
export function getInstanceId(): string {
  const raw = `${hostname()}:${userInfo().username}`;
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

/** Strip a ScanResult down to only safe-to-share metadata. */
export function anonymizeScanResult(result: ScanResult): ThreatReport {
  return {
    version: "0.1.0",
    timestamp: result.timestamp,
    instanceId: getInstanceId(),
    platform: result.platform,
    score: result.score,
    checksRun: result.checksRun,
    findingCount: result.findings.length,
    findings: result.findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      category: f.category,
    })),
  };
}

/** POST a ThreatReport to the community API. Never throws. */
export async function uploadThreatReport(
  report: ThreatReport,
  apiUrl: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`${apiUrl}/v1/reports`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (res.ok) {
      return { success: true };
    }
    return { success: false, error: `HTTP ${res.status}: ${res.statusText}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: message };
  }
}
