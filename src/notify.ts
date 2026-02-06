/**
 * Notification system for Clawhatch security scanner.
 * Supports Discord, Slack, and generic webhook alerts.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import type {
  ClawhatchConfig,
  ScanResult,
  ThreatFeed,
  WebhookAlert,
  Severity,
} from "./types.js";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

/**
 * Load clawhatch.json from the openclaw directory.
 */
export async function loadNotifyConfig(
  openclawDir: string,
): Promise<ClawhatchConfig | null> {
  try {
    const raw = await readFile(join(openclawDir, "clawhatch.json"), "utf-8");
    return JSON.parse(raw) as ClawhatchConfig;
  } catch {
    return null;
  }
}

/**
 * Save (merge) clawhatch.json in the openclaw directory.
 */
export async function saveNotifyConfig(
  openclawDir: string,
  config: ClawhatchConfig,
): Promise<void> {
  const filePath = join(openclawDir, "clawhatch.json");
  let existing: ClawhatchConfig = {};

  try {
    const raw = await readFile(filePath, "utf-8");
    existing = JSON.parse(raw) as ClawhatchConfig;
  } catch {
    // File doesn't exist or is invalid — start fresh
  }

  const merged: ClawhatchConfig = {
    ...existing,
    ...config,
    notify: {
      ...existing.notify,
      ...config.notify,
    },
  };

  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(merged, null, 2) + "\n", "utf-8");
}

/**
 * Build webhook alerts from scan results, filtered by severity threshold.
 */
export function buildAlerts(
  result: ScanResult,
  feed: ThreatFeed | null,
  threshold: string,
): WebhookAlert[] {
  const thresholdLevel = SEVERITY_ORDER[threshold.toUpperCase()] ?? 0;

  const filtered = result.findings.filter(
    (f) => (SEVERITY_ORDER[f.severity] ?? 3) <= thresholdLevel,
  );

  const alerts: WebhookAlert[] = filtered.map((f) => {
    const alert: WebhookAlert = {
      checkId: f.id,
      severity: f.severity,
      title: f.title,
      description: f.description,
    };

    if (feed) {
      const match =
        feed.topThreats.find((t) => t.id === f.id) ??
        feed.newThreats.find((t) => t.id === f.id);
      if (match) {
        alert.communityFrequency = match.frequency;
        alert.trending = match.trending;
      }
    }

    return alert;
  });

  alerts.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3),
  );

  return alerts;
}

function isDiscord(url: string): boolean {
  return url.includes("discord.com/api/webhooks");
}

function isSlack(url: string): boolean {
  return url.includes("hooks.slack.com");
}

function severityEmoji(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return ":rotating_light:";
    case "HIGH":
      return ":warning:";
    case "MEDIUM":
      return ":large_yellow_circle:";
    default:
      return ":white_circle:";
  }
}

function severityColor(severity: string): number {
  switch (severity) {
    case "CRITICAL":
      return 16711680; // red
    case "HIGH":
      return 16776960; // yellow
    case "MEDIUM":
      return 16744448; // orange
    default:
      return 8421504; // grey
  }
}

function worstSeverity(alerts: WebhookAlert[]): string {
  if (alerts.length === 0) return "LOW";
  return alerts[0].severity; // already sorted CRITICAL first
}

function buildDiscordPayload(
  alerts: WebhookAlert[],
  score: number,
): Record<string, unknown> {
  return {
    embeds: [
      {
        title: "Clawhatch Security Alert",
        description: `Score: ${score}/100`,
        color: severityColor(worstSeverity(alerts)),
        fields: alerts.map((a) => ({
          name: `${a.severity}: ${a.title}`,
          value: a.description,
          inline: false,
        })),
        footer: { text: "Clawhatch Community Threat Intelligence" },
      },
    ],
  };
}

function buildSlackPayload(
  alerts: WebhookAlert[],
  score: number,
): Record<string, unknown> {
  const blocks: Record<string, unknown>[] = [
    {
      type: "header",
      text: { type: "plain_text", text: "Clawhatch Security Alert" },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Score:* ${score}/100` },
    },
    ...alerts.map((a) => ({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `${severityEmoji(a.severity)} *${a.severity}: ${a.title}*\n${a.description}`,
      },
    })),
  ];

  return { blocks };
}

function buildGenericPayload(
  alerts: WebhookAlert[],
  score: number,
): Record<string, unknown> {
  return {
    alerts,
    score,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Send webhook alerts to a Discord, Slack, or generic endpoint.
 * Returns true on 2xx, false otherwise. Never throws.
 */
export async function sendWebhookAlert(
  webhookUrl: string,
  alerts: WebhookAlert[],
  score: number,
): Promise<boolean> {
  let payload: Record<string, unknown>;

  if (isDiscord(webhookUrl)) {
    payload = buildDiscordPayload(alerts, score);
  } else if (isSlack(webhookUrl)) {
    payload = buildSlackPayload(alerts, score);
  } else {
    payload = buildGenericPayload(alerts, score);
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeout);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Send a test message to verify the webhook is working.
 * Returns true on 2xx, false otherwise. Never throws.
 */
export async function sendTestAlert(webhookUrl: string): Promise<boolean> {
  const message =
    "Clawhatch alert subscription confirmed. You will receive security alerts here.";

  let payload: Record<string, unknown>;

  if (isDiscord(webhookUrl)) {
    payload = { content: message };
  } else if (isSlack(webhookUrl)) {
    payload = { text: message };
  } else {
    payload = { type: "test", message };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeout);
    return res.ok;
  } catch {
    return false;
  }
}
