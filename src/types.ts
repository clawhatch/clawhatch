/**
 * Core types for Clawhatch security scanner.
 */

export enum Severity {
  Critical = "CRITICAL",
  High = "HIGH",
  Medium = "MEDIUM",
  Low = "LOW",
}

export type Confidence = "high" | "medium" | "low";

export type FixType = "safe" | "behavioral";

export interface Finding {
  id: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  title: string;
  description: string;
  risk: string;
  remediation: string;
  autoFixable: boolean;
  fixType?: FixType;
  references?: string[];
  /** File path where the issue was found */
  file?: string;
  /** Line number in the file */
  line?: number;
}

export interface ScanOptions {
  openclawPath: string;
  workspacePath?: string;
  autoFix: boolean;
  deep: boolean;
  json: boolean;
  upload: boolean;
}

export interface ScanResult {
  timestamp: string;
  openclawVersion: string | null;
  score: number;
  findings: Finding[];
  suggestions: Finding[];
  filesScanned: number;
  checksRun: number;
  checksPassed: number;
  duration: number;
  platform: NodeJS.Platform;
}

export interface FixResult {
  finding: Finding;
  applied: boolean;
  backupPath?: string;
  description: string;
  skippedReason?: string;
}

/** Parsed OpenClaw config (openclaw.json). Loosely typed since the format may vary. */
export interface OpenClawConfig {
  [key: string]: unknown;
  gateway?: {
    bind?: string;
    port?: number;
    auth?: {
      mode?: string;
      token?: string;
    };
    trustedProxies?: string[];
    allowInsecureAuth?: boolean;
    dangerouslyDisableDeviceAuth?: boolean;
  };
  channels?: Record<
    string,
    {
      dmPolicy?: string;
      allowFrom?: string[];
      groupPolicy?: string;
      groupAllowFrom?: string[];
      requireMention?: boolean;
      mentionPatterns?: string[];
      dmScope?: string;
      accounts?: Record<string, unknown>[];
    }
  >;
  sandbox?: {
    mode?: string;
    scope?: string;
    workspaceAccess?: string;
    docker?: {
      network?: string;
      socketMounted?: boolean;
    };
    browser?: {
      allowHostControl?: boolean;
    };
  };
  tools?: {
    elevated?: string[];
    useAccessGroups?: boolean;
    allowlist?: string[];
    timeout?: number;
    rateLimit?: number;
    auditLog?: boolean;
  };
  retention?: {
    sessionLogTTL?: number;
    encryptAtRest?: boolean;
    logRotation?: boolean;
  };
  monitoring?: {
    enabled?: boolean;
    provider?: string;
  };
  skills?: {
    autoUpdate?: boolean;
    verifySignatures?: boolean;
    sandboxed?: boolean;
  };
  pairing?: {
    storeTTL?: number;
  };
  model?: {
    default?: string;
    fallbackOrder?: string[];
  };
  reasoning?: {
    enabled?: boolean;
  };
  verbose?: {
    enabled?: boolean;
  };
  identityLinks?: unknown[];
  commands?: {
    useAccessGroups?: boolean;
  };
  agents?: Record<string, unknown>[];
}

/** Parsed .env file as key-value pairs */
export type EnvVars = Record<string, string>;

/** A single JSONL session entry */
export interface SessionEntry {
  role?: string;
  content?: string;
  tool?: string;
  timestamp?: string;
  [key: string]: unknown;
}

/** Clawhatch-specific config (clawhatch.json, separate from openclaw.json) */
export interface ClawhatchConfig {
  apiUrl?: string;
  notify?: {
    webhookUrl?: string;
    email?: string;
    threshold?: string;
  };
}

/** Anonymized threat report for community sharing */
export interface ThreatReport {
  version: string;
  timestamp: string;
  instanceId: string;
  platform: NodeJS.Platform;
  score: number;
  checksRun: number;
  findingCount: number;
  findings: ThreatSignature[];
}

/** Anonymized finding — no file paths or secrets, just check metadata */
export interface ThreatSignature {
  id: string;
  severity: string;
  category: string;
}

/** Community threat feed */
export interface ThreatFeed {
  lastUpdated: string;
  totalScans: number;
  totalInstances: number;
  communityScore: number;
  topThreats: ThreatFeedEntry[];
  newThreats: ThreatFeedEntry[];
  advisories: Advisory[];
}

export interface ThreatFeedEntry {
  id: string;
  severity: string;
  category: string;
  title: string;
  frequency: number;
  firstSeen: string;
  lastSeen: string;
  trending: boolean;
}

export interface Advisory {
  id: string;
  severity: string;
  title: string;
  description: string;
  affectedChecks: string[];
  publishedAt: string;
}

export interface WebhookAlert {
  checkId: string;
  severity: string;
  title: string;
  description: string;
  communityFrequency?: number;
  trending?: boolean;
}

/** Discovered files to scan */
export interface DiscoveredFiles {
  configPath: string | null;
  envPath: string | null;
  credentialFiles: string[];
  authProfileFiles: string[];
  sessionLogFiles: string[];
  workspaceMarkdownFiles: string[];
  skillFiles: string[];
  customCommandFiles: string[];
  skillPackageFiles: string[];
  privateKeyFiles: string[];
  sshKeyFiles: string[];
  openclawDir: string;
  workspaceDir: string | null;
}

/** Monitor configuration */
export interface MonitorConfig {
  enabled: boolean;
  schedule: string;
  lastRun?: string;
  licenseKey?: string;
  alertOnScoreChange?: boolean;
  scoreChangeThreshold?: number;
}

/** History entry (stored scan result) */
export interface HistoryEntry {
  timestamp: string;
  score: number;
  findings: Finding[];
  duration: number;
  checksRun: number;
}

/** Trend report */
export interface TrendReport {
  periodStart: string;
  periodEnd: string;
  scans: number;
  scoreMin: number;
  scoreMax: number;
  scoreAverage: number;
  scoreCurrent: number;
  trend: "improving" | "declining" | "stable";
  newIssues: Finding[];
  resolvedIssues: Finding[];
  persistentIssues: Finding[];
}

/** Comparison result */
export interface ComparisonResult {
  newIssues: Finding[];
  resolvedIssues: Finding[];
  unchangedIssues: Finding[];
  scoreChange: number;
  scoreDelta: number;
}
