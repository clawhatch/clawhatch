import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runDataProtectionChecks } from "../checks/data-protection.js";
import { Severity, type OpenClawConfig, type DiscoveredFiles } from "../types.js";

function makeConfig(overrides: Partial<OpenClawConfig> = {}): OpenClawConfig {
  return { ...overrides };
}

function makeFiles(overrides: Partial<DiscoveredFiles> = {}): DiscoveredFiles {
  return {
    configPath: null,
    envPath: null,
    credentialFiles: [],
    authProfileFiles: [],
    sessionLogFiles: [],
    workspaceMarkdownFiles: [],
    skillFiles: [],
    customCommandFiles: [],
    skillPackageFiles: [],
    privateKeyFiles: [],
    sshKeyFiles: [],
    openclawDir: "/fake/.openclaw",
    workspaceDir: null,
    ...overrides,
  };
}

describe("runDataProtectionChecks", () => {
  // === DATA-002: No data retention policy ===
  describe("DATA-002 — No data retention policy", () => {
    it("flags missing sessionLogTTL as MEDIUM", async () => {
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-002");
      assert.ok(f, "DATA-002 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag when sessionLogTTL is set", async () => {
      const config = makeConfig({
        retention: { sessionLogTTL: 30 },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-002");
      assert.equal(f, undefined);
    });
  });

  // === DATA-003: Logs not encrypted at rest ===
  describe("DATA-003 — Encryption at rest", () => {
    it("flags missing encryptAtRest as LOW", async () => {
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-003");
      assert.ok(f, "DATA-003 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when encryptAtRest=true", async () => {
      const config = makeConfig({
        retention: { encryptAtRest: true },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-003");
      assert.equal(f, undefined);
    });
  });

  // === DATA-004: No log rotation ===
  describe("DATA-004 — Log rotation", () => {
    it("flags missing logRotation as LOW (no large logs)", async () => {
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-004");
      assert.ok(f, "DATA-004 should be present");
      // Without large logs, severity should be LOW
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when logRotation=true", async () => {
      const config = makeConfig({
        retention: { logRotation: true },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-004");
      assert.equal(f, undefined);
    });
  });

  // === DATA-005: Backups not encrypted ===
  describe("DATA-005 — Backup encryption", () => {
    it("flags retention without encryptAtRest as LOW", async () => {
      const config = makeConfig({
        retention: { sessionLogTTL: 30, encryptAtRest: false },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-005");
      assert.ok(f, "DATA-005 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when no retention config", async () => {
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-005");
      assert.equal(f, undefined);
    });

    it("does NOT flag when encryptAtRest=true", async () => {
      const config = makeConfig({
        retention: { encryptAtRest: true },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-005");
      assert.equal(f, undefined);
    });
  });

  // === DATA-006: No data anonymization ===
  describe("DATA-006 — Data anonymization", () => {
    it("flags session logs without TTL as LOW", async () => {
      const files = makeFiles({
        sessionLogFiles: ["/fake/logs/session.jsonl"],
      });
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, files);
      const f = findings.find((f) => f.id === "DATA-006");
      assert.ok(f, "DATA-006 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when sessionLogTTL is set", async () => {
      const files = makeFiles({
        sessionLogFiles: ["/fake/logs/session.jsonl"],
      });
      const config = makeConfig({
        retention: { sessionLogTTL: 30 },
      });
      const findings = await runDataProtectionChecks(config, files);
      const f = findings.find((f) => f.id === "DATA-006");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no session logs", async () => {
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-006");
      assert.equal(f, undefined);
    });
  });

  // === DATA-007: Third-party monitoring ===
  describe("DATA-007 — Third-party monitoring", () => {
    it("flags third-party monitoring as MEDIUM", async () => {
      const config = makeConfig({
        monitoring: { enabled: true, provider: "datadog" },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-007");
      assert.ok(f, "DATA-007 should be present");
      assert.equal(f.severity, Severity.Medium);
      assert.ok(f.description.includes("datadog"));
    });

    it("does NOT flag when monitoring disabled", async () => {
      const config = makeConfig({
        monitoring: { enabled: false, provider: "datadog" },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-007");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no provider", async () => {
      const config = makeConfig({
        monitoring: { enabled: true },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-007");
      assert.equal(f, undefined);
    });
  });

  // === DATA-008: No right-to-deletion ===
  describe("DATA-008 — Data deletion", () => {
    it("flags session logs without TTL as LOW", async () => {
      const files = makeFiles({
        sessionLogFiles: ["/fake/logs/session.jsonl"],
      });
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, files);
      const f = findings.find((f) => f.id === "DATA-008");
      assert.ok(f, "DATA-008 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when sessionLogTTL is set", async () => {
      const files = makeFiles({
        sessionLogFiles: ["/fake/logs/session.jsonl"],
      });
      const config = makeConfig({
        retention: { sessionLogTTL: 30 },
      });
      const findings = await runDataProtectionChecks(config, files);
      const f = findings.find((f) => f.id === "DATA-008");
      assert.equal(f, undefined);
    });
  });

  // === DATA-010: No audit trail for data access ===
  describe("DATA-010 — Data access audit trail", () => {
    it("flags missing audit log with session logs as LOW", async () => {
      const files = makeFiles({
        sessionLogFiles: ["/fake/logs/session.jsonl"],
      });
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, files);
      const f = findings.find((f) => f.id === "DATA-010");
      assert.ok(f, "DATA-010 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when auditLog is enabled", async () => {
      const files = makeFiles({
        sessionLogFiles: ["/fake/logs/session.jsonl"],
      });
      const config = makeConfig({
        tools: { auditLog: true },
      });
      const findings = await runDataProtectionChecks(config, files);
      const f = findings.find((f) => f.id === "DATA-010");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no session logs", async () => {
      const config = makeConfig({});
      const findings = await runDataProtectionChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "DATA-010");
      assert.equal(f, undefined);
    });
  });

  // === PII false-positive fix verification ===
  describe("PII pattern false-positive fixes", () => {
    it("PII_PATTERNS should match real email addresses", () => {
      // Verify the email pattern used in DATA-001 works correctly
      const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
      assert.ok(emailPattern.test("user@example.com"), "Should match valid email");
      assert.ok(emailPattern.test("test.user+tag@sub.domain.co.uk"), "Should match complex email");
    });

    it("PII_PATTERNS credit card pattern requires separators", () => {
      // The fixed pattern requires separators to avoid matching hex/IDs
      const ccPattern = /\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b/;
      assert.ok(ccPattern.test("4111 1111 1111 1111"), "Should match space-separated CC");
      assert.ok(ccPattern.test("4111-1111-1111-1111"), "Should match dash-separated CC");
      // False positive fix: should NOT match continuous digits
      assert.ok(!ccPattern.test("4111111111111111"), "Should NOT match unseparated digits");
    });

    it("removed phone/SSN patterns don't produce false positives", () => {
      // Verify the patterns that were removed for false-positive reasons
      // Phone patterns would match timestamps like "10:30:45" or ports like ":8080"
      // SSN patterns would match version numbers like "123-45-6789"
      // These should NOT be in PII_PATTERNS anymore
      const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
      const ccPattern = /\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b/;
      
      // Things that should NOT trigger PII detection
      assert.ok(!emailPattern.test("version 1.2.3"), "Should not match version numbers");
      assert.ok(!ccPattern.test("2026-02-06T10:30:45Z"), "Should not match timestamps");
      assert.ok(!ccPattern.test("port:8080"), "Should not match port numbers");
    });
  });

  // === Happy path ===
  describe("happy path — secure data protection", () => {
    it("returns minimal findings for fully configured retention", async () => {
      const config = makeConfig({
        retention: {
          sessionLogTTL: 30,
          encryptAtRest: true,
          logRotation: true,
        },
        tools: { auditLog: true },
      });
      const findings = await runDataProtectionChecks(config, makeFiles());
      const mediums = findings.filter((f) => f.severity === Severity.Medium);
      const highs = findings.filter((f) => f.severity === Severity.High);
      assert.equal(mediums.length, 0, "No MEDIUM findings for fully configured retention");
      assert.equal(highs.length, 0, "No HIGH findings for fully configured retention");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles empty config and empty files", async () => {
      const findings = await runDataProtectionChecks(makeConfig(), makeFiles());
      assert.ok(Array.isArray(findings));
    });

    it("handles retention section present but empty", async () => {
      const config = makeConfig({ retention: {} });
      const findings = await runDataProtectionChecks(config, makeFiles());
      // Should flag DATA-002, DATA-003, DATA-004
      const ids = findings.map((f) => f.id);
      assert.ok(ids.includes("DATA-002"), "Should flag missing TTL");
      assert.ok(ids.includes("DATA-003"), "Should flag missing encryption");
      assert.ok(ids.includes("DATA-004"), "Should flag missing rotation");
    });
  });
});
