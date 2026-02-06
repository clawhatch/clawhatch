import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runOperationalChecks } from "../checks/operational.js";
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

describe("runOperationalChecks", () => {
  // === OPS-001: No structured logging ===
  describe("OPS-001 — Structured logging", () => {
    it("flags missing monitoring as LOW", async () => {
      const config = makeConfig({});
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-001");
      assert.ok(f, "OPS-001 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when monitoring enabled", async () => {
      const config = makeConfig({
        monitoring: { enabled: true },
      });
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-001");
      assert.equal(f, undefined);
    });
  });

  // === OPS-002: Verbose error output ===
  describe("OPS-002 — Verbose error output", () => {
    it("flags verbose=true as MEDIUM", async () => {
      const config = makeConfig({
        verbose: { enabled: true },
      });
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-002");
      assert.ok(f, "OPS-002 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag verbose=false", async () => {
      const config = makeConfig({
        verbose: { enabled: false },
      });
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-002");
      assert.equal(f, undefined);
    });

    it("does NOT flag missing verbose section", async () => {
      const config = makeConfig({});
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-002");
      assert.equal(f, undefined);
    });
  });

  // === OPS-003: No monitoring/alerting ===
  describe("OPS-003 — Monitoring/alerting", () => {
    it("flags missing monitoring as LOW", async () => {
      const config = makeConfig({});
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-003");
      assert.ok(f, "OPS-003 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when monitoring enabled", async () => {
      const config = makeConfig({
        monitoring: { enabled: true },
      });
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-003");
      assert.equal(f, undefined);
    });
  });

  // === OPS-005: No health check ===
  describe("OPS-005 — Health check endpoint", () => {
    it("flags missing health check as LOW", async () => {
      const config = makeConfig({});
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-005");
      assert.ok(f, "OPS-005 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag config with health keyword", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).healthCheck = { enabled: true };
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-005");
      assert.equal(f, undefined);
    });

    it("does NOT flag config with readiness keyword", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).readiness = { path: "/ready" };
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-005");
      assert.equal(f, undefined);
    });

    it("does NOT flag config with liveness keyword", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).liveness = { path: "/live" };
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-005");
      assert.equal(f, undefined);
    });
  });

  // === OPS-007: No rollback plan ===
  describe("OPS-007 — Rollback plan", () => {
    it("flags missing rollback as LOW", async () => {
      const config = makeConfig({});
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-007");
      assert.ok(f, "OPS-007 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag config with backup keyword", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).backup = { enabled: true };
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-007");
      assert.equal(f, undefined);
    });

    it("does NOT flag config with rollback keyword", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).rollback = { maxVersions: 5 };
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-007");
      assert.equal(f, undefined);
    });

    it("does NOT flag config with snapshot keyword", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).snapshot = { enabled: true };
      const findings = await runOperationalChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "OPS-007");
      assert.equal(f, undefined);
    });
  });

  // === Happy path ===
  describe("happy path — fully secured ops", () => {
    it("returns minimal findings for secure ops config", async () => {
      const config = makeConfig({
        monitoring: { enabled: true },
        verbose: { enabled: false },
      });
      (config as Record<string, unknown>).healthCheck = { path: "/health" };
      (config as Record<string, unknown>).backup = { enabled: true };
      const findings = await runOperationalChecks(config, makeFiles());
      const mediums = findings.filter((f) => f.severity === Severity.Medium);
      assert.equal(mediums.length, 0, "No MEDIUM findings for secure ops config");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles completely empty config", async () => {
      const findings = await runOperationalChecks(makeConfig(), makeFiles());
      assert.ok(Array.isArray(findings));
      assert.ok(findings.length > 0, "Should produce findings for empty config");
    });

    it("handles empty files object", async () => {
      const findings = await runOperationalChecks(makeConfig(), makeFiles());
      assert.ok(Array.isArray(findings));
    });
  });
});
