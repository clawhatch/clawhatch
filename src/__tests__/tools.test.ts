import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runToolChecks } from "../checks/tools.js";
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

describe("runToolChecks", () => {
  // === TOOLS-001: Excessive elevated tools ===
  describe("TOOLS-001 — Excessive elevated tools", () => {
    it("flags >5 elevated tools as MEDIUM", async () => {
      const config = makeConfig({
        tools: {
          elevated: ["read", "write", "edit", "exec", "browser", "search"],
        },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-001");
      assert.ok(f, "TOOLS-001 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag ≤5 elevated tools", async () => {
      const config = makeConfig({
        tools: { elevated: ["read", "write", "edit"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-001");
      assert.equal(f, undefined);
    });

    it("does NOT flag empty elevated array", async () => {
      const config = makeConfig({
        tools: { elevated: [] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-001");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-002: Dangerous tools elevated ===
  describe("TOOLS-002 — Dangerous tools elevated", () => {
    it("flags exec in elevated as CRITICAL", async () => {
      const config = makeConfig({
        tools: { elevated: ["exec"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.ok(f, "TOOLS-002 should be present");
      assert.equal(f.severity, Severity.Critical);
    });

    it("flags shell in elevated as CRITICAL", async () => {
      const config = makeConfig({
        tools: { elevated: ["shell"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.ok(f, "TOOLS-002 should be present for shell");
    });

    it("flags bash in elevated as CRITICAL", async () => {
      const config = makeConfig({
        tools: { elevated: ["bash"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.ok(f, "TOOLS-002 should be present for bash");
    });

    it("flags powershell in elevated as CRITICAL", async () => {
      const config = makeConfig({
        tools: { elevated: ["powershell"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.ok(f, "TOOLS-002 should be present for powershell");
    });

    it("flags run_command in elevated as CRITICAL", async () => {
      const config = makeConfig({
        tools: { elevated: ["run_command"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.ok(f, "TOOLS-002 should be present for run_command");
    });

    it("matches case-insensitively (Exec, SHELL)", async () => {
      const config = makeConfig({
        tools: { elevated: ["Exec", "SHELL"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.ok(f, "TOOLS-002 should match case-insensitively");
    });

    it("does NOT flag safe tools in elevated", async () => {
      const config = makeConfig({
        tools: { elevated: ["read", "write", "search"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-002");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-003: Access groups not enabled ===
  describe("TOOLS-003 — Tool access groups", () => {
    it("flags elevated tools without useAccessGroups as MEDIUM", async () => {
      const config = makeConfig({
        tools: { elevated: ["read"], useAccessGroups: false },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-003");
      assert.ok(f, "TOOLS-003 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag when useAccessGroups is true", async () => {
      const config = makeConfig({
        tools: { elevated: ["read"], useAccessGroups: true },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-003");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no elevated tools", async () => {
      const config = makeConfig({
        tools: { elevated: [], useAccessGroups: false },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-003");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-004: No tool allowlist ===
  describe("TOOLS-004 — No tool allowlist", () => {
    it("flags missing allowlist as MEDIUM", async () => {
      const config = makeConfig({});
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-004");
      assert.ok(f, "TOOLS-004 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("flags empty allowlist", async () => {
      const config = makeConfig({
        tools: { allowlist: [] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-004");
      assert.ok(f, "TOOLS-004 should be present for empty allowlist");
    });

    it("does NOT flag populated allowlist", async () => {
      const config = makeConfig({
        tools: { allowlist: ["read", "write", "search"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-004");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-005: Exec unrestricted ===
  describe("TOOLS-005 — Exec tool unrestricted", () => {
    it("flags exec elevated without access groups as HIGH", async () => {
      const config = makeConfig({
        tools: { elevated: ["exec"], useAccessGroups: false },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-005");
      assert.ok(f, "TOOLS-005 should be present");
      assert.equal(f.severity, Severity.High);
    });

    it("does NOT flag exec with access groups", async () => {
      const config = makeConfig({
        tools: { elevated: ["exec"], useAccessGroups: true },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-005");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-006: Browser relay ===
  describe("TOOLS-006 — Browser host control", () => {
    it("flags allowHostControl=true as MEDIUM", async () => {
      const config = makeConfig({
        sandbox: { browser: { allowHostControl: true } },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-006");
      assert.ok(f, "TOOLS-006 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag allowHostControl=false", async () => {
      const config = makeConfig({
        sandbox: { browser: { allowHostControl: false } },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-006");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-007: File write too broad ===
  describe("TOOLS-007 — Unrestricted file write", () => {
    it("flags rw workspace without allowlist as MEDIUM", async () => {
      const config = makeConfig({
        sandbox: { workspaceAccess: "rw" },
        // no tools.allowlist
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-007");
      assert.ok(f, "TOOLS-007 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag rw with allowlist", async () => {
      const config = makeConfig({
        sandbox: { workspaceAccess: "rw" },
        tools: { allowlist: ["read", "write"] },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-007");
      assert.equal(f, undefined);
    });

    it("does NOT flag ro workspace", async () => {
      const config = makeConfig({
        sandbox: { workspaceAccess: "ro" },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-007");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-017: No command audit trail ===
  describe("TOOLS-017 — No command audit trail", () => {
    it("flags missing auditLog as MEDIUM", async () => {
      const config = makeConfig({});
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-017");
      assert.ok(f, "TOOLS-017 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag when auditLog is true", async () => {
      const config = makeConfig({
        tools: { auditLog: true },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-017");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-019: Tool timeout missing ===
  describe("TOOLS-019 — No tool timeout", () => {
    it("flags missing timeout as LOW", async () => {
      const config = makeConfig({});
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-019");
      assert.ok(f, "TOOLS-019 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when timeout is set", async () => {
      const config = makeConfig({
        tools: { timeout: 30000 },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-019");
      assert.equal(f, undefined);
    });
  });

  // === TOOLS-020: No rate limiting ===
  describe("TOOLS-020 — No rate limiting", () => {
    it("flags missing rateLimit as LOW", async () => {
      const config = makeConfig({});
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-020");
      assert.ok(f, "TOOLS-020 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when rateLimit is set", async () => {
      const config = makeConfig({
        tools: { rateLimit: 60 },
      });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-020");
      assert.equal(f, undefined);
    });
  });

  // === Happy path ===
  describe("happy path — secure config", () => {
    it("returns minimal findings for fully secured config", async () => {
      const config = makeConfig({
        tools: {
          elevated: ["read"],
          useAccessGroups: true,
          allowlist: ["read", "write", "search"],
          auditLog: true,
          timeout: 30000,
          rateLimit: 60,
        },
        sandbox: {
          workspaceAccess: "ro",
          browser: { allowHostControl: false },
        },
      });
      const findings = await runToolChecks(config, makeFiles());
      const criticals = findings.filter((f) => f.severity === Severity.Critical);
      const highs = findings.filter((f) => f.severity === Severity.High);
      assert.equal(criticals.length, 0, "No CRITICAL findings for secure config");
      assert.equal(highs.length, 0, "No HIGH findings for secure config");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles completely empty config", async () => {
      const findings = await runToolChecks(makeConfig(), makeFiles());
      // Should not throw, should produce some findings
      assert.ok(findings.length > 0, "Should produce findings for empty config");
    });

    it("handles missing tools section entirely", async () => {
      const config = makeConfig({});
      const findings = await runToolChecks(config, makeFiles());
      // Should handle gracefully
      assert.ok(Array.isArray(findings));
    });

    it("handles undefined elevated array (defaults to empty)", async () => {
      const config = makeConfig({ tools: {} });
      const findings = await runToolChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "TOOLS-001");
      assert.equal(f, undefined, "Should not flag when elevated is undefined");
    });
  });
});
