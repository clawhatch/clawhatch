import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runSandboxChecks } from "../checks/sandbox.js";
import { Severity, type OpenClawConfig } from "../types.js";

function makeConfig(overrides: Partial<OpenClawConfig> = {}): OpenClawConfig {
  return { ...overrides };
}

describe("runSandboxChecks", () => {
  // === SANDBOX-001: Sandbox mode disabled ===
  describe("SANDBOX-001 — Sandbox disabled", () => {
    it('flags mode="off" as HIGH', async () => {
      const config = makeConfig({
        sandbox: { mode: "off" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-001");
      assert.ok(f, "SANDBOX-001 should be present");
      assert.equal(f.severity, Severity.High);
      assert.ok(f.autoFixable);
    });

    it('flags mode="disabled" as HIGH', async () => {
      const config = makeConfig({
        sandbox: { mode: "disabled" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-001");
      assert.ok(f, "SANDBOX-001 should be present for disabled");
    });

    it('does NOT flag mode="all"', async () => {
      const config = makeConfig({
        sandbox: { mode: "all" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-001");
      assert.equal(f, undefined);
    });

    it('does NOT flag mode="non-main"', async () => {
      const config = makeConfig({
        sandbox: { mode: "non-main" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-001");
      assert.equal(f, undefined);
    });

    it("does NOT flag when sandbox mode is undefined", async () => {
      const config = makeConfig({
        sandbox: {},
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-001");
      assert.equal(f, undefined);
    });
  });

  // === SANDBOX-002: Sandbox scope minimal ===
  describe("SANDBOX-002 — Minimal sandbox scope", () => {
    it('flags scope="none" as MEDIUM', async () => {
      const config = makeConfig({
        sandbox: { scope: "none" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-002");
      assert.ok(f, "SANDBOX-002 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it('flags scope="minimal" as MEDIUM', async () => {
      const config = makeConfig({
        sandbox: { scope: "minimal" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-002");
      assert.ok(f, "SANDBOX-002 should be present for minimal");
    });

    it('does NOT flag scope="full"', async () => {
      const config = makeConfig({
        sandbox: { scope: "full" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-002");
      assert.equal(f, undefined);
    });

    it("does NOT flag missing scope", async () => {
      const config = makeConfig({ sandbox: {} });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-002");
      assert.equal(f, undefined);
    });
  });

  // === SANDBOX-003: workspaceAccess rw ===
  describe("SANDBOX-003 — Read-write workspace", () => {
    it('flags workspaceAccess="rw" as MEDIUM', async () => {
      const config = makeConfig({
        sandbox: { workspaceAccess: "rw" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-003");
      assert.ok(f, "SANDBOX-003 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it('does NOT flag workspaceAccess="ro"', async () => {
      const config = makeConfig({
        sandbox: { workspaceAccess: "ro" },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-003");
      assert.equal(f, undefined);
    });
  });

  // === SANDBOX-004: Many elevated tools ===
  describe("SANDBOX-004 — Many elevated tools", () => {
    it("flags >5 elevated tools as MEDIUM", async () => {
      const config = makeConfig({
        tools: {
          elevated: ["a", "b", "c", "d", "e", "f"],
        },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-004");
      assert.ok(f, "SANDBOX-004 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag ≤5 elevated tools", async () => {
      const config = makeConfig({
        tools: { elevated: ["a", "b", "c"] },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-004");
      assert.equal(f, undefined);
    });

    it("does NOT flag undefined tools", async () => {
      const config = makeConfig({});
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-004");
      assert.equal(f, undefined);
    });
  });

  // === SANDBOX-005: Elevated tools documentation ===
  describe("SANDBOX-005 — Elevated tools documentation", () => {
    it("always present when elevated tools exist", async () => {
      const config = makeConfig({
        tools: { elevated: ["read"] },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-005");
      assert.ok(f, "SANDBOX-005 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("not present when no elevated tools", async () => {
      const config = makeConfig({
        tools: { elevated: [] },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-005");
      assert.equal(f, undefined);
    });

    it("truncates long elevated list in description", async () => {
      const config = makeConfig({
        tools: {
          elevated: ["a", "b", "c", "d", "e", "f", "g"],
        },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-005");
      assert.ok(f);
      assert.ok(f.description.includes("..."), "Should truncate long lists");
    });
  });

  // === SANDBOX-006: Docker network not "none" ===
  describe("SANDBOX-006 — Docker network access", () => {
    it('flags docker network="bridge" as HIGH', async () => {
      const config = makeConfig({
        sandbox: { docker: { network: "bridge" } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-006");
      assert.ok(f, "SANDBOX-006 should be present");
      assert.equal(f.severity, Severity.High);
    });

    it('flags docker network="host" as HIGH', async () => {
      const config = makeConfig({
        sandbox: { docker: { network: "host" } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-006");
      assert.ok(f, "SANDBOX-006 should be present for host network");
    });

    it('does NOT flag docker network="none"', async () => {
      const config = makeConfig({
        sandbox: { docker: { network: "none" } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-006");
      assert.equal(f, undefined);
    });

    it("does NOT flag when docker config is missing", async () => {
      const config = makeConfig({ sandbox: {} });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-006");
      assert.equal(f, undefined);
    });
  });

  // === SANDBOX-007: Docker socket mounted ===
  describe("SANDBOX-007 — Docker socket mounted", () => {
    it("flags socketMounted=true as CRITICAL", async () => {
      const config = makeConfig({
        sandbox: { docker: { socketMounted: true } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-007");
      assert.ok(f, "SANDBOX-007 should be present");
      assert.equal(f.severity, Severity.Critical);
      assert.ok(f.autoFixable);
    });

    it("does NOT flag socketMounted=false", async () => {
      const config = makeConfig({
        sandbox: { docker: { socketMounted: false } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-007");
      assert.equal(f, undefined);
    });
  });

  // === SANDBOX-008: Browser host control ===
  describe("SANDBOX-008 — Browser host control", () => {
    it("flags allowHostControl=true as MEDIUM", async () => {
      const config = makeConfig({
        sandbox: { browser: { allowHostControl: true } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-008");
      assert.ok(f, "SANDBOX-008 should be present");
      assert.equal(f.severity, Severity.Medium);
      assert.ok(f.autoFixable);
    });

    it("does NOT flag allowHostControl=false", async () => {
      const config = makeConfig({
        sandbox: { browser: { allowHostControl: false } },
      });
      const findings = await runSandboxChecks(config);
      const f = findings.find((f) => f.id === "SANDBOX-008");
      assert.equal(f, undefined);
    });
  });

  // === Happy path ===
  describe("happy path — fully secured sandbox", () => {
    it("returns no findings for secure sandbox config", async () => {
      const config = makeConfig({
        sandbox: {
          mode: "all",
          scope: "full",
          workspaceAccess: "ro",
          docker: { network: "none", socketMounted: false },
          browser: { allowHostControl: false },
        },
        tools: { elevated: [] },
      });
      const findings = await runSandboxChecks(config);
      assert.equal(findings.length, 0, "Secure sandbox should have no findings");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles completely empty config", async () => {
      const findings = await runSandboxChecks(makeConfig());
      assert.ok(Array.isArray(findings));
    });

    it("handles sandbox section with no sub-properties", async () => {
      const config = makeConfig({ sandbox: {} });
      const findings = await runSandboxChecks(config);
      assert.ok(Array.isArray(findings));
    });
  });
});
