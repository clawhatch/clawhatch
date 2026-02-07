import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runModelChecks } from "../checks/model.js";
import { Severity, type OpenClawConfig } from "../types.js";

function makeConfig(overrides: Partial<OpenClawConfig> = {}): OpenClawConfig {
  return { ...overrides };
}

describe("runModelChecks", () => {
  // === MODEL-001: Legacy model ===
  describe("MODEL-001 — Legacy model detection", () => {
    it("flags gpt-3.5 as MEDIUM", async () => {
      const config = makeConfig({ model: { default: "gpt-3.5-turbo" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.ok(f, "MODEL-001 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("flags claude-instant as legacy", async () => {
      const config = makeConfig({ model: { default: "claude-instant-1.2" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.ok(f, "MODEL-001 should flag claude-instant");
    });

    it("flags claude-1 as legacy", async () => {
      const config = makeConfig({ model: { default: "claude-1" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.ok(f, "MODEL-001 should flag claude-1");
    });

    it("flags text-davinci as legacy", async () => {
      const config = makeConfig({ model: { default: "text-davinci-003" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.ok(f, "MODEL-001 should flag text-davinci");
    });

    it("does NOT flag claude-opus-4 as legacy", async () => {
      const config = makeConfig({ model: { default: "claude-opus-4" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.equal(f, undefined);
    });

    it("does NOT flag gpt-4 as legacy", async () => {
      const config = makeConfig({ model: { default: "gpt-4-turbo" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.equal(f, undefined);
    });

    it("does NOT flag empty model string", async () => {
      const config = makeConfig({ model: { default: "" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-002: Weak model for tool use ===
  describe("MODEL-002 — Weak model with tool access", () => {
    it("flags haiku as MEDIUM", async () => {
      const config = makeConfig({ model: { default: "claude-3-haiku" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-002");
      assert.ok(f, "MODEL-002 should flag haiku");
      assert.equal(f.severity, Severity.Medium);
    });

    it("flags gpt-4o-mini as weak", async () => {
      const config = makeConfig({ model: { default: "gpt-4o-mini" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-002");
      assert.ok(f, "MODEL-002 should flag gpt-4o-mini");
    });

    it("flags gemini-flash as weak", async () => {
      const config = makeConfig({ model: { default: "gemini-flash" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-002");
      assert.ok(f, "MODEL-002 should flag gemini-flash");
    });

    it("does NOT flag claude-opus-4 as weak", async () => {
      const config = makeConfig({ model: { default: "claude-opus-4" } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-002");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-004: Reasoning in group contexts ===
  describe("MODEL-004 — Reasoning in groups", () => {
    it("flags reasoning enabled with group channels as LOW", async () => {
      const config = makeConfig({
        reasoning: { enabled: true },
        channels: { discord: { groupPolicy: "allowlist" } },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-004");
      assert.ok(f, "MODEL-004 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when reasoning disabled", async () => {
      const config = makeConfig({
        reasoning: { enabled: false },
        channels: { discord: { groupPolicy: "allowlist" } },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-004");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no group channels", async () => {
      const config = makeConfig({
        reasoning: { enabled: true },
        channels: { whatsapp: { dmPolicy: "pairing" } },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-004");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-005: Verbose in group contexts ===
  describe("MODEL-005 — Verbose in groups", () => {
    it("flags verbose enabled with group channels as LOW", async () => {
      const config = makeConfig({
        verbose: { enabled: true },
        channels: { discord: { groupPolicy: "allowlist" } },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-005");
      assert.ok(f, "MODEL-005 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when verbose disabled", async () => {
      const config = makeConfig({
        verbose: { enabled: false },
        channels: { discord: { groupPolicy: "open" } },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-005");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-006: Weak models in fallback order ===
  describe("MODEL-006 — Weak models in fallback", () => {
    it("flags haiku in fallbackOrder as LOW", async () => {
      const config = makeConfig({
        model: {
          default: "claude-opus-4",
          fallbackOrder: ["claude-sonnet-4", "claude-3-haiku"],
        },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-006");
      assert.ok(f, "MODEL-006 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag strong models in fallback", async () => {
      const config = makeConfig({
        model: {
          default: "claude-opus-4",
          fallbackOrder: ["gpt-4-turbo", "claude-sonnet-4"],
        },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-006");
      assert.equal(f, undefined);
    });

    it("does NOT flag empty fallbackOrder", async () => {
      const config = makeConfig({
        model: { default: "claude-opus-4", fallbackOrder: [] },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-006");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-007: Multi-agent privilege separation ===
  describe("MODEL-007 — Multi-agent privilege separation", () => {
    it("flags multiple agents without privilege separation as MEDIUM", async () => {
      const config = makeConfig({
        agents: [
          { name: "main", model: "claude-opus-4" },
          { name: "sub", model: "claude-sonnet-4" },
        ],
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-007");
      assert.ok(f, "MODEL-007 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag single agent", async () => {
      const config = makeConfig({
        agents: [{ name: "main" }],
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-007");
      assert.equal(f, undefined);
    });

    it("does NOT flag agents with privilege separation", async () => {
      const config = makeConfig({
        agents: [
          { name: "main", privilege: "admin" },
          { name: "sub", privilege: "restricted" },
        ],
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-007");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-012: Temperature too high ===
  describe("MODEL-012 — High temperature", () => {
    it("flags temperature >1.0 as LOW", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).temperature = 1.5;
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-012");
      assert.ok(f, "MODEL-012 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag temperature ≤1.0", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).temperature = 0.7;
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-012");
      assert.equal(f, undefined);
    });

    it("does NOT flag temperature = 1.0 exactly", async () => {
      const config = makeConfig();
      (config as Record<string, unknown>).temperature = 1.0;
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-012");
      assert.equal(f, undefined);
    });

    it("handles NaN temperature safely (NaN guard fix)", async () => {
      // This tests the NaN guard: parseFloat("notanumber") => NaN
      // The fix ensures NaN doesn't trigger the finding
      const config = makeConfig();
      (config as Record<string, unknown>).temperature = "notanumber";
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-012");
      assert.equal(f, undefined, "NaN temperature should not trigger MODEL-012");
    });
  });

  // === MODEL-013: No output filtering ===
  describe("MODEL-013 — No output filtering", () => {
    it("flags missing output filtering as LOW when elevated tools exist", async () => {
      // MODEL-013 now only fires when elevated tools or external channels exist
      const config = makeConfig({
        tools: { elevated: ["exec"] },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-013");
      assert.ok(f, "MODEL-013 should be present with elevated tools");
      assert.equal(f.severity, Severity.Low);
    });

    it("flags missing output filtering with external channels", async () => {
      const config = makeConfig({
        channels: {
          discord: { dmPolicy: "open" },
        },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-013");
      assert.ok(f, "MODEL-013 should be present with external channels");
    });

    it("does NOT flag without elevated tools or external channels", async () => {
      // No elevated tools, no external channels - MODEL-013 should not fire
      const config = makeConfig({});
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-013");
      assert.equal(f, undefined, "MODEL-013 should not fire without risk factors");
    });

    it("does NOT flag config with filter keyword", async () => {
      const config = makeConfig({ tools: { elevated: ["exec"] } });
      (config as Record<string, unknown>).output_guard = { enabled: true };
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-013");
      assert.equal(f, undefined);
    });
  });

  // === MODEL-014: Context window abuse ===
  describe("MODEL-014 — Context window abuse", () => {
    it("flags open DM + groups as LOW", async () => {
      const config = makeConfig({
        channels: {
          discord: { dmPolicy: "open", groupPolicy: "allowlist" },
        },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-014");
      assert.ok(f, "MODEL-014 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag without open DM", async () => {
      const config = makeConfig({
        channels: {
          discord: { dmPolicy: "pairing", groupPolicy: "allowlist" },
        },
      });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-014");
      assert.equal(f, undefined);
    });
  });

  // === Happy path ===
  describe("happy path — secure config", () => {
    it("returns minimal findings for safe config", async () => {
      const config = makeConfig({
        model: { default: "claude-opus-4", fallbackOrder: [] },
        reasoning: { enabled: false },
        verbose: { enabled: false },
      });
      const findings = await runModelChecks(config, null);
      const criticals = findings.filter((f) => f.severity === Severity.Critical);
      assert.equal(criticals.length, 0, "No CRITICAL findings for secure config");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles completely empty config", async () => {
      const findings = await runModelChecks(makeConfig(), null);
      assert.ok(Array.isArray(findings));
    });

    it("handles missing model section", async () => {
      const config = makeConfig({});
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-001");
      assert.equal(f, undefined, "Empty model should not trigger legacy detection");
    });

    it("handles null soulMdPath", async () => {
      const config = makeConfig({ model: { default: "claude-opus-4" } });
      const findings = await runModelChecks(config, null);
      // MODEL-003, MODEL-008..MODEL-011 require soulMdPath — should not be present
      const soulChecks = findings.filter((f) =>
        ["MODEL-003", "MODEL-008", "MODEL-009", "MODEL-010", "MODEL-011"].includes(f.id)
      );
      assert.equal(soulChecks.length, 0, "No SOUL.md checks should trigger with null path");
    });

    it("handles undefined channels gracefully", async () => {
      const config = makeConfig({ reasoning: { enabled: true } });
      const findings = await runModelChecks(config, null);
      const f = findings.find((f) => f.id === "MODEL-004");
      assert.equal(f, undefined, "MODEL-004 should not trigger without channels");
    });
  });
});
