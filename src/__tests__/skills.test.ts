import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runSkillChecks } from "../checks/skills.js";
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

describe("runSkillChecks", () => {
  // === SKILLS-005: No skill sandboxing ===
  describe("SKILLS-005 — Skills not sandboxed", () => {
    it("flags skills without sandboxing as MEDIUM", async () => {
      const files = makeFiles({ skillFiles: ["/fake/skills/tool.js"] });
      const config = makeConfig({ skills: { sandboxed: false } });
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-005");
      assert.ok(f, "SKILLS-005 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag when sandboxed=true", async () => {
      const files = makeFiles({ skillFiles: ["/fake/skills/tool.js"] });
      const config = makeConfig({ skills: { sandboxed: true } });
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-005");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no skill files", async () => {
      const config = makeConfig({ skills: { sandboxed: false } });
      const findings = await runSkillChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "SKILLS-005");
      assert.equal(f, undefined);
    });
  });

  // === SKILLS-010: No signature verification ===
  describe("SKILLS-010 — No skill signature verification", () => {
    it("flags missing signature verification as LOW", async () => {
      const files = makeFiles({ skillFiles: ["/fake/skills/tool.js"] });
      const config = makeConfig({ skills: { verifySignatures: false } });
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-010");
      assert.ok(f, "SKILLS-010 should be present");
      assert.equal(f.severity, Severity.Low);
    });

    it("does NOT flag when verifySignatures=true", async () => {
      const files = makeFiles({ skillFiles: ["/fake/skills/tool.js"] });
      const config = makeConfig({ skills: { verifySignatures: true } });
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-010");
      assert.equal(f, undefined);
    });
  });

  // === SKILLS-011: Auto-update enabled ===
  describe("SKILLS-011 — Skills auto-update", () => {
    it("flags autoUpdate=true as MEDIUM", async () => {
      const config = makeConfig({ skills: { autoUpdate: true } });
      const findings = await runSkillChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "SKILLS-011");
      assert.ok(f, "SKILLS-011 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag autoUpdate=false", async () => {
      const config = makeConfig({ skills: { autoUpdate: false } });
      const findings = await runSkillChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "SKILLS-011");
      assert.equal(f, undefined);
    });

    it("does NOT flag when autoUpdate is undefined", async () => {
      const config = makeConfig({ skills: {} });
      const findings = await runSkillChecks(config, makeFiles());
      const f = findings.find((f) => f.id === "SKILLS-011");
      assert.equal(f, undefined);
    });
  });

  // === SKILLS-012: Workspace skill override ===
  describe("SKILLS-012 — Workspace skill override", () => {
    it("flags workspace + managed skill overlap as MEDIUM", async () => {
      const files = makeFiles({
        skillFiles: [
          "/fake/.openclaw/skills/managed.js",
          "/fake/workspace/skills/custom.js",
        ],
        openclawDir: "/fake/.openclaw",
        workspaceDir: "/fake/workspace",
      });
      const config = makeConfig({});
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-012");
      assert.ok(f, "SKILLS-012 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag when only managed skills", async () => {
      const files = makeFiles({
        skillFiles: ["/fake/.openclaw/skills/managed.js"],
        openclawDir: "/fake/.openclaw",
        workspaceDir: "/fake/workspace",
      });
      const config = makeConfig({});
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-012");
      assert.equal(f, undefined);
    });

    it("does NOT flag when no workspace dir", async () => {
      const files = makeFiles({
        skillFiles: ["/fake/.openclaw/skills/managed.js"],
        openclawDir: "/fake/.openclaw",
        workspaceDir: null,
      });
      const config = makeConfig({});
      const findings = await runSkillChecks(config, files);
      const f = findings.find((f) => f.id === "SKILLS-012");
      assert.equal(f, undefined);
    });
  });

  // === Happy path ===
  describe("happy path — secured skills config", () => {
    it("returns no findings for safe config with no skills", async () => {
      const config = makeConfig({
        skills: {
          autoUpdate: false,
          verifySignatures: true,
          sandboxed: true,
        },
      });
      const findings = await runSkillChecks(config, makeFiles());
      assert.equal(findings.length, 0, "No findings for secure config without skills");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles empty config and empty files", async () => {
      const findings = await runSkillChecks(makeConfig(), makeFiles());
      assert.ok(Array.isArray(findings));
    });

    it("handles missing skills config section", async () => {
      const files = makeFiles({ skillFiles: ["/fake/skills/tool.js"] });
      const findings = await runSkillChecks(makeConfig(), files);
      // Should flag SKILLS-005 (not sandboxed) and SKILLS-010 (no signatures)
      const f5 = findings.find((f) => f.id === "SKILLS-005");
      const f10 = findings.find((f) => f.id === "SKILLS-010");
      assert.ok(f5, "SKILLS-005 should flag when skills section missing");
      assert.ok(f10, "SKILLS-010 should flag when skills section missing");
    });
  });
});
