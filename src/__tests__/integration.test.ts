/**
 * Integration tests for the Clawhatch scanner.
 *
 * These tests create a mock ~/.openclaw/ directory structure and run
 * the full scanner to validate the output structure.
 */

import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { mkdtemp, rm, mkdir, writeFile, chmod } from "node:fs/promises";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { scan } from "../scanner.js";
import type { ScanResult } from "../types.js";

describe("Integration: Full Scanner", () => {
  let tempDir: string;
  let openclawDir: string;
  let workspaceDir: string;

  before(async () => {
    // Create temp directory structure
    tempDir = await mkdtemp(join(tmpdir(), "clawhatch-test-"));
    openclawDir = join(tempDir, ".openclaw");
    workspaceDir = join(tempDir, "workspace");
    await mkdir(openclawDir, { recursive: true });
    await mkdir(workspaceDir, { recursive: true });
  });

  after(async () => {
    // Cleanup
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("with minimal secure config", () => {
    let result: ScanResult;

    before(async () => {
      // Create minimal secure config
      const config = {
        gateway: {
          bind: "127.0.0.1",
          port: 18791,
          auth: {
            mode: "token",
            token: "${OPENCLAW_AUTH_TOKEN}",
          },
        },
        sandbox: {
          mode: "all",
          workspaceAccess: "ro",
        },
        tools: {
          auditLog: true,
          allowlist: ["read", "write"],
        },
        retention: {
          sessionLogTTL: 30,
          encryptAtRest: true,
          logRotation: true,
        },
        monitoring: {
          enabled: true,
          health: true,
        },
      };

      await writeFile(join(openclawDir, "openclaw.json"), JSON.stringify(config, null, 2));
      await writeFile(join(openclawDir, ".env"), "OPENCLAW_AUTH_TOKEN=test123456789012345678901234567890");

      // Set permissions on Unix
      if (platform() !== "win32") {
        await chmod(openclawDir, 0o700);
        await chmod(join(openclawDir, "openclaw.json"), 0o600);
        await chmod(join(openclawDir, ".env"), 0o600);
      }

      // Run scanner
      result = await scan({
        openclawPath: openclawDir,
        workspacePath: workspaceDir,
        autoFix: false,
        deep: false,
        json: true,
        upload: false,
      });
    });

    it("returns a valid ScanResult object", () => {
      assert.ok(result);
      assert.ok(typeof result.score === "number");
      assert.ok(Array.isArray(result.findings));
      assert.ok(Array.isArray(result.suggestions));
      assert.ok(typeof result.timestamp === "string");
      assert.ok(typeof result.duration === "number");
      assert.ok(typeof result.filesScanned === "number");
      assert.ok(typeof result.checksRun === "number");
      assert.ok(typeof result.checksPassed === "number");
      assert.ok(typeof result.platform === "string");
    });

    it("has a score between 0 and 100", () => {
      assert.ok(result.score >= 0, `Score ${result.score} should be >= 0`);
      assert.ok(result.score <= 100, `Score ${result.score} should be <= 100`);
    });

    it("reports 100 checks run", () => {
      assert.strictEqual(result.checksRun, 100);
    });

    it("scans at least the config and env files", () => {
      assert.ok(result.filesScanned >= 2, `Expected at least 2 files scanned, got ${result.filesScanned}`);
    });

    it("findings have valid structure", () => {
      for (const finding of result.findings) {
        assert.ok(finding.id, "Finding must have an id");
        assert.ok(finding.severity, "Finding must have a severity");
        assert.ok(finding.confidence, "Finding must have a confidence");
        assert.ok(finding.category, "Finding must have a category");
        assert.ok(finding.title, "Finding must have a title");
        assert.ok(finding.description, "Finding must have a description");
        assert.ok(finding.risk, "Finding must have a risk");
        assert.ok(finding.remediation, "Finding must have a remediation");
        assert.ok(typeof finding.autoFixable === "boolean", "Finding must have autoFixable boolean");
      }
    });

    it("suggestions have valid structure", () => {
      for (const suggestion of result.suggestions) {
        assert.ok(suggestion.id, "Suggestion must have an id");
        assert.strictEqual(suggestion.confidence, "low", "Suggestions should have low confidence");
      }
    });
  });

  describe("with insecure config", () => {
    let result: ScanResult;

    before(async () => {
      // Create insecure config
      const config = {
        gateway: {
          bind: "0.0.0.0",
          port: 18791,
          auth: { mode: "off" },
        },
        channels: {
          discord: {
            dmPolicy: "open",
            groupPolicy: "open",
          },
        },
        sandbox: { mode: "off" },
        tools: {
          elevated: ["exec", "shell", "bash", "powershell", "run_command", "another"],
        },
      };

      await writeFile(join(openclawDir, "openclaw.json"), JSON.stringify(config, null, 2));

      result = await scan({
        openclawPath: openclawDir,
        workspacePath: workspaceDir,
        autoFix: false,
        deep: false,
        json: true,
        upload: false,
      });
    });

    it("detects critical findings for insecure config", () => {
      const critical = result.findings.filter((f) => f.severity === "CRITICAL");
      assert.ok(critical.length > 0, "Should have critical findings for insecure config");
    });

    it("detects exposed gateway (NETWORK-001)", () => {
      const network001 = result.findings.find((f) => f.id === "NETWORK-001");
      assert.ok(network001, "Should detect gateway exposed on all interfaces");
      assert.strictEqual(network001.severity, "CRITICAL");
    });

    it("detects disabled auth (NETWORK-002)", () => {
      const network002 = result.findings.find((f) => f.id === "NETWORK-002");
      assert.ok(network002, "Should detect disabled authentication");
      assert.strictEqual(network002.severity, "CRITICAL");
    });

    it("detects open DM policy (IDENTITY-001)", () => {
      const identity001 = result.findings.find((f) => f.id === "IDENTITY-001");
      assert.ok(identity001, "Should detect open DM policy");
      assert.strictEqual(identity001.severity, "CRITICAL");
    });

    it("detects disabled sandbox (SANDBOX-001)", () => {
      const sandbox001 = result.findings.find((f) => f.id === "SANDBOX-001");
      assert.ok(sandbox001, "Should detect disabled sandbox");
    });

    it("detects dangerous elevated tools (TOOLS-002)", () => {
      const tools002 = result.findings.find((f) => f.id === "TOOLS-002");
      assert.ok(tools002, "Should detect dangerous elevated tools");
      assert.strictEqual(tools002.severity, "CRITICAL");
    });

    it("caps score at 40 due to critical findings", () => {
      assert.ok(result.score <= 40, `Score should be capped at 40 with critical findings, got ${result.score}`);
    });
  });

  describe("with secrets in config", () => {
    let result: ScanResult;

    before(async () => {
      // Create config with API keys — use a proper Anthropic key pattern that matches regex
      const config = {
        gateway: {
          bind: "127.0.0.1",
          auth: { mode: "token", token: "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789" },
        },
        database: "postgres://user:password@localhost:5432/db",
      };

      await writeFile(join(openclawDir, "openclaw.json"), JSON.stringify(config, null, 2));

      result = await scan({
        openclawPath: openclawDir,
        workspacePath: workspaceDir,
        autoFix: false,
        deep: false,
        json: true,
        upload: false,
      });
    });

    it("detects API keys in config (SECRET-001)", () => {
      const secret001 = result.findings.find((f) => f.id === "SECRET-001");
      assert.ok(secret001, "Should detect API keys in config");
      assert.strictEqual(secret001.severity, "CRITICAL");
    });

    it("detects database connection strings (SECRET-015)", () => {
      const secret015 = result.findings.find((f) => f.id === "SECRET-015");
      assert.ok(secret015, "Should detect database connection strings");
    });
  });

  describe("finding deduplication", () => {
    let result: ScanResult;

    before(async () => {
      // Create config that would trigger multiple identical findings
      const config = {
        gateway: { bind: "127.0.0.1", auth: { mode: "token", token: "${TOKEN}" } },
        sandbox: { mode: "all" },
      };

      await writeFile(join(openclawDir, "openclaw.json"), JSON.stringify(config, null, 2));

      // Create multiple credential files that would trigger SECRET-005
      const credsDir = join(openclawDir, "credentials");
      await mkdir(credsDir, { recursive: true });
      await writeFile(join(credsDir, "discord.json"), '{"token": "test"}');
      await writeFile(join(credsDir, "slack.json"), '{"token": "test"}');
      await writeFile(join(credsDir, "telegram.json"), '{"token": "test"}');

      // Set loose permissions on Unix (should trigger SECRET-005 for each file)
      if (platform() !== "win32") {
        await chmod(join(credsDir, "discord.json"), 0o644);
        await chmod(join(credsDir, "slack.json"), 0o644);
        await chmod(join(credsDir, "telegram.json"), 0o644);
      }

      result = await scan({
        openclawPath: openclawDir,
        workspacePath: workspaceDir,
        autoFix: false,
        deep: false,
        json: true,
        upload: false,
      });
    });

    it("deduplicates findings with the same ID", () => {
      // Count findings by ID
      const idCounts = new Map<string, number>();
      for (const f of result.findings) {
        idCounts.set(f.id, (idCounts.get(f.id) || 0) + 1);
      }

      // Each ID should appear at most once (deduplicated)
      for (const [id, count] of idCounts) {
        assert.strictEqual(count, 1, `Finding ${id} should appear only once, but appeared ${count} times`);
      }
    });
  });
});

describe("Integration: Output formats", () => {
  let tempDir: string;
  let openclawDir: string;

  before(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawhatch-format-test-"));
    openclawDir = join(tempDir, ".openclaw");
    await mkdir(openclawDir, { recursive: true });

    const config = {
      gateway: { bind: "127.0.0.1", auth: { mode: "token", token: "${TOKEN}" } },
    };
    await writeFile(join(openclawDir, "openclaw.json"), JSON.stringify(config, null, 2));
  });

  after(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("scan result is valid JSON", async () => {
    const result = await scan({
      openclawPath: openclawDir,
      autoFix: false,
      deep: false,
      json: true,
      upload: false,
    });

    // Should be serializable to JSON without errors
    const json = JSON.stringify(result);
    const parsed = JSON.parse(json);
    assert.strictEqual(parsed.score, result.score);
  });
});
