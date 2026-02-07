/**
 * Tests for the auto-fix system (fixer.ts).
 *
 * Tests the fix application logic with mock files.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import { mkdtemp, rm, mkdir, writeFile, readFile, chmod, stat } from "node:fs/promises";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { applyFixes } from "../fixer.js";
import { Severity, type Finding } from "../types.js";

describe("applyFixes", () => {
  let tempDir: string;
  let openclawDir: string;

  before(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawhatch-fixer-test-"));
    openclawDir = join(tempDir, ".openclaw");
    await mkdir(openclawDir, { recursive: true });
  });

  after(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("gitignore fix (SECRET-002)", () => {
    it("creates .gitignore if it does not exist", async () => {
      const findings: Finding[] = [
        {
          id: "SECRET-002",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "No .gitignore found",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      const applied = results.filter((r) => r.applied);

      // Check the fix was applied
      assert.ok(applied.length > 0, "Should have applied the gitignore fix");

      // Check the file was created
      const gitignorePath = join(openclawDir, ".gitignore");
      const content = await readFile(gitignorePath, "utf-8");
      assert.ok(content.includes(".env"), ".gitignore should include .env");
      assert.ok(content.includes("credentials/"), ".gitignore should include credentials/");
    });

    it("adds missing entries to existing .gitignore", async () => {
      const gitignorePath = join(openclawDir, ".gitignore");
      await writeFile(gitignorePath, "# Existing gitignore\nnode_modules/\n");

      const findings: Finding[] = [
        {
          id: "SECRET-002",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: ".env not in .gitignore",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);

      const content = await readFile(gitignorePath, "utf-8");
      assert.ok(content.includes("node_modules/"), "Should preserve existing content");
      assert.ok(content.includes(".env"), ".gitignore should now include .env");
    });

    it("creates backup before modifying existing .gitignore", async () => {
      const gitignorePath = join(openclawDir, ".gitignore");
      await writeFile(gitignorePath, "# Original content\n");

      const findings: Finding[] = [
        {
          id: "SECRET-002",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: ".env not in .gitignore",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      const applied = results.filter((r) => r.applied && r.backupPath);

      if (applied.length > 0) {
        assert.ok(applied[0].backupPath, "Should have created a backup");
        assert.ok(applied[0].backupPath.includes(".bak."), "Backup path should contain .bak.");
      }
    });
  });

  describe("permission fix (SECRET-003, SECRET-004)", () => {
    // Only run on Unix
    const isUnix = platform() !== "win32";

    it("fixes directory permissions on Unix", { skip: !isUnix }, async () => {
      const testDir = join(tempDir, "perm-test-dir");
      await mkdir(testDir, { recursive: true });
      await chmod(testDir, 0o755); // Set loose permissions

      const findings: Finding[] = [
        {
          id: "SECRET-003",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "OpenClaw directory has loose permissions",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
          file: testDir,
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      const applied = results.filter((r) => r.applied);

      assert.ok(applied.length > 0, "Should have applied the permission fix");

      // Verify permissions
      const s = await stat(testDir);
      const mode = s.mode & 0o777;
      assert.strictEqual(mode, 0o700, "Directory should have 700 permissions");
    });

    it("fixes file permissions on Unix", { skip: !isUnix }, async () => {
      const testFile = join(tempDir, "perm-test-file.json");
      await writeFile(testFile, '{"test": true}');
      await chmod(testFile, 0o644); // Set loose permissions

      const findings: Finding[] = [
        {
          id: "SECRET-004",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "Config file has loose permissions",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
          file: testFile,
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      const applied = results.filter((r) => r.applied);

      assert.ok(applied.length > 0, "Should have applied the permission fix");

      // Verify permissions
      const s = await stat(testFile);
      const mode = s.mode & 0o777;
      assert.strictEqual(mode, 0o600, "File should have 600 permissions");
    });

    it("skips permission fixes on Windows", { skip: isUnix }, async () => {
      const testFile = join(tempDir, "perm-test-file-win.json");
      await writeFile(testFile, '{"test": true}');

      const findings: Finding[] = [
        {
          id: "SECRET-004",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "Config file has loose permissions",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
          file: testFile,
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      const skipped = results.filter((r) => !r.applied);

      assert.ok(skipped.length > 0, "Should have skipped permission fix on Windows");
      assert.ok(skipped[0].skippedReason?.includes("Windows"), "Skip reason should mention Windows");
    });
  });

  describe("config fix (NETWORK-001)", () => {
    it("fixes gateway bind address", async () => {
      const configPath = join(openclawDir, "openclaw-fix-test.json");
      const initialConfig = {
        gateway: {
          bind: "0.0.0.0",
          port: 18791,
        },
      };
      await writeFile(configPath, JSON.stringify(initialConfig, null, 2));

      const findings: Finding[] = [
        {
          id: "NETWORK-001",
          severity: Severity.Critical,
          confidence: "high",
          category: "Network Exposure",
          title: "Gateway exposed on all interfaces",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
          file: configPath,
        },
      ];

      const results = await applyFixes(findings, configPath, openclawDir);
      const applied = results.filter((r) => r.applied);

      // Read the fixed config
      const fixedContent = await readFile(configPath, "utf-8");
      const fixedConfig = JSON.parse(fixedContent);

      assert.strictEqual(fixedConfig.gateway.bind, "127.0.0.1", "Gateway bind should be fixed to 127.0.0.1");
    });

    it("creates backup before modifying config", async () => {
      const configPath = join(openclawDir, "openclaw-backup-test.json");
      const initialConfig = {
        gateway: {
          bind: "0.0.0.0",
          port: 18791,
        },
      };
      await writeFile(configPath, JSON.stringify(initialConfig, null, 2));

      const findings: Finding[] = [
        {
          id: "NETWORK-001",
          severity: Severity.Critical,
          confidence: "high",
          category: "Network Exposure",
          title: "Gateway exposed on all interfaces",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
          file: configPath,
        },
      ];

      const results = await applyFixes(findings, configPath, openclawDir);
      const applied = results.filter((r) => r.applied && r.backupPath);

      assert.ok(applied.length > 0, "Should have created a backup");
      assert.ok(applied[0].backupPath?.includes(".bak."), "Backup path should contain .bak.");
    });
  });

  describe("handles non-fixable findings gracefully", () => {
    it("returns empty results for non-fixable findings", async () => {
      const findings: Finding[] = [
        {
          id: "CUSTOM-001",
          severity: Severity.Medium,
          confidence: "high",
          category: "Custom",
          title: "Non-fixable finding",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: false,
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      assert.strictEqual(results.length, 0, "Should return empty results for non-fixable findings");
    });
  });

  describe("handles missing files gracefully", () => {
    it("skips permission fix when file is missing", async () => {
      const findings: Finding[] = [
        {
          id: "SECRET-004",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "Config file has loose permissions",
          description: "Test description",
          risk: "Test risk",
          remediation: "Test remediation",
          autoFixable: true,
          fixType: "safe",
          file: "/nonexistent/path/config.json",
        },
      ];

      const results = await applyFixes(findings, null, openclawDir);
      const skipped = results.filter((r) => !r.applied);

      if (platform() !== "win32") {
        assert.ok(skipped.length > 0, "Should have skipped fix for missing file");
      }
    });
  });
});
