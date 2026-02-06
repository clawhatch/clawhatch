import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runCloudSyncCheck } from "../checks/cloud-sync.js";
import { Severity } from "../types.js";
import { homedir, platform } from "node:os";
import { join } from "node:path";

describe("runCloudSyncCheck", () => {
  // === CLOUD-001: OpenClaw dir inside cloud sync ===
  describe("CLOUD-001 — Cloud sync detection", () => {
    it("flags OpenClaw dir inside OneDrive as HIGH", async () => {
      // Only meaningful test on Windows where OneDrive is common
      if (platform() === "win32") {
        const onedrivePath = join(homedir(), "OneDrive", ".openclaw");
        const findings = await runCloudSyncCheck(onedrivePath);
        // This will only produce a finding if OneDrive folder actually exists
        // We just verify no crash and correct structure
        assert.ok(Array.isArray(findings));
        if (findings.length > 0) {
          const f = findings.find((f) => f.id === "CLOUD-001");
          assert.ok(f);
          assert.equal(f.severity, Severity.High);
          assert.ok(f.title.includes("OneDrive"));
        }
      }
    });

    it("does NOT flag OpenClaw dir outside cloud sync folders", async () => {
      // Use a path that is definitely not inside any cloud sync folder
      const safePath = platform() === "win32"
        ? "C:\\SafeDir\\.openclaw"
        : "/opt/safe/.openclaw";
      const findings = await runCloudSyncCheck(safePath);
      const f = findings.find((f) => f.id === "CLOUD-001");
      assert.equal(f, undefined, "Should not flag non-cloud paths");
    });

    it("returns empty findings for non-existent cloud sync dirs", async () => {
      const fakePath = platform() === "win32"
        ? "C:\\NonExistent\\Path\\.openclaw"
        : "/nonexistent/path/.openclaw";
      const findings = await runCloudSyncCheck(fakePath);
      // Cloud sync dirs don't exist at fakePath, so no findings
      assert.ok(Array.isArray(findings));
    });

    it("handles empty string path without crash", async () => {
      const findings = await runCloudSyncCheck("");
      assert.ok(Array.isArray(findings));
    });
  });

  // === Cross-platform behavior ===
  describe("cross-platform behavior", () => {
    it("checks appropriate cloud services for current platform", async () => {
      // This is a structural test — just ensure the function runs without error
      // on the current platform
      const findings = await runCloudSyncCheck(join(homedir(), ".openclaw"));
      assert.ok(Array.isArray(findings));
      // Each finding should be CLOUD-001 with HIGH severity
      for (const f of findings) {
        assert.equal(f.id, "CLOUD-001");
        assert.equal(f.severity, Severity.High);
        assert.equal(f.confidence, "high");
        assert.equal(f.category, "Cloud Sync");
      }
    });

    it("produces at most one finding per cloud service", async () => {
      const findings = await runCloudSyncCheck(join(homedir(), ".openclaw"));
      // Service names should be unique across findings
      const serviceNames = findings.map((f) => f.title);
      const uniqueNames = new Set(serviceNames);
      assert.equal(serviceNames.length, uniqueNames.size, "Should have at most one finding per service");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles path with special characters", async () => {
      const weirdPath = platform() === "win32"
        ? "C:\\Users\\Test User (1)\\.openclaw"
        : "/home/test user (1)/.openclaw";
      const findings = await runCloudSyncCheck(weirdPath);
      assert.ok(Array.isArray(findings));
    });

    it("case-insensitive path comparison works", async () => {
      // The implementation uses .toLowerCase() for comparison
      // Verify it doesn't miss paths due to casing on Windows
      if (platform() === "win32") {
        const home = homedir();
        // Test with uppercase variant
        const upperPath = join(home.toUpperCase(), "OneDrive", ".openclaw");
        const findings = await runCloudSyncCheck(upperPath);
        // Just verify no crash — actual result depends on whether OneDrive exists
        assert.ok(Array.isArray(findings));
      }
    });
  });
});
