import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runIdentityChecks } from "../checks/identity.js";
import { Severity, type OpenClawConfig } from "../types.js";

const emptyFiles = { credentialFiles: [], authProfileFiles: [] };

function makeConfig(overrides: Partial<OpenClawConfig> = {}): OpenClawConfig {
  return { ...overrides };
}

describe("runIdentityChecks", () => {
  it('flags dmPolicy="open" as CRITICAL IDENTITY-001', async () => {
    const config = makeConfig({
      channels: {
        discord: { dmPolicy: "open" },
      },
    });
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-001");
    assert.ok(f, "IDENTITY-001 should be present");
    assert.equal(f.severity, Severity.Critical);
    assert.ok(f.title.includes("discord"));
  });

  it("flags wildcard in allowFrom as HIGH IDENTITY-002", async () => {
    const config = makeConfig({
      channels: {
        slack: { allowFrom: ["user1", "*"] },
      },
    });
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-002");
    assert.ok(f, "IDENTITY-002 should be present");
    assert.equal(f.severity, Severity.High);
    assert.ok(f.title.includes("slack"));
  });

  it('does NOT flag dmPolicy="pairing"', async () => {
    const config = makeConfig({
      channels: {
        telegram: { dmPolicy: "pairing" },
      },
    });
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-001");
    assert.equal(f, undefined, "IDENTITY-001 should not flag pairing policy");
  });

  it('flags groupPolicy="open" as HIGH IDENTITY-003', async () => {
    const config = makeConfig({
      channels: {
        whatsapp: { groupPolicy: "open" },
      },
    });
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-003");
    assert.ok(f, "IDENTITY-003 should be present");
    assert.equal(f.severity, Severity.High);
    assert.ok(f.title.includes("whatsapp"));
  });

  it("flags wildcard in groupAllowFrom as HIGH IDENTITY-010", async () => {
    const config = makeConfig({
      channels: {
        discord: { groupAllowFrom: ["group1", "*"] },
      },
    });
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-010");
    assert.ok(f, "IDENTITY-010 should be present");
    assert.equal(f.severity, Severity.High);
  });

  it("flags requireMention=false as MEDIUM IDENTITY-005", async () => {
    const config = makeConfig({
      channels: {
        slack: { groupPolicy: "allowlist", requireMention: false },
      },
    });
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-005");
    assert.ok(f, "IDENTITY-005 should be present");
    assert.equal(f.severity, Severity.Medium);
  });

  it("returns no channel findings for empty config", async () => {
    const config = makeConfig({});
    const findings = await runIdentityChecks(config, emptyFiles);
    // Should only have IDENTITY-013 (always present)
    const channelFindings = findings.filter(
      (f) => f.id !== "IDENTITY-013"
    );
    assert.equal(channelFindings.length, 0);
  });

  it("always includes IDENTITY-013 (no rotation evidence)", async () => {
    const config = makeConfig({});
    const findings = await runIdentityChecks(config, emptyFiles);
    const f = findings.find((f) => f.id === "IDENTITY-013");
    assert.ok(f, "IDENTITY-013 should always be present");
    assert.equal(f.severity, Severity.Low);
  });
});
