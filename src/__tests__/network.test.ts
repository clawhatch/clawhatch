import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runNetworkChecks } from "../checks/network.js";
import { Severity, type OpenClawConfig } from "../types.js";

function makeConfig(overrides: Partial<OpenClawConfig> = {}): OpenClawConfig {
  return { ...overrides };
}

describe("runNetworkChecks", () => {
  it("flags bind=0.0.0.0 as CRITICAL NETWORK-001", async () => {
    const config = makeConfig({
      gateway: { bind: "0.0.0.0" },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-001");
    assert.ok(f, "NETWORK-001 should be present");
    assert.equal(f.severity, Severity.Critical);
  });

  it("flags auth mode=off as CRITICAL NETWORK-002", async () => {
    const config = makeConfig({
      gateway: { auth: { mode: "off" } },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-002");
    assert.ok(f, "NETWORK-002 should be present");
    assert.equal(f.severity, Severity.Critical);
  });

  it("flags short token (<32 chars) as HIGH NETWORK-003", async () => {
    const config = makeConfig({
      gateway: { auth: { mode: "token", token: "short-token-only-20ch" } },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-003");
    assert.ok(f, "NETWORK-003 should be present");
    assert.equal(f.severity, Severity.High);
  });

  it('flags weak token "password" as CRITICAL NETWORK-004', async () => {
    const config = makeConfig({
      gateway: { auth: { mode: "token", token: "password" } },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-004");
    assert.ok(f, "NETWORK-004 should be present");
    assert.equal(f.severity, Severity.Critical);
  });

  it("does NOT flag localhost bind", async () => {
    const config = makeConfig({
      gateway: { bind: "127.0.0.1", auth: { mode: "token", token: "a".repeat(64) } },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-001");
    assert.equal(f, undefined, "NETWORK-001 should not be present for localhost");
  });

  it("does NOT flag ${VAR} token references", async () => {
    const config = makeConfig({
      gateway: { auth: { mode: "token", token: "${AUTH_TOKEN}" } },
    });
    const findings = await runNetworkChecks(config);
    const shortToken = findings.find((f) => f.id === "NETWORK-003");
    const weakToken = findings.find((f) => f.id === "NETWORK-004");
    assert.equal(shortToken, undefined, "NETWORK-003 should not flag env refs");
    assert.equal(weakToken, undefined, "NETWORK-004 should not flag env refs");
  });

  it("flags allowInsecureAuth=true as HIGH NETWORK-006", async () => {
    const config = makeConfig({
      gateway: { allowInsecureAuth: true },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-006");
    assert.ok(f, "NETWORK-006 should be present");
    assert.equal(f.severity, Severity.High);
  });

  it("flags dangerouslyDisableDeviceAuth=true as CRITICAL NETWORK-007", async () => {
    const config = makeConfig({
      gateway: { dangerouslyDisableDeviceAuth: true },
    });
    const findings = await runNetworkChecks(config);
    const f = findings.find((f) => f.id === "NETWORK-007");
    assert.ok(f, "NETWORK-007 should be present");
    assert.equal(f.severity, Severity.Critical);
  });

  it("returns no findings for a safe config", async () => {
    const config = makeConfig({
      gateway: {
        bind: "127.0.0.1",
        auth: { mode: "token", token: "a".repeat(64) },
        allowInsecureAuth: false,
        dangerouslyDisableDeviceAuth: false,
      },
    });
    const findings = await runNetworkChecks(config);
    assert.equal(findings.length, 0, "Safe config should have no findings");
  });
});
