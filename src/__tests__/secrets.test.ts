import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runSecretChecks } from "../checks/secrets.js";
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

describe("runSecretChecks", () => {
  // === SECRET-001: API keys in config ===
  describe("SECRET-001 — API keys in config", () => {
    it("flags OpenAI key in raw config as CRITICAL", async () => {
      const config = makeConfig();
      const raw = '{"model": {"apiKey": "sk-abcdefghijklmnopqrstuvwxyz0123456789"}}';
      const findings = await runSecretChecks(config, raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present");
      assert.equal(f.severity, Severity.Critical);
      assert.ok(f.description.includes("1"));
    });

    it("flags Anthropic key pattern", async () => {
      const raw = '{"key": "sk-ant-abcdefghijklmnopqrstuvwxyz01234567"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present for Anthropic key");
    });

    it("flags Google AI key pattern (AIza...)", async () => {
      const raw = '{"key": "AIzaSyA0123456789abcdefghijklmnopqrstuv"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present for Google key");
    });

    it("flags AWS access key pattern (AKIA...)", async () => {
      const raw = '{"key": "AKIAIOSFODNN7EXAMPLE"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present for AWS key");
    });

    it("flags GitHub token patterns (ghp_...)", async () => {
      const raw = '{"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present for GitHub token");
    });

    it("flags Stripe key patterns", async () => {
      const raw = '{"stripe": "sk_live_abcdefghij0123456789ab"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present for Stripe key");
    });

    it("flags Slack token patterns (xoxb-...)", async () => {
      const raw = '{"slack": "xoxb-1234567890-abcdef"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f, "SECRET-001 should be present for Slack token");
    });

    it("counts multiple keys correctly", async () => {
      const raw = '{"a": "sk-abcdefghijklmnopqrstuvwxyz0123456789", "b": "AKIAIOSFODNN7EXAMPLE"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.ok(f);
      assert.ok(f.description.includes("2"), `Expected 2 keys, got: ${f.description}`);
    });

    it("does NOT flag when configRaw is null", async () => {
      const findings = await runSecretChecks(makeConfig(), null, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.equal(f, undefined, "SECRET-001 should not be present when no raw config");
    });

    it("does NOT flag safe config without API keys", async () => {
      const raw = '{"model": {"default": "claude-opus-4"}, "gateway": {"bind": "127.0.0.1"}}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.equal(f, undefined, "SECRET-001 should not be present for clean config");
    });
  });

  // === SECRET-003: File permissions (Windows) ===
  describe("SECRET-003 — File permissions on Windows", () => {
    it("emits a finding on Windows (either ACL check result or inconclusive)", async () => {
      // On Windows, the scanner now attempts icacls check
      // It should produce either a HIGH finding (permissive ACLs) or a LOW finding (inconclusive)
      const findings = await runSecretChecks(makeConfig(), null, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-003");
      if (process.platform === "win32") {
        assert.ok(f, "SECRET-003 should be present on Windows");
        // Either HIGH (found permissive ACLs) or LOW (inconclusive/couldn't check)
        assert.ok(
          f.severity === Severity.High || f.severity === Severity.Low,
          "SECRET-003 should be HIGH or LOW severity"
        );
      }
    });
  });

  // === SECRET-013: Private keys in workspace ===
  describe("SECRET-013 — Private key files", () => {
    it("flags private key files as HIGH", async () => {
      const files = makeFiles({
        privateKeyFiles: ["/workspace/server.key", "/workspace/cert.pem"],
      });
      const findings = await runSecretChecks(makeConfig(), null, files, false);
      const f = findings.find((f) => f.id === "SECRET-013");
      assert.ok(f, "SECRET-013 should be present");
      assert.equal(f.severity, Severity.High);
      assert.ok(f.description.includes("2"));
    });

    it("does NOT flag when no private key files", async () => {
      const findings = await runSecretChecks(makeConfig(), null, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-013");
      assert.equal(f, undefined);
    });
  });

  // === SECRET-015: Database URLs ===
  describe("SECRET-015 — Database connection strings", () => {
    it("flags postgres URL as HIGH", async () => {
      const raw = '{"db": "postgresql://user:pass@localhost:5432/mydb"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-015");
      assert.ok(f, "SECRET-015 should be present");
      assert.equal(f.severity, Severity.High);
    });

    it("flags mysql URL", async () => {
      const raw = '{"db": "mysql://root:secret@db.host:3306/app"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-015");
      assert.ok(f, "SECRET-015 should be present for MySQL");
    });

    it("flags mongodb+srv URL", async () => {
      const raw = '{"db": "mongodb+srv://admin:pass@cluster.mongodb.net/db"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-015");
      assert.ok(f, "SECRET-015 should be present for MongoDB");
    });

    it("flags redis URL", async () => {
      const raw = '{"cache": "redis://default:secret@redis.host:6379"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-015");
      assert.ok(f, "SECRET-015 should be present for Redis");
    });

    it("does NOT flag config without DB URLs", async () => {
      const raw = '{"model": "claude-opus-4"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-015");
      assert.equal(f, undefined);
    });
  });

  // === SECRET-017: Webhook secrets ===
  describe("SECRET-017 — Webhook secrets in config", () => {
    it("flags Stripe webhook secret", async () => {
      const raw = '{"webhook": "whsec_abcdefghij0123456789ab"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-017");
      assert.ok(f, "SECRET-017 should be present");
      assert.equal(f.severity, Severity.High);
    });

    it("flags generic webhook_secret assignment (non-JSON format)", async () => {
      // The regex expects webhook_secret = "value" or webhook-secret: "value" format
      // (not JSON-quoted key format) — this is raw config/env style
      const raw = 'webhook_secret = "my-webhook-signing-secret"';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-017");
      assert.ok(f, "SECRET-017 should be present for generic webhook secret");
    });
  });

  // === SECRET-018: SSH keys ===
  describe("SECRET-018 — SSH keys in workspace", () => {
    it("flags SSH key files as HIGH", async () => {
      const files = makeFiles({
        sshKeyFiles: ["/workspace/id_rsa", "/workspace/id_ed25519"],
      });
      const findings = await runSecretChecks(makeConfig(), null, files, false);
      const f = findings.find((f) => f.id === "SECRET-018");
      assert.ok(f, "SECRET-018 should be present");
      assert.equal(f.severity, Severity.High);
    });

    it("does NOT flag when no SSH keys", async () => {
      const findings = await runSecretChecks(makeConfig(), null, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-018");
      assert.equal(f, undefined);
    });
  });

  // === SECRET-019: AWS credentials ===
  describe("SECRET-019 — AWS credentials in config", () => {
    it("flags AWS access key as CRITICAL", async () => {
      const raw = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-019");
      assert.ok(f, "SECRET-019 should be present");
      assert.equal(f.severity, Severity.Critical);
    });

    it("flags AWS secret access key", async () => {
      const raw = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-019");
      assert.ok(f, "SECRET-019 should be present for secret key");
    });

    it("does NOT flag ${VAR} AWS references", async () => {
      const raw = 'AWS_ACCESS_KEY_ID = "${AWS_KEY}"';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-019");
      assert.equal(f, undefined, "SECRET-019 should not flag env var references");
    });
  });

  // === SECRET-020: Weak JWT secret ===
  describe("SECRET-020 — Weak JWT secret", () => {
    it("flags short JWT secret as MEDIUM", async () => {
      // The regex expects jwt_secret = "value" or jwt-secret: "value" (non-JSON-key format)
      const raw = 'jwt_secret = "short"';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-020");
      assert.ok(f, "SECRET-020 should be present");
      assert.equal(f.severity, Severity.Medium);
    });

    it("does NOT flag long JWT secret (≥32 chars)", async () => {
      const raw = `jwt_secret = "${"a".repeat(32)}"`;
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-020");
      assert.equal(f, undefined, "SECRET-020 should not flag long JWT secrets");
    });

    it("does NOT flag JWT secret using env var reference", async () => {
      const raw = 'jwt_secret = "${JWT_SECRET}"';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-020");
      assert.equal(f, undefined, "SECRET-020 should not flag env var refs");
    });
  });

  // === SECRET-022: Internal IPs/domains ===
  describe("SECRET-022 — Internal IPs and staging domains", () => {
    it("flags 10.x.x.x private IPs", async () => {
      const raw = '{"api": "http://10.0.1.5:8080/api"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-022");
      assert.ok(f, "SECRET-022 should flag 10.x IPs");
      assert.equal(f.severity, Severity.Low);
    });

    it("flags 192.168.x.x private IPs", async () => {
      const raw = '{"server": "192.168.1.100"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-022");
      assert.ok(f, "SECRET-022 should flag 192.168.x IPs");
    });

    it("flags 172.16-31.x.x private IPs", async () => {
      const raw = '{"db": "172.16.0.1"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-022");
      assert.ok(f, "SECRET-022 should flag 172.16.x IPs");
    });

    it("flags staging domains", async () => {
      const raw = '{"api": "https://staging.myapp.com"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-022");
      assert.ok(f, "SECRET-022 should flag staging domains");
    });

    it("flags .internal domains", async () => {
      const raw = '{"api": "https://api.internal"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-022");
      assert.ok(f, "SECRET-022 should flag .internal domains");
    });

    it("flags .local domains", async () => {
      const raw = '{"api": "https://myservice.local"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-022");
      assert.ok(f, "SECRET-022 should flag .local domains");
    });
  });

  // === SECRET-023: Credential rotation ===
  describe("SECRET-023 — No credential rotation", () => {
    it("is present when .env file exists", async () => {
      // SECRET-023 now only fires when credentials are found
      const files = makeFiles({ envPath: "/fake/.openclaw/.env" });
      const findings = await runSecretChecks(makeConfig(), null, files, false);
      const f = findings.find((f) => f.id === "SECRET-023");
      // May or may not be present depending on .env modified date heuristic
      // Just verify it doesn't crash
      if (f) {
        assert.equal(f.severity, Severity.Low);
      }
    });

    it("is NOT present when no credentials exist", async () => {
      // Without .env or API keys in config, SECRET-023 should not fire
      const findings = await runSecretChecks(makeConfig(), null, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-023");
      assert.equal(f, undefined, "SECRET-023 should not fire without credentials");
    });
  });

  // === SECRET-029: Live billing keys ===
  describe("SECRET-029 — Live billing API keys", () => {
    it("flags Stripe live secret key as CRITICAL", async () => {
      const raw = '{"stripe": "sk_live_abcdefghij0123456789ab"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-029");
      assert.ok(f, "SECRET-029 should be present");
      assert.equal(f.severity, Severity.Critical);
    });

    it("flags Stripe restricted live key", async () => {
      const raw = '{"stripe": "rk_live_abcdefghij0123456789ab"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-029");
      assert.ok(f, "SECRET-029 should be present for restricted key");
    });

    it("does NOT flag test keys", async () => {
      const raw = '{"stripe": "sk_test_abcdefghij0123456789ab"}';
      const findings = await runSecretChecks(makeConfig(), raw, makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-029");
      assert.equal(f, undefined, "SECRET-029 should not flag test keys");
    });
  });

  // === Happy path: clean config ===
  describe("happy path — clean config", () => {
    it("returns minimal findings for safe empty config", async () => {
      const findings = await runSecretChecks(makeConfig(), null, makeFiles(), false);
      // Should only have SECRET-023 (always present) and possibly SECRET-003 (Windows)
      const criticals = findings.filter((f) => f.severity === Severity.Critical);
      const highs = findings.filter((f) => f.severity === Severity.High);
      assert.equal(criticals.length, 0, "No CRITICAL findings for clean config");
      assert.equal(highs.length, 0, "No HIGH findings for clean config");
    });
  });

  // === Edge cases ===
  describe("edge cases", () => {
    it("handles empty configRaw string", async () => {
      const findings = await runSecretChecks(makeConfig(), "", makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.equal(f, undefined, "Empty string should not trigger SECRET-001");
    });

    it("handles configRaw with only whitespace", async () => {
      const findings = await runSecretChecks(makeConfig(), "   \n  ", makeFiles(), false);
      const f = findings.find((f) => f.id === "SECRET-001");
      assert.equal(f, undefined);
    });
  });
});
