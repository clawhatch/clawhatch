import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseConfig, readConfigRaw } from "../parsers/config.js";
import { parseEnv } from "../parsers/env.js";

const testDir = join(tmpdir(), `clawhatch-test-${Date.now()}`);

// Setup and teardown
await mkdir(testDir, { recursive: true });
after(async () => {
  await rm(testDir, { recursive: true, force: true });
});

describe("parseConfig", () => {
  it("parses valid JSON5 config", async () => {
    const configPath = join(testDir, "valid.json5");
    await writeFile(
      configPath,
      `{
        // JSON5 allows comments
        gateway: {
          bind: "127.0.0.1",
          port: 3000,
          auth: { mode: "token", token: "abc123" },
        },
        channels: {
          discord: { dmPolicy: "pairing" },
        },
      }`
    );
    const result = await parseConfig(configPath);
    assert.ok(result, "Should parse successfully");
    assert.equal(result.gateway?.bind, "127.0.0.1");
    assert.equal(result.gateway?.port, 3000);
    assert.equal(result.gateway?.auth?.mode, "token");
    assert.equal(result.channels?.discord?.dmPolicy, "pairing");
  });

  it("parses standard JSON config", async () => {
    const configPath = join(testDir, "valid.json");
    await writeFile(
      configPath,
      JSON.stringify({
        gateway: { bind: "0.0.0.0" },
      })
    );
    const result = await parseConfig(configPath);
    assert.ok(result);
    assert.equal(result.gateway?.bind, "0.0.0.0");
  });

  it("returns null for nonexistent file", async () => {
    const result = await parseConfig(join(testDir, "nope.json"));
    assert.equal(result, null);
  });

  it("returns null for invalid JSON", async () => {
    const configPath = join(testDir, "bad.json");
    await writeFile(configPath, "not valid json {{{");
    const result = await parseConfig(configPath);
    assert.equal(result, null);
  });
});

describe("readConfigRaw", () => {
  it("returns raw file contents as string", async () => {
    const configPath = join(testDir, "raw.json");
    const content = '{"gateway": {"bind": "127.0.0.1"}}';
    await writeFile(configPath, content);
    const result = await readConfigRaw(configPath);
    assert.equal(result, content);
  });

  it("returns null for nonexistent file", async () => {
    const result = await readConfigRaw(join(testDir, "missing.json"));
    assert.equal(result, null);
  });
});

describe("parseEnv", () => {
  it("parses valid .env content", async () => {
    const envPath = join(testDir, ".env-valid");
    await writeFile(
      envPath,
      [
        "API_KEY=sk-abc123",
        "SECRET=mysecret",
        'QUOTED="hello world"',
        "SINGLE='single quoted'",
        "",
        "# This is a comment",
        "EMPTY=",
      ].join("\n")
    );
    const result = await parseEnv(envPath);
    assert.ok(result, "Should parse successfully");
    assert.equal(result.API_KEY, "sk-abc123");
    assert.equal(result.SECRET, "mysecret");
    assert.equal(result.QUOTED, "hello world");
    assert.equal(result.SINGLE, "single quoted");
    assert.equal(result.EMPTY, "");
  });

  it("skips comments and blank lines", async () => {
    const envPath = join(testDir, ".env-comments");
    await writeFile(
      envPath,
      ["# comment", "", "  ", "# another comment", "KEY=value"].join("\n")
    );
    const result = await parseEnv(envPath);
    assert.ok(result);
    assert.equal(Object.keys(result).length, 1);
    assert.equal(result.KEY, "value");
  });

  it("handles keys with = in value", async () => {
    const envPath = join(testDir, ".env-equals");
    await writeFile(envPath, "CONNECTION=host=localhost;port=5432");
    const result = await parseEnv(envPath);
    assert.ok(result);
    assert.equal(result.CONNECTION, "host=localhost;port=5432");
  });

  it("returns null for nonexistent file", async () => {
    const result = await parseEnv(join(testDir, ".env-missing"));
    assert.equal(result, null);
  });

  it("trims whitespace around keys and values", async () => {
    const envPath = join(testDir, ".env-spaces");
    await writeFile(envPath, "  MY_KEY  =  my_value  ");
    const result = await parseEnv(envPath);
    assert.ok(result);
    assert.equal(result.MY_KEY, "my_value");
  });
});
