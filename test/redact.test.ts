/**
 * Tests: deterministic redaction scanner (M0 Slice 4a).
 * Covers: per-rule detection, clean-input negative controls (including
 * legitimate 64-hex digests), offset-only findings with raw-value leak
 * prevention, deterministic records, and ruleset self-description digest
 * verified against an independently reconstructed ruleset document.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/canon.ts";
import { domainDigestHex } from "../src/digest.ts";
import {
  RULESET_ID,
  RULESET_VERSION,
  SCANNER_VERSION,
  redactionRulesetDigest,
  scanForSecrets,
} from "../src/redact.ts";

const CANARY = "AB_CANARY_0123456789abcdef0123456789abcdef";

test("each v1 rule detects its synthetic fixture", () => {
  const fixtures: ReadonlyArray<readonly [string, string]> = [
    [`token ${CANARY} end`, "canary_token"],
    ["-----BEGIN RSA PRIVATE KEY-----", "private_key_pem"],
    ["-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_pem"],
    ["key AKIAIOSFODNN7EXAMPLE here", "aws_access_key_id"],
    ["Authorization: Bearer abcdefghijklmnopqrstuvwx", "bearer_token"],
    ["password = hunter2", "secret_assignment"],
    ["API_KEY: sk-live-12345", "secret_assignment"],
    ["my_token='abc123'", "secret_assignment"],
    ['Set {"secret":"top-secret-value"} now', "secret_assignment"],
  ];
  for (const [text, rule] of fixtures) {
    const rec = scanForSecrets([text], ["fixture_text"]);
    assert.ok(!rec.clean, `expected a finding for: ${text}`);
    const ids = rec.findings.map((f) => f.rule_id);
    assert.ok(ids.includes(rule), `"${text}" expected ${rule}, got [${ids.join(",")}]`);
  }
});

test("clean input yields zero findings", () => {
  const rec = scanForSecrets(
    [
      "all quiet on the western front",
      "run id abcd1234 status ok",
      "verdict pending review",
    ],
    ["artifact_text"],
  );
  assert.ok(rec.clean);
  assert.deepEqual(rec.findings, []);
});

test("legitimate 64-hex payload digests are NOT flagged (negative control)", () => {
  const hex64 = "e49056dac5f7b635a80e2590256b36cd8e1567f45615b31a758487f8e4fda05d";
  const rec = scanForSecrets([hex64, `digest: ${hex64}`, `{"value_hex":"${hex64}"}`], ["artifact_text"]);
  assert.ok(rec.clean, JSON.stringify(rec.findings));
});

test("findings carry offsets only; raw matched values never enter the record", () => {
  const pemWithBody = "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAA";
  const rec = scanForSecrets([`x=${CANARY}`, pemWithBody], ["log_line", "artifact_text"]);
  assert.equal(rec.findings.length, 2);
  for (const f of rec.findings) {
    assert.equal(f.length, f.end - f.start);
    assert.ok(Number.isInteger(f.start) && Number.isInteger(f.scope_index));
  }
  const serialized = JSON.stringify(rec);
  assert.ok(!serialized.includes(CANARY), "canary raw value leaked into record");
  assert.ok(!serialized.includes("PRIVATE KEY"), "matched key-header text leaked into record");
  assert.ok(!serialized.includes("hunter2"));
  assert.equal(rec.scanner_version, SCANNER_VERSION);
  assert.equal(rec.ruleset_id, RULESET_ID);
  assert.equal(rec.ruleset_version, RULESET_VERSION);
  assert.equal(rec.clean, false);
});

test("record embeds declared limitations", () => {
  const rec = scanForSecrets(["clean"], ["string"]);
  assert.ok(rec.limitations.some((l) => l.includes("no entropy scoring")));
  assert.ok(rec.limitations.some((l) => l.includes("UTF-16")));
  assert.ok(rec.limitations.length >= 5);
});

test("two scans of identical inputs are byte-identical", () => {
  const inputs = ["Bearer abcdefghijklmnopqrstuvwx", `canary ${CANARY}`];
  const r1 = scanForSecrets(inputs, ["artifact_text"]);
  const r2 = scanForSecrets([...inputs], ["artifact_text"]);
  assert.equal(JSON.stringify(r1), JSON.stringify(r2));
});

test("findings sort deterministically by scope, position, then rule", () => {
  const rec = scanForSecrets([`AKIAIOSFODNN7EXAMPLE then ${CANARY}`], ["artifact_text"]);
  assert.equal(rec.findings.length, 2);
  const starts = rec.findings.map((f) => f.start);
  assert.deepEqual(starts, [...starts].sort((a, b) => a - b));
});

test("empty scan yields a valid clean record", () => {
  const rec = scanForSecrets([], []);
  assert.ok(rec.clean);
  assert.equal(rec.scanned_items, 0);
});

test("ruleset digest equals an independently reconstructed domain digest", () => {
  // Rebuilt from docs/implementation-plan.md Slice 4a — NOT imported from redact.ts.
  const doc = {
    ruleset_id: RULESET_ID,
    version: RULESET_VERSION,
    rules: [
      { id: "canary_token", description: "AegisBench synthetic canary token", source: "AB_CANARY_[0-9a-f]{32}" },
      { id: "private_key_pem", description: "PEM private key header", source: "-----BEGIN[A-Z ]*PRIVATE KEY-----" },
      { id: "aws_access_key_id", description: "AWS access key ID shape", source: "AKIA[0-9A-Z]{16}" },
      { id: "bearer_token", description: "Bearer credential prefix", source: "Bearer [A-Za-z0-9_-]{20,}" },
      {
        id: "secret_assignment",
        description: "Assignment to password/secret/api-key/token names",
        source: `(password|secret|api[_-]?key|token)["']?\\s*[:=]\\s*("[^"]*"|'[^']*'|[^"',;\\s)]+)`,
        flags: "i",
      },
    ],
  };
  const c = canonicalize(doc);
  assert.ok(c.ok);
  if (!c.ok) return;
  const d = domainDigestHex("redaction_ruleset", Buffer.from(c.canonicalText, "utf8"));
  assert.ok(d.ok);
  if (!d.ok) return;
  assert.equal(d.hex, redactionRulesetDigest());
  // Pinned known-answer (belt and braces):
  assert.equal(redactionRulesetDigest(), "d5dac76459c7c31a9db935b70e4e1f6e460a1c1330f4ca1f1241fcdb60b1a1e2");
});
