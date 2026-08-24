/**
 * Tests: AB-JCS-1 domain-separated SHA-256 digests (M0 Slice 2).
 * Known-answer vectors were computed independently from the pinned layout in
 * docs/implementation-plan.md using raw node:crypto — NOT via src/digest.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { canonicalize } from "../src/canon.ts";
import { parseStrict } from "../src/json.ts";
import {
  DIGEST_DOMAIN_PREFIX,
  DIGEST_LABELS,
  canonicalPayloadDigest,
  domainDigestHex,
  verifyDigestHex,
} from "../src/digest.ts";

const utf8 = new TextEncoder();

test("known-answer vector: canonical_payload over {\"a\":1}", () => {
  const c = canonicalize({ a: 1 });
  assert.ok(c.ok);
  if (!c.ok) return;
  assert.equal(c.canonicalText, '{"a":1}');
  const d = canonicalPayloadDigest(c.canonicalText);
  assert.ok(d.ok);
  if (!d.ok) return;
  // Pinned from independent computation:
  assert.equal(d.hex, "e49056dac5f7b635a80e2590256b36cd8e1567f45615b31a758487f8e4fda05d");
});

test("known-answer vector: payload abc", () => {
  const d = domainDigestHex(DIGEST_LABELS.canonicalPayload, utf8.encode("abc"));
  assert.ok(d.ok);
  if (!d.ok) return;
  assert.equal(d.hex, "18a9ed14d6606481ae8c05fef7bfdc040bbabf339515d968fc90b11ddc587299");
});

test("tamper detection: flipping one byte changes the digest", () => {
  const p1 = utf8.encode('{"id":"scenario-benign-001","value":1}');
  const p2 = utf8.encode('{"id":"scenario-benign-001","value":2}');
  const d1 = domainDigestHex("canonical_payload", p1);
  const d2 = domainDigestHex("canonical_payload", p2);
  assert.ok(d1.ok && d2.ok);
  if (!(d1.ok && d2.ok)) return;
  assert.notEqual(d1.hex, d2.hex);
  assert.equal(verifyDigestHex(d1.hex, d2.hex), false);
  assert.equal(verifyDigestHex(d1.hex, d1.hex), true);
});

test("boundary ambiguity: label/payload splits never collide", () => {
  const a = domainDigestHex("a", utf8.encode("bcd"));
  const b = domainDigestHex("ab", utf8.encode("cd"));
  const c = domainDigestHex("abc", utf8.encode("d"));
  const plain = createHash("sha256").update(utf8.encode("abcd")).digest("hex");
  assert.ok(a.ok && b.ok && c.ok);
  if (!(a.ok && b.ok && c.ok)) return;
  // Independently computed expected values:
  assert.equal(a.hex, "abe4aa937ff24b4ba69e868cf2016cdab1193e073ec1144006e5552e4ed8f6a5");
  assert.equal(b.hex, "af94b2330c9243e405c375205de2107e4e82183aa8008da888dc92ceef6a3a72");
  assert.notEqual(a.hex, b.hex);
  assert.notEqual(a.hex, c.hex);
  assert.notEqual(b.hex, c.hex);
  // Domain separation: unhashed-domain input can never reproduce the raw hash.
  assert.notEqual(a.hex, plain);
});

test("label validation rejects invalid labels with stable codes", () => {
  const bads: ReadonlyArray<readonly [string, string]> = [
    ["", "D_INVALID_LABEL"],
    ["Uppercase", "D_INVALID_LABEL"],
    ["1leading-digit", "D_INVALID_LABEL"],
    ["has space", "D_INVALID_LABEL"],
    ["x".repeat(65), "D_LABEL_TOO_LONG"],
  ];
  for (const [label, code] of bads) {
    const r = domainDigestHex(label, utf8.encode("p"));
    assert.ok(!r.ok, `expected rejection for ${JSON.stringify(label)}`);
    if (!r.ok) assert.equal(r.errors[0]?.code, code);
  }
  const typeErr = domainDigestHex("ok_label", "not-bytes" as unknown as Uint8Array);
  assert.ok(!typeErr.ok);
  if (!typeErr.ok) assert.equal(typeErr.errors[0]?.code, "D_PAYLOAD_TYPE");
});

test("verifyDigestHex is safe against malformed expectations", () => {
  const d = domainDigestHex("canonical_payload", utf8.encode("abc"));
  assert.ok(d.ok);
  if (!d.ok) return;
  assert.equal(verifyDigestHex("", d.hex), false);
  assert.equal(verifyDigestHex("nothex", d.hex), false);
  assert.equal(verifyDigestHex(d.hex.toUpperCase(), d.hex), false); // case must match exactly
  assert.equal(verifyDigestHex(d.hex, d.hex), true);
});

test("domain prefix constant matches the pinned layout", () => {
  assert.equal(DIGEST_DOMAIN_PREFIX, "AB-JCS-1");
  assert.equal(DIGEST_LABELS.canonicalPayload, "canonical_payload");
});

// ---------------------------------------------------------------------------
// Cross-process determinism: identical hex from independent node processes.
// ---------------------------------------------------------------------------

const SAMPLE_DOC = '{"bundle_id":"bundle-ref-0001","n":[0.002,1e30,-2e24]}';

function digestHexFromFreshProcess(): string {
  const canonUrl = new URL("../src/canon.ts", import.meta.url).href;
  const digestUrl = new URL("../src/digest.ts", import.meta.url).href;
  const probe = [
    `import { canonicalize } from ${JSON.stringify(canonUrl)};`,
    `import { canonicalPayloadDigest } from ${JSON.stringify(digestUrl)};`,
    `const v = JSON.parse(${JSON.stringify(SAMPLE_DOC)});`,
    `const c = canonicalize(v);`,
    `if (!c.ok) throw new Error("canon failed");`,
    `const d = canonicalPayloadDigest(c.canonicalText);`,
    `if (!d.ok) throw new Error("digest failed");`,
    `console.log(d.hex);`,
  ].join("\n");
  const stdout = execFileSync(process.execPath, ["--input-type=module", "-e", probe], {
    encoding: "utf8",
  }).trim();
  assert.match(stdout, /^[0-9a-f]{64}$/);
  return stdout;
}

test("identical digest across two independent processes and local computation", () => {
  const h1 = digestHexFromFreshProcess();
  const h2 = digestHexFromFreshProcess();
  assert.equal(h1, h2);

  const p = parseStrict(SAMPLE_DOC);
  assert.ok(p.ok);
  if (!p.ok) return;
  const c = canonicalize(p.value);
  assert.ok(c.ok);
  if (!c.ok) return;
  const local = canonicalPayloadDigest(c.canonicalText);
  assert.ok(local.ok);
  if (!local.ok) return;
  assert.equal(local.hex, h1);
});
