/**
 * Mutation tests (M1 Slice 5): deliberately defective REIMPLEMENTATIONS of
 * production algorithm fragments, each killed by the same contract oracles
 * the suite uses. NO production file is modified. Each mutant documents its
 * defect class and the oracle that must reject it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseStrict, STRICT_LIMITS } from "../src/json.ts";
import { canonicalize } from "../src/canon.ts";

// ---------------------------------------------------------------------------
// M1 — canon mutant: object keys NOT sorted (insertion order leaks).
// Oracle: key-shuffle invariance (canonical bytes depend on value only).
// ---------------------------------------------------------------------------

function canonMutantUnsorted(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) return `[${v.map(canonMutantUnsorted).join(",")}]`;
  const o = v as { [k: string]: unknown };
  // DEFECT: Object.keys insertion order preserved instead of sorted.
  return `{${Object.keys(o).map((k) => `${JSON.stringify(k)}:${canonMutantUnsorted(o[k])}`).join(",")}}`;
}

test("M1 unsorted-keys mutant is killed by key-shuffle invariance; real canon survives", () => {
  const a = { b: 1, a: 2 };
  const b = { a: 2, b: 1 };
  assert.notEqual(canonMutantUnsorted(a), canonMutantUnsorted(b), "mutant should leak order");
  const realA = canonicalize(a as never);
  const realB = canonicalize(b as never);
  assert.ok(realA.ok && realB.ok);
  if (!(realA.ok && realB.ok)) return;
  assert.equal(realA.canonicalText, realB.canonicalText, "real implementation must be order-invariant");
});

// ---------------------------------------------------------------------------
// M2 — digest mutant: no length prefixes (boundary ambiguity possible).
// Oracle: split-resistance vectors from docs/implementation-plan.md.
// ---------------------------------------------------------------------------

function digestMutantNoPrefixes(label: string, payload: Uint8Array): string {
  // DEFECT: label and payload concatenated with no length framing.
  return createHash("sha256").update(Buffer.concat([Buffer.from("AB-JCS-1", "utf8"), Buffer.from(label, "utf8"), payload])).digest("hex");
}

test("M2 unprefixed-digest mutant collides across splits; pinned layout does not", () => {
  // ("a","bcd") vs ("ab","cd"): without prefixes both flatten to AB-JCS-1|abcd.
  const m1 = digestMutantNoPrefixes("a", Buffer.from("bcd", "utf8"));
  const m2 = digestMutantNoPrefixes("ab", Buffer.from("cd", "utf8"));
  assert.equal(m1, m2, "mutant should be ambiguous");

  const r1 = domainDigestHexPinned("a", Buffer.from("bcd", "utf8"));
  const r2 = domainDigestHexPinned("ab", Buffer.from("cd", "utf8"));
  assert.notEqual(r1, r2, "pinned layout must resist boundary ambiguity");
});

function domainDigestHexPinned(label: string, payload: Uint8Array): string {
  const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };
  const lb = Buffer.from(label, "utf8");
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from("AB-JCS-1", "utf8"), u32(lb.length), lb, u32(payload.length), payload]))
    .digest("hex");
}

// ---------------------------------------------------------------------------
// M3 — parser mutant: duplicate keys accepted last-wins.
// Oracle: E_DUPLICATE_KEY contract before materialization.
// ---------------------------------------------------------------------------

function jsonParseMutantLastWins(text: string): { ok: boolean; value?: unknown; code?: string } {
  try {
    // DEFECT: plain JSON.parse silently accepts duplicates (last wins).
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, code: "E_MALFORMED" };
  }
}

test("M3 last-wins mutant accepts duplicates; strict parser rejects pre-materialization", () => {
  const text = '{"id":"x","id":"y"}';
  const mutant = jsonParseMutantLastWins(text);
  assert.deepEqual(mutant.value, { id: "y" }, "mutant silently keeps last value");
  const real = parseStrict(text);
  assert.ok(!real.ok);
  if (!real.ok && real.errors[0]) {
    assert.equal(real.errors[0].code, "E_DUPLICATE_KEY");
    assert.equal(real.errors[0].path, "$.id");
  } else if (real.ok) {
    assert.fail("strict parser accepted duplicate keys");
  }
});

// ---------------------------------------------------------------------------
// M4 — canon/parser mutant: -0 silently normalized to 0.
// Oracles: E_NEGATIVE_ZERO (parse) / C_NEGATIVE_ZERO (canon).
// ---------------------------------------------------------------------------

test("M4 negative-zero-normalizing mutant is killed by both contracts", () => {
  const mutantCanon = (n: number): string => String(Object.is(n, -0) ? 0 : n);
  assert.equal(mutantCanon(-0), "0", "mutant hides -0");

  const p = parseStrict("-0");
  assert.ok(!p.ok);
  if (!p.ok && p.errors[0]) assert.equal(p.errors[0].code, "E_NEGATIVE_ZERO");

  const c = canonicalize({ a: -0 });
  assert.ok(!c.ok);
  if (!c.ok && c.errors[0]) {
    assert.equal(c.errors[0].code, "C_NEGATIVE_ZERO");
  } else if (c.ok) {
    assert.fail("canonicalizer accepted -0");
  }

  // The real canon also rejects -0 arriving via mutation of a valid doc.
  const c2 = canonicalize({ list: [1, -0] });
  assert.ok(!c2.ok);
});

// ---------------------------------------------------------------------------
// Guard: limits constants still pinned (guards against accidental loosening)
// ---------------------------------------------------------------------------

test("STRICT_LIMITS remain at their pinned values", () => {
  assert.equal(STRICT_LIMITS.maxDepth, 64);
  assert.equal(STRICT_LIMITS.maxDocumentBytes, 1048576);
  assert.equal(STRICT_LIMITS.maxStringBytes, 65536);
  assert.equal(STRICT_LIMITS.maxContainerMembers, 10000);
});
