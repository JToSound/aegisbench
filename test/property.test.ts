/**
 * Property-based tests over the deterministic core (M1 Slice 5).
 * Self-written seeded PRNG (mulberry32, FIXED seed) — fully deterministic,
 * zero external dependencies. Any failure prints the seed and iteration.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseStrict, type JsonValue } from "../src/json.ts";
import { canonicalize } from "../src/canon.ts";
import { canonicalPayloadDigest, domainDigestHex } from "../src/digest.ts";
import { validateEnvelope } from "../src/schema.ts";

const SEED = 0xae915b & 0xffffffff; // pinned in docs/implementation-plan.md (valid hex of "AEG15B"-style tag)
const N = 300;

/** mulberry32 — small deterministic PRNG. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Deterministic JSON generator: objects, arrays, strings, safe numbers.
function genValue(rng: () => number, depth: number): JsonValue {
  const roll = rng();
  if (depth <= 0 || roll < 0.25) {
    const leaf = rng();
    if (leaf < 0.2) return null;
    if (leaf < 0.4) return rng() < 0.5;
    if (leaf < 0.6) return genString(rng);
    // Numbers chosen inside the RFC 8785-friendly range.
    return genNumber(rng);
  }
  if (roll < 0.6) {
    const len = Math.floor(rng() * 5);
    const arr: JsonValue[] = [];
    for (let i = 0; i < len; i++) arr.push(genValue(rng, depth - 1));
    return arr;
  }
  const len = Math.floor(rng() * 5);
  const obj: { [k: string]: JsonValue } = {};
  for (let i = 0; i < len; i++) {
    obj[genKey(rng)] = genValue(rng, depth - 1);
  }
  return obj;
}

const KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCZ_0123456789-";
const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
function genKey(rng: () => number): string {
  const len = 1 + Math.floor(rng() * 10);
  let s = LOWERCASE[Math.floor(rng() * LOWERCASE.length)] as string;
  for (let i = 1; i < len; i++) s += KEY_ALPHABET[Math.floor(rng() * KEY_ALPHABET.length)] as string;
  return s;
}

function genString(rng: () => number): string {
  const len = Math.floor(rng() * 20);
  let s = "";
  for (let i = 0; i < len; i++) {
    // BMP-safe printable mix incl. quotes/backslashes/newlines to stress escaping.
    const pick = rng();
    if (pick < 0.05) s += '"';
    else if (pick < 0.1) s += "\\";
    else if (pick < 0.15) s += "\n";
    else if (pick < 0.2) s += "€";
    else s += String.fromCharCode(32 + Math.floor(rng() * 90));
  }
  return s;
}

function genNumber(rng: () => number): number {
  const pick = rng();
  if (pick < 0.3) return Math.floor(rng() * 10000) - 5000;
  if (pick < 0.6) return Math.round(rng() * 1e9) / 1e6;
  if (pick < 0.8) return Number(`1e${Math.floor(rng() * 30)}`);
  return rng();
}

function deepCopyShuffleKeys(v: JsonValue, rng: () => number): JsonValue {
  if (Array.isArray(v)) return v.map((x) => deepCopyShuffleKeys(x, rng));
  if (v !== null && typeof v === "object") {
    const keys = Object.keys(v);
    for (let i = keys.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [keys[i], keys[j]] = [keys[j] as string, keys[i] as string];
    }
    const out: { [k: string]: JsonValue } = {};
    for (const k of keys) out[k] = deepCopyShuffleKeys((v as { [k: string]: JsonValue })[k] as JsonValue, rng);
    return out;
  }
  return v;
}

test("P1 round-trip: parse(JSON.stringify(v)) equals v (deterministic seed)", () => {
  const rng = mulberry32(SEED);
  assert.equal(SEED > 0, true, "seed must be the pinned nonzero constant");
  for (let i = 0; i < N; i++) {
    const v = genValue(rng, 4);
    const r = parseStrict(JSON.stringify(v));
    assert.ok(r.ok, `seed=${SEED} iter=${i}: parse failed`);
    if (!r.ok) return;
    assert.deepEqual(r.value, v, `seed=${SEED} iter=${i}: round-trip diverged`);
  }
});

test("P2 key-shuffle invariance: canonical bytes ignore insertion order", () => {
  const rng = mulberry32(SEED ^ 0x1234567);
  for (let i = 0; i < N; i++) {
    const v = genValue(rng, 4);
    const c1 = canonicalize(v);
    const c2 = canonicalize(deepCopyShuffleKeys(JSON.parse(JSON.stringify(v)) as JsonValue, rng));
    assert.ok(c1.ok && c2.ok, `iter=${i}`);
    if (!(c1.ok && c2.ok)) return;
    assert.equal(c1.canonicalText, c2.canonicalText, `seed=${SEED} iter=${i}: order leaked into canonical bytes`);
  }
});

test("P3 digest stability under reordering; sensitivity to leaf mutation", () => {
  const rng = mulberry32(SEED ^ 0x7654321);
  for (let i = 0; i < N; i++) {
    const v = genValue(rng, 3);
    const d1 = canonicalPayloadDigest(canonicalize(v).ok ? (canonicalize(v) as { ok: true; canonicalText: string }).canonicalText : "");
    const shuffled = deepCopyShuffleKeys(JSON.parse(JSON.stringify(v)) as JsonValue, rng);
    const d2 = canonicalPayloadDigest(canonicalize(shuffled).ok ? (canonicalize(shuffled) as { ok: true; canonicalText: string }).canonicalText : "");
    assert.ok(d1.ok && d2.ok);
    if (!(d1.ok && d2.ok)) return;
    assert.equal(d1.hex, d2.hex, `iter=${i}: digest not stable under reordering`);

    // Mutate one random leaf/container; digest must change.
    const res = mutateValue(JSON.parse(JSON.stringify(v)) as JsonValue, rng);
    if (!res.changed) continue;
    const d3 = canonicalPayloadDigest(canonicalize(res.value).ok ? (canonicalize(res.value) as { ok: true; canonicalText: string }).canonicalText : "");
    assert.ok(d3.ok);
    if (!d3.ok) return;
    assert.notEqual(d2.hex, d3.hex, `iter=${i}: mutation undetected`);
  }
});

/** Pure: returns a structurally-different copy of v (always changed). */
function mutateValue(v: JsonValue, rng: () => number): { readonly value: JsonValue; readonly changed: boolean } {
  switch (typeof v) {
    case "string":
      return { value: `${v}#mut`, changed: true };
    case "boolean":
      return { value: !v, changed: true };
    case "number": {
      // Float-safe transforms: avoid -0, avoid no-op additions on large doubles.
      let m: number;
      if (Object.is(v, -0) || v === 0) m = 7;
      else if (Math.abs(v) < 1e15) m = v * 2;
      else m = Math.round(v / 2);
      return { value: m, changed: m !== v || Object.is(m, -0) !== Object.is(v, -0) };
    }
    case "object": {
      if (v === null) return { value: "was-null", changed: true };
      if (Array.isArray(v)) {
        if (v.length === 0) return { value: ["mutated"], changed: true };
        const idx = Math.floor(rng() * v.length);
        const inner = mutateValue(v[idx] as JsonValue, rng);
        const copy = v.slice();
        copy[idx] = inner.value;
        return { value: copy, changed: inner.changed };
      }
      const keys = Object.keys(v);
      if (keys.length === 0) return { value: { mutated_key: true }, changed: true };
      const k = keys[Math.floor(rng() * keys.length)] as string;
      const inner = mutateValue((v as { [k: string]: JsonValue })[k] as JsonValue, rng);
      return { value: { ...(v as { [k: string]: JsonValue }), [k]: inner.value }, changed: inner.changed };
    }
    default:
      return { value: v, changed: false };
  }
}

test("P4 generated valid envelopes always pass validation", () => {
  const rng = mulberry32(SEED ^ 0x2468ace);
  for (let i = 0; i < N; i++) {
    const nScenarios = 1 + Math.floor(rng() * 3);
    const scenarios = Array.from({ length: nScenarios }, (_, s) => ({
      id: `scenario-gen-${i}-${s}`,
      title: genString(rng) || "synthetic",
      requirement_ids: [`req-gen-${Math.floor(rng() * 5)}`],
    }));
    const doc = {
      $schema: "ab.evidence-envelope/1",
      bundle_id: `bundle-gen-${i}`,
      created_utc: "2026-08-24T08:00:00Z",
      scenarios,
    };
    const r = validateEnvelope(doc as JsonValue);
    assert.deepEqual(r, { ok: true }, `seed=${SEED} iter=${i}`);
  }
});
