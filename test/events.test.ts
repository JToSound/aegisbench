/**
 * Tests: event envelope `ab.event/1` + trace invariants (M0 Slice 3).
 * Covers: valid event/chain, tampered payload, forged digest, missing
 * mandatory fields, unknown schema version, invalid IDs, extra fields,
 * orphan uncertainty, timestamp shape, duplicate/unresolved/self/cyclic
 * predecessors, sequence monotonicity.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { JsonValue } from "../src/json.ts";
import { SUPPORTED_EVENT_SCHEMA, buildPayloadDigest, validateEvent, validateEventTrace } from "../src/events.ts";

type MutableRecord = Record<string, unknown>;

function validDigestObject(payload: JsonValue): MutableRecord {
  const r = buildPayloadDigest(payload);
  assert.ok(r.ok, "fixture digest construction failed");
  if (!r.ok) throw new Error("unreachable");
  return { algorithm: r.digest.algorithm, label: r.digest.label, value_hex: r.digest.value_hex };
}

/** A fully valid event; overrides deep-applied at top level. */
function makeEvent(overrides: Readonly<Record<string, unknown>> = {}): JsonValue {
  const payload = (overrides["payload"] as JsonValue | undefined) ?? { kind: "observation", v: 1 };
  const base: MutableRecord = {
    $schema: SUPPORTED_EVENT_SCHEMA,
    event_id: "event-0001",
    correlation_nonce: "nonce-run-0001",
    producer_id: "producer-harness",
    event_source: "src-harness-obs",
    loss_semantics: "lossless",
    payload,
    payload_digest: validDigestObject(payload),
  };
  return { ...base, ...overrides } as JsonValue;
}

function codesOf(result: ReturnType<typeof validateEvent>): string[] {
  return result.ok ? [] : result.issues.map((i) => i.code);
}

function issuePaths(result: ReturnType<typeof validateEvent>): string[] {
  return result.ok ? [] : result.issues.map((i) => i.path);
}

// ---------------------------------------------------------------------------
// Valid cases
// ---------------------------------------------------------------------------

test("valid minimal event passes schema + integrity binding", () => {
  assert.deepEqual(validateEvent(makeEvent()), { ok: true });
});

test("valid event with all optional fields passes", () => {
  const e = makeEvent({
    sequence: 7,
    timestamp_utc: "2026-08-24T07:15:00.123Z",
    timestamp_uncertainty_ms: 5,
    causal_predecessors: [],
  });
  assert.deepEqual(validateEvent(e), { ok: true });
});

test("valid multi-event chain passes trace validation", () => {
  const e1 = makeEvent({ event_id: "ev-a", producer_id: "prod-x", sequence: 1 });
  const e2 = makeEvent({
    event_id: "ev-b",
    producer_id: "prod-x",
    sequence: 2,
    causal_predecessors: ["ev-a"],
    payload: { kind: "effect", ok: true },
  });
  assert.deepEqual(validateEventTrace([e1, e2]), { ok: true });
});

test("buildPayloadDigest output matches independently constructed layout", () => {
  const canonicalText = '{"a":[true,null],"z":1}';
  const r = buildPayloadDigest({ z: 1, a: [true, null] });
  assert.ok(r.ok);
  if (!r.ok) return;
  // Independently reconstruct the pinned byte layout from
  // docs/implementation-plan.md (Slice 2), NOT via src/digest.ts:
  const label = "canonical_payload";
  const lb = Buffer.from(label, "utf8");
  const pb = Buffer.from(canonicalText, "utf8");
  const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };
  const independent = createHash("sha256")
    .update(Buffer.concat([Buffer.from("AB-JCS-1", "utf8"), u32(lb.length), lb, u32(pb.length), pb]))
    .digest("hex");
  assert.equal(r.digest.value_hex, independent);
  // Negative control: the domain-separated digest must NOT equal the raw
  // hash of the same bytes.
  const rawSha = createHash("sha256").update(pb).digest("hex");
  assert.notEqual(r.digest.value_hex, rawSha);
});

// ---------------------------------------------------------------------------
// Integrity binding (consumes Slices 1–2 end-to-end)
// ---------------------------------------------------------------------------

test("tampered inline payload yields V_DIGEST_MISMATCH", () => {
  const original = makeEvent();
  const tampered = JSON.parse(JSON.stringify(original)) as MutableRecord;
  (tampered["payload"] as MutableRecord)["v"] = 999; // mutate after digest was bound
  const r = validateEvent(tampered as JsonValue);
  assert.ok(!r.ok);
  assert.ok(codesOf(r).includes("V_DIGEST_MISMATCH"));
  assert.ok(issuePaths(r).includes("$.payload_digest.value_hex"));
});

test("forged digest value yields V_DIGEST_MISMATCH", () => {
  const e = makeEvent({
    payload_digest: { algorithm: "sha256", label: "canonical_payload", value_hex: "a".repeat(64) },
  });
  const r = validateEvent(e);
  assert.ok(!r.ok);
  assert.ok(codesOf(r).includes("V_DIGEST_MISMATCH"));
});

test("digest object with wrong label/algorithm/value shape is rejected", () => {
  const wrongLabel = makeEvent({
    payload_digest: { algorithm: "sha256", label: "other_label", value_hex: "a".repeat(64) },
  });
  assert.ok(codesOf(validateEvent(wrongLabel)).includes("V_INVALID_FIELD_TYPE"));
  const wrongAlg = makeEvent({
    payload_digest: { algorithm: "md5", label: "canonical_payload", value_hex: "a".repeat(64) },
  });
  assert.ok(codesOf(validateEvent(wrongAlg)).includes("V_INVALID_FIELD_TYPE"));
  const badHex = makeEvent({
    payload_digest: { algorithm: "sha256", label: "canonical_payload", value_hex: "XYZ" },
  });
  assert.ok(codesOf(validateEvent(badHex)).includes("V_INVALID_FIELD_TYPE"));
});

// ---------------------------------------------------------------------------
// Structural gates
// ---------------------------------------------------------------------------

test("missing mandatory fields are each reported with paths", () => {
  const e = {
    $schema: SUPPORTED_EVENT_SCHEMA,
    event_id: "event-0002",
  };
  const r = validateEvent(e as JsonValue);
  assert.ok(!r.ok);
  const missing = r.issues.filter((i) => i.code === "V_MISSING_MANDATORY_FIELD").map((i) => i.path);
  for (const field of [
    "$.correlation_nonce",
    "$.producer_id",
    "$.event_source",
    "$.loss_semantics",
    "$.payload",
    "$.payload_digest",
  ]) {
    assert.ok(missing.includes(field), `expected missing ${field}`);
  }
});

test("unknown schema version is rejected and gates remaining checks", () => {
  const e = makeEvent({ $schema: "ab.event/99" });
  const r = validateEvent(e);
  assert.ok(!r.ok);
  assert.deepEqual(codesOf(r), ["V_UNKNOWN_SCHEMA_VERSION"]);
});

test("$schema must be a string", () => {
  const r = validateEvent(makeEvent({ $schema: 1 }));
  assert.ok(!r.ok);
  assert.ok(codesOf(r).includes("V_SCHEMA_VERSION_NOT_STRING"));
});

test("restricted-ID violations reported for id fields", () => {
  const e = makeEvent({
    event_id: "9bad",
    correlation_nonce: "has space",
    producer_id: "",
    event_source: "ok-source",
  });
  const r = validateEvent(e);
  assert.ok(!r.ok);
  const badIds = r.issues.filter((i) => i.code === "V_INVALID_ID").map((i) => i.path);
  assert.deepEqual(badIds.sort(), ["$.correlation_nonce", "$.event_id", "$.producer_id"]);
});

test("undeclared fields rejected on event and digest objects", () => {
  const e = makeEvent({
    sneaky: true,
    payload_digest: { ...validDigestObject({ kind: "observation", v: 1 }), extra: 1 },
  });
  const r = validateEvent(e);
  assert.ok(!r.ok);
  const extras = r.issues.filter((i) => i.code === "V_EXTRA_FIELD").map((i) => i.path);
  assert.deepEqual(extras.sort(), ["$.payload_digest.extra", "$.sneaky"]);
});

test("loss_semantics is a closed set", () => {
  assert.ok(codesOf(validateEvent(makeEvent({ loss_semantics: "sometimes" }))).includes("V_INVALID_FIELD_TYPE"));
  assert.deepEqual(validateEvent(makeEvent({ loss_semantics: "lossy_bounded" })), { ok: true });
});

test("sequence must be an integer within range when present", () => {
  assert.ok(codesOf(validateEvent(makeEvent({ sequence: -1 }))).includes("V_INVALID_FIELD_TYPE"));
  assert.ok(codesOf(validateEvent(makeEvent({ sequence: 1.5 }))).includes("V_INVALID_FIELD_TYPE"));
  assert.ok(codesOf(validateEvent(makeEvent({ sequence: Number.MAX_SAFE_INTEGER + 1 }))).includes("V_INVALID_FIELD_TYPE"));
});

test("orphan uncertainty and malformed timestamps are rejected", () => {
  const orphan = makeEvent({ timestamp_uncertainty_ms: 5 });
  const ro = validateEvent(orphan);
  assert.ok(!ro.ok);
  assert.ok(issuePaths(ro).includes("$.timestamp_utc"));

  const badTs = makeEvent({ timestamp_utc: "2026/08/24 07:00:00Z" });
  assert.ok(codesOf(validateEvent(badTs)).includes("V_INVALID_FIELD_TYPE"));

  const badUnc = makeEvent({ timestamp_utc: "2026-08-24T07:00:00Z", timestamp_uncertainty_ms: 0 });
  assert.ok(codesOf(validateEvent(badUnc)).includes("V_INVALID_FIELD_TYPE"));

  // Non-orphan uncertainty with well-formed timestamp passes.
  assert.deepEqual(
    validateEvent(makeEvent({ timestamp_utc: "2026-08-24T07:00:00Z", timestamp_uncertainty_ms: 12 })),
    { ok: true },
  );
});

// ---------------------------------------------------------------------------
// Trace-level invariants
// ---------------------------------------------------------------------------

function traceCodes(result: ReturnType<typeof validateEventTrace>): string[] {
  return result.ok ? [] : result.issues.map((i) => i.code);
}

test("duplicate event_ids reported at later occurrences", () => {
  const e1 = makeEvent({ event_id: "dup-ev" });
  const e2 = makeEvent({ event_id: "dup-ev" });
  const e3 = makeEvent({ event_id: "dup-ev" });
  const r = validateEventTrace([e1, e2, e3]);
  assert.ok(!r.ok);
  const dups = r.issues.filter((i) => i.code === "V_DUPLICATE_ID");
  assert.equal(dups.length, 2);
  assert.deepEqual(dups.map((d) => d.path), ["$.events[1].event_id", "$.events[2].event_id"]);
});

test("unresolved predecessor is reported", () => {
  const e = makeEvent({ causal_predecessors: ["ghost-event"] });
  const r = validateEventTrace([e]);
  assert.ok(!r.ok);
  assert.ok(traceCodes(r).includes("V_UNRESOLVED_REFERENCE"));
});

test("self-reference is reported as V_CAUSAL_SELF_REFERENCE", () => {
  const e = makeEvent({ event_id: "selfish", causal_predecessors: ["selfish"] });
  const r = validateEventTrace([e]);
  assert.ok(!r.ok);
  const codes = traceCodes(r);
  assert.ok(codes.includes("V_CAUSAL_SELF_REFERENCE"));
  assert.ok(!codes.includes("V_UNRESOLVED_REFERENCE")); // resolves, but forbidden
});

test("two-node causal cycle is detected deterministically", () => {
  const a = makeEvent({ event_id: "cyc-a", causal_predecessors: ["cyc-b"] });
  const b = makeEvent({ event_id: "cyc-b", causal_predecessors: ["cyc-a"] });
  const r = validateEventTrace([a, b]);
  assert.ok(!r.ok);
  assert.equal(traceCodes(r).filter((c) => c === "V_CAUSAL_CYCLE").length, 1);
});

test("diamond dependency (shared predecessor, no cycle) passes", () => {
  const root = makeEvent({ event_id: "root" });
  const l = makeEvent({ event_id: "left", causal_predecessors: ["root"] });
  const rgt = makeEvent({ event_id: "right", causal_predecessors: ["root"] });
  const sink = makeEvent({ event_id: "sink", causal_predecessors: ["left", "right"] });
  assert.deepEqual(validateEventTrace([root, l, rgt, sink]), { ok: true });
});

test("per-producer sequence must strictly increase in trace order", () => {
  const p = "prod-seq";
  const e1 = makeEvent({ event_id: "s1", producer_id: p, sequence: 10 });
  const e2 = makeEvent({ event_id: "s2", producer_id: p, sequence: 11 });
  const e3 = makeEvent({ event_id: "s3", producer_id: p, sequence: 11 }); // equal ⇒ violation
  const e4 = makeEvent({ event_id: "s4", producer_id: "other-prod", sequence: 1 }); // separate namespace
  const r = validateEventTrace([e1, e2, e3, e4]);
  assert.ok(!r.ok);
  const seqIssues = r.issues.filter((i) => i.code === "V_SEQUENCE_NOT_MONOTONIC");
  assert.equal(seqIssues.length, 1);
  assert.equal(seqIssues[0]?.path, "$.events[2].sequence");
});

test("empty trace is trivially valid", () => {
  assert.deepEqual(validateEventTrace([]), { ok: true });
});
