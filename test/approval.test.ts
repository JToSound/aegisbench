/**
 * Tests: single-use integrity-bound approvals (M1 Slice 2).
 * Binding integrity, effect-boundary revalidation (all mismatch classes,
 * time-window edges, replay), disclosure-bounded denials, immutability.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { JsonValue } from "../src/json.ts";
import { canonicalize } from "../src/canon.ts";
import { domainDigestHex } from "../src/digest.ts";
import {
  SUPPORTED_APPROVAL_SCHEMA,
  buildApproval,
  consumeApproval,
  evaluateApprovalAtEffectBoundary,
  validateApproval,
} from "../src/approval.ts";

const PARAMS = '{"path":"synthetic://outbox/report.txt","mode":"export"}';
const CREATED = "2026-08-24T08:00:00Z";
const EXPIRY = "2026-08-24T09:00:00Z";
const NOW = "2026-08-24T08:30:00Z";
const CANARY = "AB_CANARY_0123456789abcdef0123456789abcdef";

function issuance(): Parameters<typeof buildApproval>[0] {
  return {
    approvalId: "approval-export-001",
    issuerId: "issuer-policy-engine",
    subjectId: "subject-agent-x",
    sessionId: "session-run-77",
    scenarioId: "scenario-export-002",
    policyVersion: "policy-v4",
    actionType: "action-file-export",
    parametersCanonicalText: PARAMS,
    destinationIdentity: "dest-synthetic-bucket-alpha",
    nonce: "nonce-capability-0091",
    executionCorrelation: "corr-attempt-001",
    createdUtc: CREATED,
    expiryUtc: EXPIRY,
  };
}

function built(): Record<string, JsonValue> {
  const r = buildApproval(issuance());
  assert.ok(r.ok, JSON.stringify(r.ok ? {} : r.issues));
  if (!r.ok) throw new Error("unreachable");
  return r.approval;
}

function decide(doc: JsonValue, overrides: Partial<Parameters<typeof evaluateApprovalAtEffectBoundary>[1]> = {}) {
  const req = {
    actionType: "action-file-export",
    parametersCanonicalText: PARAMS,
    destinationIdentity: "dest-synthetic-bucket-alpha",
    nowUtc: NOW,
    executionCorrelation: "corr-attempt-001",
    ...overrides,
  };
  return evaluateApprovalAtEffectBoundary(doc, req);
}

// ---------------------------------------------------------------------------
// Issuance + integrity
// ---------------------------------------------------------------------------

test("builder output passes validation", () => {
  assert.deepEqual(validateApproval(built() as JsonValue), { ok: true });
});

test("approval_digest equals an independent reconstruction over binding fields", () => {
  const doc = built();
  const subset: Record<string, JsonValue> = {};
  for (const [k, v] of Object.entries(doc)) {
    if (k !== "approval_digest" && k !== "consumption_state") subset[k] = v;
  }
  const c = canonicalize(subset);
  assert.ok(c.ok);
  if (!c.ok) return;
  const d = domainDigestHex("approval_binding", Buffer.from(c.canonicalText, "utf8"));
  assert.ok(d.ok);
  if (!d.ok) return;
  assert.equal(d.hex, String(doc["approval_digest"]));
});

test("tampering ANY bound field flips integrity (V_DIGEST_MISMATCH)", () => {
  const base = built();
  const tamperedFields = [
    ["scenario_id", "scenario-other-999"],
    ["policy_version", "policy-v9"],
    ["destination_identity", "dest-synthetic-bucket-beta"],
    ["nonce", "nonce-capability-9999"],
    ["expiry_utc", "2026-08-24T23:59:59Z"],
    ["parameter_digest", { algorithm: "sha256", label: "canonical_payload", value_hex: "a".repeat(64) }],
  ] as const;
  for (const [field, value] of tamperedFields) {
    const t = { ...base, [field]: value } as JsonValue;
    const r = validateApproval(t);
    assert.ok(!r.ok, field);
    if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_DIGEST_MISMATCH"), field);
  }
});

test("unknown schema version gates further checks", () => {
  const r = validateApproval({ ...built(), $schema: "ab.approval/9" } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.deepEqual(r.issues.map((i) => i.code), ["V_UNKNOWN_SCHEMA_VERSION"]);
});

// ---------------------------------------------------------------------------
// Effect-boundary revalidation
// ---------------------------------------------------------------------------

test("exact agreement everywhere allows the action", () => {
  assert.deepEqual(decide(built()), { allowed: true });
});

test("every binding mismatch denies with fixed-message evidence", () => {
  const cases: ReadonlyArray<readonly [string, Partial<Parameters<typeof evaluateApprovalAtEffectBoundary>[1]>]> = [
    ["action_type", { actionType: "action-file-delete" }],
    ["parameters", { parametersCanonicalText: '{"path":"synthetic://outbox/other.txt","mode":"export"}' }],
    ["destination", { destinationIdentity: "dest-synthetic-bucket-gamma" }],
    ["correlation", { executionCorrelation: "corr-attempt-002" }],
  ];
  for (const [name, override] of cases) {
    const r = decide(built(), override);
    assert.ok(!r.allowed, name);
    if (!r.allowed) {
      assert.ok(r.issues.some((i) => i.code === "V_BINDING_MISMATCH"), name);
      for (const i of r.issues) {
        assert.equal(i.message, "request does not match the capability binding", `${name}: messages are fixed`);
      }
    }
  }
});

test("time window: both inclusive edges allow, outside denies distinctly", () => {
  assert.deepEqual(decide(built(), { nowUtc: CREATED }), { allowed: true });
  assert.deepEqual(decide(built(), { nowUtc: EXPIRY }), { allowed: true });

  const early = decide(built(), { nowUtc: "2026-08-24T07:59:59Z" });
  assert.ok(!early.allowed);
  if (!early.allowed) assert.ok(early.issues.some((i) => i.code === "V_NOT_YET_VALID"));

  const late = decide(built(), { nowUtc: "2026-08-24T09:00:01Z" });
  assert.ok(!late.allowed);
  if (!late.allowed) assert.ok(late.issues.some((i) => i.code === "V_EXPIRED"));
});

test("replayed capability is denied as already consumed", () => {
  const first = consumeApproval(built() as JsonValue, NOW);
  assert.ok(first.ok);
  if (!first.ok) return;
  const r = decide(first.consumed as JsonValue);
  assert.ok(!r.allowed);
  if (!r.allowed) assert.ok(r.issues.some((i) => i.code === "V_ALREADY_CONSUMED"));
});

test("multiple violations are collected together", () => {
  const r = decide(
    consumeApproval(built() as JsonValue, NOW).ok ? (consumeApproval(built() as JsonValue, NOW) as { ok: true; consumed: JsonValue }).consumed : (built() as JsonValue),
    { actionType: "wrong-action", nowUtc: "2026-08-25T00:00:00Z" },
  );
  assert.ok(!r.allowed);
  if (!r.allowed) {
    const codes = r.issues.map((i) => i.code);
    assert.ok(codes.includes("V_ALREADY_CONSUMED"));
    assert.ok(codes.includes("V_BINDING_MISMATCH"));
    assert.ok(codes.includes("V_EXPIRED"));
  }
});

test("denial records never contain raw parameter material (canary-checked)", () => {
  const leakyParams = `{"note":"${CANARY}","mode":"export"}`;
  const r = decide(built(), { parametersCanonicalText: leakyParams });
  assert.ok(!r.allowed);
  if (!r.allowed) {
    const serialized = JSON.stringify(r.issues);
    assert.ok(!serialized.includes(CANARY), "raw parameter material leaked into denial record");
    assert.ok(serialized.length > 0);
  }
});

// ---------------------------------------------------------------------------
// Single-use consumption + immutability
// ---------------------------------------------------------------------------

test("consumption returns a NEW document; input stays untouched", () => {
  const original = built();
  const before = JSON.stringify(original);
  const r = consumeApproval(original as JsonValue, NOW);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(JSON.stringify(original), before, "input must not be mutated");
  const cs = r.consumed["consumption_state"] as Record<string, unknown>;
  assert.equal(cs["consumed"], true);
  assert.equal(cs["consumed_at_utc"], NOW);
  // Binding integrity survives the consumption flip.
  assert.deepEqual(validateApproval(r.consumed as JsonValue), { ok: true });
});

test("double consumption is refused", () => {
  const first = consumeApproval(built() as JsonValue, NOW);
  assert.ok(first.ok);
  if (!first.ok) return;
  const second = consumeApproval(first.consumed as JsonValue, NOW);
  assert.ok(!second.ok);
  if (!second.ok) assert.ok(second.issues.some((i) => i.code === "V_ALREADY_CONSUMED"));
});
