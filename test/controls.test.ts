/**
 * Tests: measurement plans, control results, requirement matrix (M1 Slice 4).
 * Six-kind completeness, per-defect-class result application, matrix
 * coverage defects named exhaustively.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { JsonValue } from "../src/json.ts";
import {
  CONTROL_KINDS,
  applyControlResults,
  validateMeasurementPlan,
  validateRequirementMatrix,
} from "../src/controls.ts";

type Mutable = Record<string, unknown>;

function planDoc(planId = "plan-export-deny-001", propertyId = "prop-export-denied-002"): JsonValue {
  const controls = CONTROL_KINDS.map((kind, i) => ({
    control_id: `ctl-${planId}-${String(i + 1).padStart(2, "0")}`,
    kind,
  }));
  return {
    $schema: "ab.measurement-plan/1",
    plan_id: planId,
    property_id: propertyId,
    subject_version_binding: "subject pinned at ab-host/1.0.0",
    action_boundary: "host export permission check immediately before effect",
    ordering_model: "causal_order from correlation nonce chains",
    clock_source: "single synthetic monotonic clock service",
    temporal_interval: { start_utc: "2026-08-24T08:00:00Z", end_utc: "2026-08-24T09:00:00Z" },
    clock_uncertainty_ms: 20,
    loss_semantics: "lossless",
    route_inventory_ref: "inventory-clipboard-001",
    observation_planes: ["api_boundary", "filesystem"],
    required_controls: controls,
    predicates: {
      pass: "no export event observed for denied destination within interval",
      fail: "export effect observed at the boundary",
      inconclusive: "observer liveness cannot be established",
    },
    permitted_result_classes: ["adapter_observed_conformance"],
  } as JsonValue;
}

function controlIdsOf(doc: JsonValue): string[] {
  return ((doc as Mutable)["required_controls"] as Array<{ control_id: string }>).map((c) => c.control_id);
}

test("valid plan passes validation", () => {
  assert.deepEqual(validateMeasurementPlan(planDoc()), { ok: true });
});

test("removing any one of the six kinds yields its named missing-kind issue", () => {
  for (const kind of CONTROL_KINDS) {
    const doc = planDoc();
    const d = doc as Mutable;
    d["required_controls"] = (d["required_controls"] as Array<{ kind: string }>).filter((c) => c.kind !== kind);
    const r = validateMeasurementPlan(doc);
    assert.ok(!r.ok, kind);
    if (!r.ok) {
      const m = r.issues.find((i) => i.code === "V_CONTROL_KIND_MISSING" && i.message.includes(`"${kind}"`));
      assert.ok(m !== undefined, `expected missing-kind issue for ${kind}`);
    }
  }
});

test("duplicate control ids rejected", () => {
  const doc = planDoc() as Mutable;
  const controls = (doc["required_controls"] as Array<{ control_id: string; kind: string }>).slice();
  controls.push({ control_id: controls[0]!.control_id, kind: "positive" });
  doc["required_controls"] = controls;
  const r = validateMeasurementPlan(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_DUPLICATE_ID"));
});

test("unknown schema version gates checks", () => {
  const r = validateMeasurementPlan({ ...(planDoc() as Mutable), $schema: "ab.measurement-plan/9" } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.deepEqual(r.issues.map((i) => i.code), ["V_UNKNOWN_SCHEMA_VERSION"]);
});

test("inverted interval rejected; bad planes and result classes rejected", () => {
  const inv = { ...(planDoc() as Mutable), temporal_interval: { start_utc: "2026-08-24T09:00:00Z", end_utc: "2026-08-24T08:00:00Z" } };
  const r1 = validateMeasurementPlan(inv as JsonValue);
  assert.ok(!r1.ok);
  if (!r1.ok) assert.ok(r1.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"));

  const r2 = validateMeasurementPlan({ ...(planDoc() as Mutable), observation_planes: ["telepathy"] } as JsonValue);
  assert.ok(!r2.ok);

  const r3 = validateMeasurementPlan({ ...(planDoc() as Mutable), permitted_result_classes: ["total_safety"] } as JsonValue);
  assert.ok(!r3.ok);
});

// ---------------------------------------------------------------------------
// Control-result application
// ---------------------------------------------------------------------------

test("all declared controls passed ⇒ complete and allPassed", () => {
  const doc = planDoc();
  const results = controlIdsOf(doc).map((control_id) => ({ control_id, outcome: "passed" as const }));
  const r = applyControlResults(doc, results);
  assert.equal(r.complete, true);
  assert.equal(r.allPassed, true);
  assert.equal(r.passedCount, results.length);
  assert.deepEqual(r.failedIds, []);
  assert.deepEqual(r.notRunIds, []);
  assert.deepEqual(r.missingIds, []);
  assert.deepEqual(r.unknownIds, []);
});

test("failed control surfaces by id (feeds policy 'control' failure honestly)", () => {
  const doc = planDoc();
  const ids = controlIdsOf(doc);
  const results = ids.map((control_id, i) => ({
    control_id,
    outcome: i === 0 ? ("failed" as const) : ("passed" as const),
  }));
  const r = applyControlResults(doc, results);
  assert.equal(r.allPassed, false);
  assert.deepEqual(r.failedIds, [ids[0]]);
});

test("missing, not_run, and unknown ids are each reported distinctly", () => {
  const doc = planDoc();
  const ids = controlIdsOf(doc);
  const partial = ids.slice(1).map((control_id) => ({ control_id, outcome: "passed" as const }));
  const withExtras = [
    ...partial,
    { control_id: ids[0]!, outcome: "not_run" as const },
    { control_id: "ctl-ghost", outcome: "passed" as const },
  ];
  const r = applyControlResults(doc, withExtras);
  assert.equal(r.complete, false);
  assert.equal(r.allPassed, false);
  assert.deepEqual(r.missingIds, []);
  assert.deepEqual(r.notRunIds, [ids[0]]);
  assert.deepEqual(r.unknownIds, ["ctl-ghost"]);
  assert.equal(r.passedCount, ids.length - 1);

  const missingOnly = applyControlResults(doc, []);
  assert.equal(missingOnly.complete, false);
  assert.equal(missingOnly.missingIds.length, ids.length);
});

test("empty declared-controls plan can never be allPassed", () => {
  const doc = planDoc() as Mutable;
  doc["required_controls"] = [];
  const r = applyControlResults(doc as JsonValue, []);
  // The plan itself is invalid, but the application must still be safe.
  assert.equal(r.allPassed, false);
});

// ---------------------------------------------------------------------------
// Requirement matrix
// ---------------------------------------------------------------------------

function matrixDoc(): JsonValue {
  return {
    $schema: "ab.requirement-matrix/1",
    matrix_id: "matrix-m1-core-001",
    requirements: [
      { requirement_id: "req-bnd-020", statement: "Exports are denied at declared boundaries." },
      { requirement_id: "req-obs-011", statement: "Required observers are healthy or runs invalidate." },
    ],
    mappings: [
      { requirement_id: "req-bnd-020", plan_id: "plan-export-deny-001" },
      { requirement_id: "req-obs-011", plan_id: "plan-observer-health-001" },
    ],
  } as JsonValue;
}

test("complete valid matrix over valid plans passes", () => {
  const plans = new Map<string, JsonValue>([
    ["plan-export-deny-001", planDoc()],
    ["plan-observer-health-001", planDoc("plan-observer-health-001", "prop-observer-health-003")],
  ]);
  assert.deepEqual(validateRequirementMatrix(matrixDoc(), plans), { ok: true });
});

test("dangling requirement and dangling plan references named", () => {
  const plans = new Map<string, JsonValue>([
    ["plan-export-deny-001", planDoc()],
    ["plan-observer-health-001", planDoc("plan-observer-health-001", "prop-x")],
  ]);
  const m = matrixDoc() as Mutable;
  (m["mappings"] as Mutable[]).push({ requirement_id: "req-ghost-999", plan_id: "plan-export-deny-001" });
  (m["mappings"] as Mutable[]).push({ requirement_id: "req-bnd-020", plan_id: "plan-ghost-001" });
  const r = validateRequirementMatrix(m as JsonValue, plans);
  assert.ok(!r.ok);
  if (!r.ok) {
    assert.ok(r.issues.some((i) => i.message.includes("req-ghost-999")));
    assert.ok(r.issues.some((i) => i.message.includes("plan-ghost-001")));
  }
});

test("requirement without mapping is named", () => {
  const plans = new Map<string, JsonValue>([
    ["plan-export-deny-001", planDoc()],
    ["plan-observer-health-001", planDoc("plan-observer-health-001", "prop-y")],
  ]);
  const m = matrixDoc() as Mutable;
  m["mappings"] = [{ requirement_id: "req-bnd-020", plan_id: "plan-export-deny-001" }];
  const r = validateRequirementMatrix(m as JsonValue, plans);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.message.includes("req-obs-011") && i.message.includes("no test mapping")));
});

test("unmapped plan is named (V_UNMAPPED_PLAN)", () => {
  const plans = new Map<string, JsonValue>([
    ["plan-export-deny-001", planDoc()],
    ["plan-observer-health-001", planDoc("plan-observer-health-001", "prop-z")],
    ["plan-orphan-999", planDoc("plan-orphan-999", "prop-w")],
  ]);
  const r = validateRequirementMatrix(matrixDoc(), plans);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_UNMAPPED_PLAN" && i.message.includes("plan-orphan-999")));
});

test("structurally invalid referenced plan is named against its id", () => {
  const brokenPlan = planDoc("plan-observer-health-001");
  const bp = brokenPlan as Mutable;
  delete bp["predicates"];
  const plans = new Map<string, JsonValue>([
    ["plan-export-deny-001", planDoc()],
    ["plan-observer-health-001", bp as JsonValue],
  ]);
  const r = validateRequirementMatrix(matrixDoc(), plans);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.path === "#plans.plan-observer-health-001"));
});
