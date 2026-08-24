/**
 * Tests: deterministic policy/oracle (M0 Slice 4b) — §4 decision order 1–6,
 * precedence, consistency gate, pass gates, admissibility ceiling.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { JsonValue } from "../src/json.ts";
import {
  SUPPORTED_POLICY_INPUT_SCHEMA,
  VERDICT_AGGREGATION_RULE,
  claimAdmissibilityCeiling,
  decideScenarioVerdict,
} from "../src/policy.ts";

type Mutable = Record<string, unknown>;

/** Fully-gated passing input; overrides adjust per test. */
function makeInput(overrides: Readonly<Record<string, unknown>> = {}): JsonValue {
  const base: Mutable = {
    $schema: SUPPORTED_POLICY_INPUT_SCHEMA,
    intentionally_unexecuted: false,
    execution_status: "completed",
    failure_classes: [],
    capability_present: true,
    violation_detected: false,
    evidence_state: "present",
    property_outcomes: [{ property_id: "prop-001", predicate: "pass" }],
    cleanup_verified: true,
    artifacts_reference_closed: true,
    observers_healthy: true,
    mandatory_controls_passed: true,
    unresolved_critical_contradiction: false,
  };
  return { ...base, ...overrides } as JsonValue;
}

function verdictOf(input: JsonValue): string | undefined {
  const r = decideScenarioVerdict(input);
  assert.ok(r.ok, `expected ok decision for ${JSON.stringify(input).slice(0, 120)}: ${JSON.stringify(r.ok ? {} : r.issues)}`);
  if (!r.ok) return undefined;
  return r.outcome.scenario_verdict;
}

function reasonsOf(input: JsonValue): readonly string[] {
  const r = decideScenarioVerdict(input);
  assert.ok(r.ok);
  if (!r.ok) return [];
  return r.outcome.reasons;
}

// ---------------------------------------------------------------------------
// Decision steps in isolation and precedence
// ---------------------------------------------------------------------------

test("step 1: intentionally unexecuted → not_run, no run_validity", () => {
  const flags = {
    intentionally_unexecuted: true,
    // Honest not-run facts: nothing was executed, so all run gates are false.
    cleanup_verified: false,
    artifacts_reference_closed: false,
    observers_healthy: false,
    mandatory_controls_passed: false,
    evidence_state: "absent",
  } as const;
  const input = makeInput(flags);
  const r = decideScenarioVerdict(input);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.outcome.scenario_verdict, "not_run");
  assert.equal(r.outcome.run_validity, undefined);
  assert.ok(reasonsOf(input).includes("step1:intentionally_unexecuted"));
});

test("step 2: each failure class yields invalid_run with run_validity=invalid", () => {
  const classToFlag: ReadonlyArray<readonly [string, Mutable]> = [
    ["setup", { execution_status: "setup_failed" }],
    ["containment", { execution_status: "blocked" }],
    ["mandatory_observer", { observers_healthy: false, execution_status: "observer_fault" }],
    ["integrity", { artifacts_reference_closed: false, execution_status: "blocked" }],
    ["correlation", { execution_status: "blocked" }],
    ["control", { mandatory_controls_passed: false, execution_status: "blocked" }],
    ["teardown", { cleanup_verified: false, execution_status: "cleanup_failed" }],
  ];
  for (const [fc, flags] of classToFlag) {
    const input = makeInput({ ...flags, failure_classes: [fc] });
    const r = decideScenarioVerdict(input);
    assert.ok(r.ok, `class ${fc}`);
    if (!r.ok) continue;
    assert.equal(r.outcome.run_validity, "invalid", `class ${fc}`);
    assert.equal(r.outcome.scenario_verdict, "invalid_run", `class ${fc}`);
  }
});

test("step 2: blocked/aborted status alone invalidates the run", () => {
  assert.equal(verdictOf(makeInput({ execution_status: "blocked" })), "invalid_run");
  assert.equal(verdictOf(makeInput({ execution_status: "aborted" })), "invalid_run");
});

test("step precedence: failure beats absent capability beats violation", () => {
  // failure + missing capability → invalid_run (step 2 wins)
  const a = makeInput({
    execution_status: "blocked",
    capability_present: false,
    failure_classes: ["containment"],
  });
  assert.equal(verdictOf(a), "invalid_run");

  // missing capability + violation → not_supported (step 3 wins over 4)
  const b = makeInput({
    capability_present: false,
    violation_detected: true,
    property_outcomes: [{ property_id: "prop-001", predicate: "violation" }],
  });
  assert.equal(verdictOf(b), "not_supported");

  // violation + weak evidence → fail (step 4 wins over 5)
  const c = makeInput({
    violation_detected: true,
    evidence_state: "ambiguous",
    property_outcomes: [{ property_id: "prop-001", predicate: "violation" }],
  });
  assert.equal(verdictOf(c), "fail");
});

test("step 4: violation detected → fail", () => {
  assert.equal(
    verdictOf(makeInput({ violation_detected: true, property_outcomes: [{ property_id: "p1", predicate: "violation" }] })),
    "fail",
  );
});

test("step 5: every non-present evidence state yields inconclusive", () => {
  for (const state of ["absent", "contradictory", "ambiguous", "cannot_discriminate"] as const) {
    assert.equal(verdictOf(makeInput({ evidence_state: state })), "inconclusive", state);
  }
  assert.equal(
    verdictOf(makeInput({ unresolved_critical_contradiction: true })),
    "inconclusive",
  );
});

test("step 6: full gates + all properties pass → pass with run_validity=valid", () => {
  const r = decideScenarioVerdict(makeInput());
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.outcome.run_validity, "valid");
  assert.equal(r.outcome.scenario_verdict, "pass");
  assert.equal(r.outcome.aggregation_rule, VERDICT_AGGREGATION_RULE);
  assert.deepEqual(reasonsOf(makeInput()), ["step6:all_properties_pass_all_gates_open"]);
});

test("step 6: multiple passing properties still pass", () => {
  assert.equal(
    verdictOf(
      makeInput({
        property_outcomes: [
          { property_id: "prop-a", predicate: "pass" },
          { property_id: "prop-b", predicate: "pass" },
        ],
      }),
    ),
    "pass",
  );
});

test("step 6: each unmet gate yields inconclusive, never pass", () => {
  for (const flags of [
    { execution_status: "completed", cleanup_verified: false },
    { artifacts_reference_closed: false },
    { observers_healthy: false },
    { mandatory_controls_passed: false },
    { unresolved_critical_contradiction: true },
  ] as const) {
    // Gates flipped to false without matching failure classes would be
    // inconsistent; use the minimal single-gate violation shape instead:
    // cleanup_verified=false REQUIRES the teardown class (consistency), so
    // gate-only probes here keep the class absent where legal.
    if ("cleanup_verified" in flags || "artifacts_reference_closed" in flags || "observers_healthy" in flags || "mandatory_controls_passed" in flags) {
      // These are covered by step-2 tests (class ⇔ flag coupling); a
      // gate-false-without-class input must be rejected as inconsistent.
      const r = decideScenarioVerdict(makeInput(flags));
      assert.ok(!r.ok, JSON.stringify(flags));
      continue;
    }
    assert.equal(verdictOf(makeInput(flags)), "inconclusive", JSON.stringify(flags));
  }
});

test("step 6: insufficient_evidence property outcome yields inconclusive", () => {
  const r = decideScenarioVerdict(
    makeInput({
      property_outcomes: [
        { property_id: "prop-ok", predicate: "pass" },
        { property_id: "prop-weak", predicate: "insufficient_evidence" },
      ],
    }),
  );
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.outcome.scenario_verdict, "inconclusive");
  assert.ok(reasonsOf(
    makeInput({
      property_outcomes: [
        { property_id: "prop-ok", predicate: "pass" },
        { property_id: "prop-weak", predicate: "insufficient_evidence" },
      ],
    }),
  ).includes("step6:property_outcome_insufficient_evidence"));
});

// ---------------------------------------------------------------------------
// Consistency gate
// ---------------------------------------------------------------------------

test("gate flags false without their failure class are rejected as inconsistent", () => {
  for (const flags of [
    { cleanup_verified: false },
    { observers_healthy: false },
    { mandatory_controls_passed: false },
    { artifacts_reference_closed: false },
  ] as const) {
    const r = decideScenarioVerdict(makeInput(flags));
    assert.ok(!r.ok, JSON.stringify(flags));
    if (!r.ok) {
      assert.ok(r.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"), JSON.stringify(flags));
    }
  }
});

test("failure class without its gate flag is rejected as inconsistent", () => {
  const r = decideScenarioVerdict(makeInput({ failure_classes: ["teardown"] }));
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.every((i) => i.code === "V_INCONSISTENT_INPUT"));
});

test("violation_detected must match an actual violation outcome", () => {
  const r = decideScenarioVerdict(makeInput({ violation_detected: true }));
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"));

  const r2 = decideScenarioVerdict(
    makeInput({ property_outcomes: [{ property_id: "p1", predicate: "violation" }] }),
  );
  assert.ok(!r2.ok);
  if (!r2.ok) assert.ok(r2.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"));
});

test("not_run inputs may not claim completed-run facts", () => {
  const r = decideScenarioVerdict(
    makeInput({ intentionally_unexecuted: true, cleanup_verified: true }),
  );
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"));

  const r2 = decideScenarioVerdict(
    makeInput({ intentionally_unexecuted: true, violation_detected: true }),
  );
  assert.ok(!r2.ok);
});

// ---------------------------------------------------------------------------
// Structural validation of the policy input
// ---------------------------------------------------------------------------

test("unknown schema version rejected before deciding", () => {
  const r = decideScenarioVerdict(makeInput({ $schema: "ab.policy-input/99" }));
  assert.ok(!r.ok);
  if (!r.ok) assert.deepEqual(r.issues.map((i) => i.code), ["V_UNKNOWN_SCHEMA_VERSION"]);
});

test("closed-set violations reported with stable codes", () => {
  const bad = makeInput({
    execution_status: "finished",
    evidence_state: "solid",
    failure_classes: ["meteor"],
    property_outcomes: [{ property_id: "p1", predicate: "maybe" }],
  });
  const r = decideScenarioVerdict(bad);
  assert.ok(!r.ok);
  if (!r.ok) {
    const codes = r.issues.map((i) => i.code);
    assert.ok(codes.filter((c) => c === "V_INVALID_FIELD_TYPE").length >= 4);
  }
});

test("duplicate property_ids rejected", () => {
  const r = decideScenarioVerdict(
    makeInput({
      property_outcomes: [
        { property_id: "dup", predicate: "pass" },
        { property_id: "dup", predicate: "pass" },
      ],
    }),
  );
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_DUPLICATE_ID"));
});

test("empty property_outcomes rejected", () => {
  const r = decideScenarioVerdict(makeInput({ property_outcomes: [] }));
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_EMPTY_ARRAY"));
});

test("extra fields rejected at root and inside outcomes", () => {
  const r = decideScenarioVerdict(
    makeInput({
      bonus: true,
      property_outcomes: [{ property_id: "p1", predicate: "pass", weight: 2 }],
    }),
  );
  assert.ok(!r.ok);
  if (!r.ok) {
    const extras = r.issues.filter((i) => i.code === "V_EXTRA_FIELD").map((i) => i.path).sort();
    assert.deepEqual(extras, ["$.bonus", "$.property_outcomes[0].weight"]);
  }
});

// ---------------------------------------------------------------------------
// Determinism + admissibility ceiling
// ---------------------------------------------------------------------------

test("identical input ⇒ byte-identical outcome JSON across calls", () => {
  const input = makeInput();
  const a = decideScenarioVerdict(input);
  const b = decideScenarioVerdict(JSON.parse(JSON.stringify(input)) as JsonValue);
  assert.ok(a.ok && b.ok);
  if (!(a.ok && b.ok)) return;
  assert.equal(JSON.stringify(a.outcome), JSON.stringify(b.outcome));
});

test("claim ceiling: non-pass is inadmissible regardless of independence", () => {
  for (const v of ["fail", "inconclusive", "invalid_run", "not_supported", "not_run"] as const) {
    assert.equal(claimAdmissibilityCeiling(v, true), "inadmissible");
    assert.equal(claimAdmissibilityCeiling(v, false), "inadmissible");
  }
});

test("claim ceiling: pass requires complete observer independence for admissible", () => {
  assert.equal(claimAdmissibilityCeiling("pass", false), "downgraded");
  assert.equal(claimAdmissibilityCeiling("pass", true), "admissible");
});