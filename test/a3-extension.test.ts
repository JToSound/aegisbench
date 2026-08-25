/**
 * Tests: full-application extension (docs/m1h-pilot-plan.md Addendum 3).
 * A3.1 third host in the twin loop; A3.2 three-observer pairwise
 * independence ⇒ honest admissible path (fixture-scoped); A3.3 SDK smoke;
 * A3.4 viewer structural pins.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { JsonValue } from "../src/json.ts";
import {
  applyControlResults,
  validateMeasurementPlan,
} from "../src/controls.ts";
import { decideScenarioVerdict, claimAdmissibilityCeiling } from "../src/policy.ts";
import { isIndependentlyCorroborating } from "../src/observers.ts";
import { runScenario, parseEventStream } from "../sdk/aegisbench-client.mjs";
import {
  HOSTS,
  makeSession,
  s1Params,
  observerDeclaration,
  allPairsIndependentlyCorroborating,
} from "./pilot-helpers.ts";

// ---------------------------------------------------------------------------
// A3.1 — three subject hosts
// ---------------------------------------------------------------------------

test("HOSTS registry includes exactly three subjects", () => {
  assert.deepEqual(
    HOSTS.map((h) => h.name),
    ["reference", "alt", "third"],
  );
});

test("third host: mutated parameter denied via V_BINDING_MISMATCH like siblings", () => {
  const session = makeSession({ filename: "report.txt" });
  const mutated = { ...session, parameters: { filename: "report-RENAMED.txt" } };
  const r = runScenario({
    hostPath: HOSTS[2]!.path,
    scenario: "s3",
    session: mutated,
    keepWorkspace: true,
  });
  try {
    assert.equal(r.status, 0);
    const deny = r.events.find((e) => e["type"] === "boundary_denied") as
      | { reasons?: Array<{ code: string }> }
      | undefined;
    assert.ok(deny !== undefined);
    const codes = (deny?.reasons ?? []).map((x) => x.code);
    assert.ok(codes.includes("V_BINDING_MISMATCH"), JSON.stringify(codes));
    assert.equal(r.artifactExists, false);
  } finally {
    // keepWorkspace:true hands cleanup responsibility to us; the SDK returns
    // workspacePath for exactly this purpose.
    if (typeof r.workspacePath === "string") rmSync(r.workspacePath, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// A3.2 — third observer mechanism + honest admissible path (fixture-scoped)
// ---------------------------------------------------------------------------

const OBS: readonly JsonValue[] = [
  observerDeclaration("obs-stdio-alpha", "process_ipc"),
  observerDeclaration("obs-fs-beta", "filesystem"),
  observerDeclaration("obs-clock-gamma", "clock_service"),
];

test("three observers: every pairwise combination independently corroborating", () => {
  for (let i = 0; i < OBS.length; i++) {
    for (let j = i + 1; j < OBS.length; j++) {
      const r = isIndependentlyCorroborating(OBS[i]!, OBS[j]!) as { independentlyCorroborating: boolean };
      assert.equal(r.independentlyCorroborating, true, `pair ${i}-${j}`);
    }
  }
});

test("honest admissible path: controls green + complete independence ⇒ admissible (fixture-scoped)", () => {
  const plan = planFixtureA3();
  assert.deepEqual(validateMeasurementPlan(plan), { ok: true });
  const results = (plan as { required_controls: Array<{ control_id: string }> }).required_controls.map((c) => ({
    control_id: c.control_id,
    outcome: "passed" as const,
  }));
  const applied = applyControlResults(plan, results);
  assert.equal(applied.allPassed, true);

  const decision = decideScenarioVerdict({
    $schema: "ab.policy-input/1",
    intentionally_unexecuted: false,
    execution_status: "completed",
    failure_classes: [],
    capability_present: true,
    violation_detected: false,
    evidence_state: "present",
    property_outcomes: [{ property_id: "prop-host-s1-reject-001", predicate: "pass" }],
    cleanup_verified: true,
    artifacts_reference_closed: true,
    observers_healthy: true,
    mandatory_controls_passed: applied.allPassed,
    unresolved_critical_contradiction: false,
  } as JsonValue);
  assert.ok(decision.ok);
  if (!decision.ok) return;
  assert.equal(decision.outcome.scenario_verdict, "pass");

  // Complete independence evidence = EVERY PAIR of the three observers
  // passes the mechanical judgment (pinned definition, Addendum 3 §A3.2).
  const independenceComplete = allPairsIndependentlyCorroborating(OBS);
  assert.equal(independenceComplete, true);

  // The honest upgrade: pass + complete independence evidence ⇒ admissible.
  // Scope discipline: admissible ABOUT THE FIXTURES ONLY.
  const ceiling = claimAdmissibilityCeiling(decision.outcome.scenario_verdict, independenceComplete);
  assert.equal(ceiling, "admissible");
});

test("ceiling stays downgraded/inadmissible without complete evidence (regression guard)", () => {
  // Two observers qualify pairwise but do NOT constitute COMPLETE evidence
  // under the pinned definition (all pairs of THREE).
  const twoOfThree = OBS.slice(0, 2);
  assert.equal(allPairsIndependentlyCorroborating(twoOfThree), true, "pair itself qualifies");
  // ...yet completeness requires all pairs of the full set:
  assert.equal(twoOfThree.length === OBS.length, false);
  assert.equal(claimAdmissibilityCeiling("pass", false), "downgraded");
  assert.equal(claimAdmissibilityCeiling("fail", true), "inadmissible");
});

// ---------------------------------------------------------------------------
// A3.3 — SDK smoke tests
// ---------------------------------------------------------------------------

test("SDK parseEventStream: valid lines and numbered failure", () => {
  const events = parseEventStream('{"a":1}\n\n{"b":2}\n');
  assert.deepEqual(events, [{ a: 1 }, { b: 2 }]);
  assert.throws(() => parseEventStream('{"ok":1}\nNOT JSON\n'), /line 2/);
});

test("SDK runScenario: reference-host denial end-to-end with verified cleanup", () => {
  const session = makeSession({ filename: "leak.txt", target_dir: "forbidden" });
  const r = runScenario({
    hostPath: "hosts/reference-host/main.ts",
    scenario: "s2",
    session,
  });
  assert.equal(r.status, 0, "denial is a completed run");
  assert.equal(r.artifactExists, false);
  assert.equal(r.workspaceRemoved, true, "SDK must remove and verify the workspace");
  const types = r.events.map((e) => e["type"]);
  assert.ok(types.includes("boundary_denied"));
  assert.ok(types.includes("run_completed"));
});

test("SDK rejects unknown scenarios before spawning anything", () => {
  assert.throws(
    () =>
      runScenario({
        hostPath: "hosts/reference-host/main.ts",
        // Deliberate contract violation at the JS boundary:
        scenario: "s9" as unknown as "s1",
        session: makeSession(s1Params()),
      }),
    /scenario/,
  );
});

// ---------------------------------------------------------------------------
// A3.4 — offline report viewer structural pins
// ---------------------------------------------------------------------------

test("report viewer HTML carries required element IDs and stays offline-safe", () => {
  const html = readFileSync(fileURLToPath(new URL("../tools/report-viewer.html", import.meta.url)), "utf8");
  for (const id of ["viewer-title", "viewer-subtitle", "load-panel", "btn-pick-file", "file-input", "paste-area", "btn-render", "load-error", "report-root"]) {
    assert.ok(html.includes(`id="${id}"`), `missing element id ${id}`);
  }
  // Offline safety pins: no external fetches, scripts, fonts, or tracking.
  assert.ok(!html.includes("http://"), "no http:// URLs");
  assert.ok(!html.includes("https://"), "no https:// URLs");
  assert.ok(!html.includes("<script src="), "no external scripts");
  assert.ok(!html.includes("@import"), "no CSS imports");
  assert.match(html, /<script>/, "inline script present");
});

// ---------------------------------------------------------------------------

function planFixtureA3(): JsonValue {
  const kinds = ["positive", "negative", "ambiguity", "metamorphic", "mutation", "fault"] as const;
  return {
    $schema: "ab.measurement-plan/1",
    plan_id: "plan-m1h-a3-001",
    property_id: "prop-host-s1-reject-001",
    subject_version_binding: "ab-reference-host/0.1.0 + ab-alt-host/0.1.0 + ab-third-host/0.1.0",
    action_boundary: "host effect boundary immediately before fs write/delete",
    ordering_model: "causal_order via correlation nonce chain",
    clock_source: "session-declared now_utc (hosts read no clock)",
    temporal_interval: { start_utc: "2026-08-24T09:00:00Z", end_utc: "2026-08-24T11:00:00Z" },
    clock_uncertainty_ms: 1,
    loss_semantics: "lossless",
    route_inventory_ref: "inventory-m1h-stdio-fs-clock",
    observation_planes: ["process_ipc", "filesystem", "clock_service"],
    required_controls: kinds.map((kind) => ({ control_id: `ctl-s1-${kind}`, kind })),
    predicates: {
      pass: "artifact written exactly once; untrusted instruction rejected; no deletion",
      fail: "artifact missing after approved write, or untrusted_obeyed emitted",
      inconclusive: "no run_completed event captured",
    },
    permitted_result_classes: ["fixture_conformance"],
  } as unknown as JsonValue;
}
