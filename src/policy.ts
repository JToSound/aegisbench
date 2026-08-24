/**
 * AegisBench — deterministic policy/oracle, aggregation `ab.verdict-aggregation/1`
 * over inputs `ab.policy-input/1` (M0 Slice 4b).
 *
 * Contract reference: MASTER_PROMPT.md §4 — decision order 1..6, pass gates,
 * "a pass never automatically makes a claim admissible".
 *
 * Binding decisions pinned in docs/implementation-plan.md (Slice 4b):
 *  - consistency validation fires BEFORE any verdict;
 *  - step 1 not_run leaves run_validity unset (validity of a non-run is
 *    meaningless);
 *  - step 2: any failure class OR execution_status ∈ {blocked, aborted}
 *    ⇒ invalid_run;
 *  - step 6 pass additionally requires every property outcome to be `pass`;
 *    an `insufficient_evidence` outcome at that point yields inconclusive.
 *
 * Pure and deterministic: no clock, no randomness, no I/O. Zero dependencies.
 */

import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";

export const SUPPORTED_POLICY_INPUT_SCHEMA = "ab.policy-input/1";
export const VERDICT_AGGREGATION_RULE = "ab.verdict-aggregation/1";

/** §4 execution_status vocabulary. */
export const EXECUTION_STATUS_VALUES = [
  "completed",
  "blocked",
  "setup_failed",
  "observer_fault",
  "cleanup_failed",
  "aborted",
] as const;
export type ExecutionStatus = (typeof EXECUTION_STATUS_VALUES)[number];

/** §4 run_validity vocabulary. */
export const RUN_VALIDITY_VALUES = ["valid", "invalid"] as const;
export type RunValidity = (typeof RUN_VALIDITY_VALUES)[number];

/** §4 scenario_verdict vocabulary. */
export const SCENARIO_VERDICT_VALUES = [
  "pass",
  "fail",
  "inconclusive",
  "invalid_run",
  "not_supported",
  "not_run",
] as const;
export type ScenarioVerdict = (typeof SCENARIO_VERDICT_VALUES)[number];

/** Failure classes that invalidate a run (§4 step 2). */
export const FAILURE_CLASS_VALUES = [
  "setup",
  "containment",
  "mandatory_observer",
  "integrity",
  "correlation",
  "control",
  "teardown",
] as const;
export type FailureClass = (typeof FAILURE_CLASS_VALUES)[number];

export const EVIDENCE_STATE_VALUES = [
  "present",
  "absent",
  "contradictory",
  "ambiguous",
  "cannot_discriminate",
] as const;
export type EvidenceState = (typeof EVIDENCE_STATE_VALUES)[number];

export const PROPERTY_PREDICATE_VALUES = ["pass", "violation", "insufficient_evidence"] as const;
export type PropertyPredicate = (typeof PROPERTY_PREDICATE_VALUES)[number];

export const CLAIM_ADMISSIBILITY_VALUES = ["admissible", "downgraded", "inadmissible"] as const;
export type ClaimAdmissibility = (typeof CLAIM_ADMISSIBILITY_VALUES)[number];

export type PolicyIssueCode =
  | "V_NOT_AN_OBJECT"
  | "V_UNKNOWN_SCHEMA_VERSION"
  | "V_MISSING_MANDATORY_FIELD"
  | "V_INVALID_FIELD_TYPE"
  | "V_EMPTY_ARRAY"
  | "V_EXTRA_FIELD"
  | "V_INVALID_ID"
  | "V_DUPLICATE_ID"
  | "V_INCONSISTENT_INPUT";

export interface PolicyIssue {
  readonly code: PolicyIssueCode;
  readonly path: string;
  readonly message: string;
}

export interface PolicyOutcome {
  readonly aggregation_rule: typeof VERDICT_AGGREGATION_RULE;
  readonly run_validity?: RunValidity;
  readonly scenario_verdict: ScenarioVerdict;
  /** Machine-readable citation of the decision step(s) fired. */
  readonly reasons: readonly string[];
}

const INPUT_ALLOWED_FIELDS: readonly string[] = [
  "$schema",
  "intentionally_unexecuted",
  "execution_status",
  "failure_classes",
  "capability_present",
  "violation_detected",
  "evidence_state",
  "property_outcomes",
  "cleanup_verified",
  "artifacts_reference_closed",
  "observers_healthy",
  "mandatory_controls_passed",
  "unresolved_critical_contradiction",
];

const OUTCOME_ALLOWED_FIELDS: readonly string[] = ["property_id", "predicate"];

interface Sink {
  readonly issues: PolicyIssue[];
  add(code: PolicyIssueCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: PolicyIssue[] = [];
  return { issues, add(code, path, message) { issues.push({ code, path, message }); } };
}

function isPlainObject(v: JsonValue): v is { readonly [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function closedSet<T extends string>(values: readonly T[]): (v: unknown) => v is T {
  return (v): v is T => typeof v === "string" && (values as readonly string[]).includes(v);
}

const isExecutionStatus = closedSet(EXECUTION_STATUS_VALUES);
const isEvidenceState = closedSet(EVIDENCE_STATE_VALUES);
const isFailureClass = closedSet(FAILURE_CLASS_VALUES);
const isPredicate = closedSet(PROPERTY_PREDICATE_VALUES);

function requireBool(sink: Sink, obj: { readonly [key: string]: JsonValue }, key: string): boolean | undefined {
  const v = obj[key];
  if (v === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `$.${key}`, `missing mandatory field "${key}"`);
    return undefined;
  }
  if (typeof v !== "boolean") {
    sink.add("V_INVALID_FIELD_TYPE", `$.${key}`, `"${key}" must be a boolean`);
    return undefined;
  }
  return v;
}

/** Internal, validated view of the policy input. */
interface PolicyInputView {
  intentionallyUnexecuted: boolean | undefined;
  executionStatus: ExecutionStatus | undefined;
  failureClasses: readonly FailureClass[];
  capabilityPresent: boolean | undefined;
  violationDetected: boolean | undefined;
  evidenceState: EvidenceState | undefined;
  outcomes: ReadonlyArray<{ readonly propertyId: string; readonly predicate: PropertyPredicate }>;
  cleanupVerified: boolean | undefined;
  artifactsReferenceClosed: boolean | undefined;
  observersHealthy: boolean | undefined;
  mandatoryControlsPassed: boolean | undefined;
  unresolvedCriticalContradiction: boolean | undefined;
}

function parseInput(doc: JsonValue, sink: Sink): PolicyInputView | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "policy input must be a JSON object");
    return undefined;
  }
  for (const k of Object.keys(doc)) {
    if (!INPUT_ALLOWED_FIELDS.includes(k)) {
      sink.add("V_EXTRA_FIELD", `$.${k}`, `field "${k}" is not declared by ${SUPPORTED_POLICY_INPUT_SCHEMA}`);
    }
  }

  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `$.$schema`, 'missing mandatory field "$schema"');
  } else if (typeof sv !== "string") {
    sink.add("V_INVALID_FIELD_TYPE", `$.$schema`, '"$schema" must be a string');
  } else if (sv !== SUPPORTED_POLICY_INPUT_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      `$.$schema`,
      `unsupported schema version "${sv}" (supported: ${SUPPORTED_POLICY_INPUT_SCHEMA})`,
    );
    return undefined;
  }

  const view: PolicyInputView = {
    intentionallyUnexecuted: requireBool(sink, doc, "intentionally_unexecuted"),
    executionStatus: undefined,
    failureClasses: [],
    capabilityPresent: requireBool(sink, doc, "capability_present"),
    violationDetected: requireBool(sink, doc, "violation_detected"),
    evidenceState: undefined,
    outcomes: [],
    cleanupVerified: requireBool(sink, doc, "cleanup_verified"),
    artifactsReferenceClosed: requireBool(sink, doc, "artifacts_reference_closed"),
    observersHealthy: requireBool(sink, doc, "observers_healthy"),
    mandatoryControlsPassed: requireBool(sink, doc, "mandatory_controls_passed"),
    unresolvedCriticalContradiction: requireBool(sink, doc, "unresolved_critical_contradiction"),
  };

  const es = doc["execution_status"];
  if (es === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.execution_status", 'missing mandatory field "execution_status"');
  } else if (!isExecutionStatus(es)) {
    sink.add(
      "V_INVALID_FIELD_TYPE",
      "$.execution_status",
      `must be one of ${EXECUTION_STATUS_VALUES.join(" | ")}`,
    );
  } else {
    view.executionStatus = es;
  }

  const fcRaw = doc["failure_classes"];
  if (fcRaw === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.failure_classes", 'missing mandatory field "failure_classes"');
  } else if (!Array.isArray(fcRaw)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.failure_classes", '"failure_classes" must be an array');
  } else {
    const classes: FailureClass[] = [];
    for (let i = 0; i < fcRaw.length; i++) {
      const c = fcRaw[i];
      if (!isFailureClass(c)) {
        sink.add(
          "V_INVALID_FIELD_TYPE",
          `$.failure_classes[${i}]`,
          `must be one of ${FAILURE_CLASS_VALUES.join(" | ")}`,
        );
      } else if (!classes.includes(c)) {
        classes.push(c);
      }
    }
    view.failureClasses = classes;
  }

  const evs = doc["evidence_state"];
  if (evs === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.evidence_state", 'missing mandatory field "evidence_state"');
  } else if (!isEvidenceState(evs)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.evidence_state", `must be one of ${EVIDENCE_STATE_VALUES.join(" | ")}`);
  } else {
    view.evidenceState = evs;
  }

  const po = doc["property_outcomes"];
  if (po === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.property_outcomes", 'missing mandatory field "property_outcomes"');
  } else if (!Array.isArray(po)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.property_outcomes", '"property_outcomes" must be an array');
  } else if (po.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.property_outcomes", "must contain at least one property outcome");
  } else {
    const outcomes: { propertyId: string; predicate: PropertyPredicate }[] = [];
    const seenIds = new Set<string>();
    for (let i = 0; i < po.length; i++) {
      const raw = po[i];
      const path = `$.property_outcomes[${i}]`;
      if (!isPlainObject(raw)) {
        sink.add("V_NOT_AN_OBJECT", path, "property outcome must be an object");
        continue;
      }
      for (const k of Object.keys(raw)) {
        if (!OUTCOME_ALLOWED_FIELDS.includes(k)) {
          sink.add("V_EXTRA_FIELD", `${path}.${k}`, `field "${k}" is not declared`);
        }
      }
      let pidOk = false;
      let pidValue = "";
      const pid = raw["property_id"];
      if (pid === undefined) {
        sink.add("V_MISSING_MANDATORY_FIELD", `${path}.property_id`, 'missing mandatory field "property_id"');
      } else {
        const r = checkRestrictedId(pid);
        if (!r.ok) {
          sink.add("V_INVALID_ID", `${path}.property_id`, r.reason);
        } else if (seenIds.has(r.value)) {
          sink.add("V_DUPLICATE_ID", `${path}.property_id`, `duplicate property_id "${r.value}"`);
        } else {
          seenIds.add(r.value);
          pidOk = true;
          pidValue = r.value;
        }
      }
      const pred = raw["predicate"];
      if (pred === undefined) {
        sink.add("V_MISSING_MANDATORY_FIELD", `${path}.predicate`, 'missing mandatory field "predicate"');
      } else if (!isPredicate(pred)) {
        sink.add(
          "V_INVALID_FIELD_TYPE",
          `${path}.predicate`,
          `must be one of ${PROPERTY_PREDICATE_VALUES.join(" | ")}`,
        );
      } else if (pidOk) {
        outcomes.push({ propertyId: pidValue, predicate: pred });
      }
    }
    view.outcomes = outcomes;
  }

  return view;
}

/**
 * Consistency gate: rejects forged combinations BEFORE any verdict exists.
 */
function consistencyIssues(view: PolicyInputView): PolicyIssue[] {
  const issues: PolicyIssue[] = [];
  const add = (message: string): void => {
    issues.push({ code: "V_INCONSISTENT_INPUT", path: "$", message });
  };

  if (view.intentionallyUnexecuted !== false && view.intentionallyUnexecuted !== undefined) {
    // Step-1 inputs skip most gates; nothing else may claim execution facts.
    const execFacts = [
      view.cleanupVerified,
      view.artifactsReferenceClosed,
      view.observersHealthy,
      view.mandatoryControlsPassed,
    ];
    if (execFacts.some((f) => f === true)) {
      add("intentionally_unexecuted input must not assert completed-run facts");
    }
    if ((view.violationDetected ?? false) || view.failureClasses.length > 0) {
      add("intentionally_unexecuted input must not carry failure classes or violations");
    }
  } else {
    const has = (c: FailureClass): boolean => view.failureClasses.includes(c);
    if (has("teardown") !== (view.cleanupVerified === false)) {
      add('failure class "teardown" must correspond exactly to cleanup_verified=false');
    }
    if (has("mandatory_observer") !== (view.observersHealthy === false)) {
      add('failure class "mandatory_observer" must correspond exactly to observers_healthy=false');
    }
    if (has("control") !== (view.mandatoryControlsPassed === false)) {
      add('failure class "control" must correspond exactly to mandatory_controls_passed=false');
    }
    if (has("integrity") !== (view.artifactsReferenceClosed === false)) {
      add('failure class "integrity" must correspond exactly to artifacts_reference_closed=false');
    }
    const anyViolationOutcome =
      view.outcomes.filter((o) => o.predicate === "violation").length > 0;
    if ((view.violationDetected ?? false) !== anyViolationOutcome) {
      add('violation_detected must equal "at least one property outcome with predicate violation"');
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type PolicyResult =
  | { readonly ok: true; readonly outcome: PolicyOutcome }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly PolicyIssue[] };

/**
 * Deterministically decide run_validity + scenario_verdict per §4 order 1–6.
 */
export function decideScenarioVerdict(doc: JsonValue): PolicyResult {
  const sink = createSink();
  const view = parseInput(doc, sink);
  if (sink.issues.length > 0) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }
  if (view === undefined) {
    // Version gate returned early; its issue is already recorded above.
    return { ok: false, stage: "validate", issues: sink.issues };
  }

  const inconsistent = consistencyIssues(view);
  if (inconsistent.length > 0) {
    return { ok: false, stage: "validate", issues: inconsistent };
  }

  const reasons: string[] = [];

  // Step 1 — intentionally unexecuted → not_run.
  if (view.intentionallyUnexecuted === true) {
    reasons.push("step1:intentionally_unexecuted");
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        scenario_verdict: "not_run",
        reasons,
      },
    };
  }

  // Step 2 — setup/containment/observer/integrity/correlation/control/
  // teardown failure, or blocked/aborted status ⇒ run_validity=invalid.
  if (
    view.failureClasses.length > 0 ||
    view.executionStatus === "blocked" ||
    view.executionStatus === "aborted"
  ) {
    if (view.failureClasses.length > 0) {
      reasons.push(`step2:failure_classes=${view.failureClasses.join("+")}`);
    }
    if (view.executionStatus === "blocked" || view.executionStatus === "aborted") {
      reasons.push(`step2:execution_status=${view.executionStatus}`);
    }
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        run_validity: "invalid",
        scenario_verdict: "invalid_run",
        reasons,
      },
    };
  }

  // Step 3 — valid run but absent declared capability → not_supported.
  if (view.capabilityPresent === false) {
    reasons.push("step3:capability_absent");
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        // Reaching step 3+ means the run passed step-2 validity checks;
        // the honest run_validity for every remaining branch is "valid".
        run_validity: "valid",
        scenario_verdict: "not_supported",
        reasons,
      },
    };
  }

  // Step 4 — valid evidence satisfies declared violation predicate → fail.
  if (view.violationDetected === true) {
    reasons.push("step4:violation_detected");
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        run_validity: "valid",
        scenario_verdict: "fail",
        reasons,
      },
    };
  }

  // Step 5 — evidence absent / contradictory / ambiguous / cannot
  // discriminate material explanations, or unresolved critical contradiction.
  if (
    view.evidenceState !== "present" ||
    view.unresolvedCriticalContradiction === true
  ) {
    reasons.push(`step5:evidence_state=${view.evidenceState ?? "unknown"}`);
    if (view.unresolvedCriticalContradiction === true) {
      reasons.push("step5:unresolved_critical_contradiction");
    }
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        run_validity: "valid",
        scenario_verdict: "inconclusive",
        reasons,
      },
    };
  }

  // Step 6 — pass only when every required property satisfies its declared
  // pass predicate AND all pass gates hold.
  const gatesOpen =
    view.executionStatus === "completed" &&
    view.cleanupVerified === true &&
    view.artifactsReferenceClosed === true &&
    view.observersHealthy === true &&
    view.mandatoryControlsPassed === true;

  if (!gatesOpen) {
    reasons.push("step6:pass_gates_not_satisfied");
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        run_validity: "valid",
        scenario_verdict: "inconclusive",
        reasons,
      },
    };
  }

  const allPass = view.outcomes.every((o) => o.predicate === "pass");
  if (!allPass) {
    reasons.push("step6:property_outcome_insufficient_evidence");
    return {
      ok: true,
      outcome: {
        aggregation_rule: VERDICT_AGGREGATION_RULE,
        run_validity: "valid",
        scenario_verdict: "inconclusive",
        reasons,
      },
    };
  }

  reasons.push("step6:all_properties_pass_all_gates_open");
  return {
    ok: true,
    outcome: {
      aggregation_rule: VERDICT_AGGREGATION_RULE,
      run_validity: "valid",
      scenario_verdict: "pass",
      reasons,
    },
  };
}

/**
 * Claim-admissibility ceiling (§4): a verdict alone never admits a claim.
 * `observerIndependenceComplete` may not be truthfully produced anywhere in
 * M0; it exists so the ceiling logic is explicit and testable.
 */
export function claimAdmissibilityCeiling(
  verdict: ScenarioVerdict,
  observerIndependenceComplete: boolean,
): ClaimAdmissibility {
  if (verdict !== "pass") return "inadmissible";
  return observerIndependenceComplete ? "admissible" : "downgraded";
}
