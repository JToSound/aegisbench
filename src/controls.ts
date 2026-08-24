/**
 * AegisBench — measurement plans, control results, requirement matrix
 * (M1 Slice 4).
 *
 * Contract reference: MASTER_PROMPT.md §5 — each critical property requires a
 * versioned measurement plan binding subject version, action boundary,
 * interval, route model, observation planes, event grammar, ordering/clock
 * model, pass/fail/inconclusive predicates, and "positive, negative,
 * ambiguity, metamorphic, mutation, and fault controls". §4 supplies the
 * result-class vocabulary; the `control` failure class consumes the honest
 * outcome of applied control results.
 *
 * Binding decisions pinned in docs/implementation-plan.md (M1 Slice 4):
 *  - every plan declares ≥1 control of EACH of the six kinds;
 *  - control results are applied 1:1 against declared ids; any failed or
 *    not-run control is surfaced (never averaged away);
 *  - the requirement matrix is validated mechanically against plans.
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";

export const SUPPORTED_MEASUREMENT_PLAN_SCHEMA = "ab.measurement-plan/1";
export const SUPPORTED_REQUIREMENT_MATRIX_SCHEMA = "ab.requirement-matrix/1";

/** §5 exact control enumeration. */
export const CONTROL_KINDS = [
  "positive",
  "negative",
  "ambiguity",
  "metamorphic",
  "mutation",
  "fault",
] as const;
export type ControlKind = (typeof CONTROL_KINDS)[number];

/** §4 result classes, reused verbatim. */
export const RESULT_CLASSES = [
  "harness_integrity",
  "fixture_conformance",
  "adapter_observed_conformance",
  "host_validated_conformance",
  "research_observation",
] as const;
export type ResultClass = (typeof RESULT_CLASSES)[number];

/** Observation planes reused from observers.ts vocabulary. */
export const OBSERVATION_PLANES = [
  "process_ipc",
  "filesystem",
  "api_boundary",
  "admin_plane",
  "network_loopback",
  "clock_service",
] as const;

export const LOSS_SEMANTICS_VALUES = ["lossless", "lossy_bounded", "lossy_unbounded"] as const;

export type ControlsIssueCode =
  | "V_NOT_AN_OBJECT"
  | "V_UNKNOWN_SCHEMA_VERSION"
  | "V_MISSING_MANDATORY_FIELD"
  | "V_INVALID_FIELD_TYPE"
  | "V_EMPTY_ARRAY"
  | "V_EXTRA_FIELD"
  | "V_INVALID_ID"
  | "V_DUPLICATE_ID"
  | "V_UNRESOLVED_REFERENCE"
  | "V_INCONSISTENT_INPUT"
  | "V_CONTROL_KIND_MISSING"
  | "V_UNMAPPED_PLAN";

export interface ControlsIssue {
  readonly code: ControlsIssueCode;
  readonly path: string;
  readonly message: string;
}

export type ControlsValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly ControlsIssue[] };

const PLAN_ALLOWED: readonly string[] = [
  "$schema",
  "plan_id",
  "property_id",
  "subject_version_binding",
  "action_boundary",
  "ordering_model",
  "clock_source",
  "temporal_interval",
  "clock_uncertainty_ms",
  "loss_semantics",
  "route_inventory_ref",
  "observation_planes",
  "required_controls",
  "predicates",
  "permitted_result_classes",
];

const INTERVAL_ALLOWED: readonly string[] = ["start_utc", "end_utc"];
const CONTROL_ENTRY_ALLOWED: readonly string[] = ["control_id", "kind"];
const PREDICATES_ALLOWED: readonly string[] = ["pass", "fail", "inconclusive"];

const MATRIX_ALLOWED: readonly string[] = ["$schema", "matrix_id", "requirements", "mappings"];
const REQUIREMENT_ALLOWED: readonly string[] = ["requirement_id", "statement"];
const MAPPING_ALLOWED: readonly string[] = ["requirement_id", "plan_id"];

const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

interface Sink {
  readonly issues: ControlsIssue[];
  add(code: ControlsIssueCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: ControlsIssue[] = [];
  return { issues, add(code, path, message) { issues.push({ code, path, message }); } };
}

function isPlainObject(v: JsonValue): v is { readonly [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyString(v: JsonValue | undefined, maxLen = 256): boolean {
  return typeof v === "string" && v.length > 0 && v.length <= maxLen;
}

// ---------------------------------------------------------------------------
// Measurement plan
// ---------------------------------------------------------------------------

interface PlanView {
  readonly planId: string;
  readonly controlIds: ReadonlySet<string>;
}

function parsePlan(doc: JsonValue, sink: Sink): PlanView | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "measurement plan must be a JSON object");
    return undefined;
  }
  for (const k of Object.keys(doc)) {
    if (!PLAN_ALLOWED.includes(k)) {
      sink.add("V_EXTRA_FIELD", `$.${k}`, `field "${k}" is not declared by ${SUPPORTED_MEASUREMENT_PLAN_SCHEMA}`);
    }
  }
  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"');
  } else if (sv !== SUPPORTED_MEASUREMENT_PLAN_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      "$.$schema",
      `unsupported schema version "${String(sv)}" (supported: ${SUPPORTED_MEASUREMENT_PLAN_SCHEMA})`,
    );
    return undefined;
  }

  let planId = "";
  const pid = doc["plan_id"];
  if (pid === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.plan_id", 'missing mandatory field "plan_id"');
  } else {
    const r = checkRestrictedId(pid);
    if (!r.ok) sink.add("V_INVALID_ID", "$.plan_id", r.reason);
    else planId = r.value;
  }

  const propId = doc["property_id"];
  if (propId === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.property_id", 'missing mandatory field "property_id"');
  } else {
    const r = checkRestrictedId(propId);
    if (!r.ok) sink.add("V_INVALID_ID", "$.property_id", r.reason);
  }

  for (const key of ["subject_version_binding", "action_boundary", "ordering_model", "clock_source"] as const) {
    if (!nonEmptyString(doc[key])) {
      const v = doc[key];
      sink.add(
        v === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_FIELD_TYPE",
        `$.${key}`,
        v === undefined ? `missing mandatory field "${key}"` : `"${key}" must be a non-empty string ≤256`,
      );
    }
  }

  // Temporal interval.
  const ti = doc["temporal_interval"];
  let intervalOk = false;
  if (ti === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.temporal_interval", 'missing mandatory field "temporal_interval"');
  } else if (!isPlainObject(ti)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.temporal_interval", "must be an object");
  } else {
    for (const k of Object.keys(ti)) {
      if (!INTERVAL_ALLOWED.includes(k)) sink.add("V_EXTRA_FIELD", `$.temporal_interval.${k}`, "undeclared field");
    }
    const s = ti["start_utc"];
    const e = ti["end_utc"];
    let sOk = false;
    let eOk = false;
    if (s === undefined) sink.add("V_MISSING_MANDATORY_FIELD", "$.temporal_interval.start_utc", "missing start_utc");
    else if (typeof s !== "string" || !RFC3339_UTC_RE.test(s)) sink.add("V_INVALID_FIELD_TYPE", "$.temporal_interval.start_utc", "must match RFC 3339 UTC shape");
    else sOk = true;
    if (e === undefined) sink.add("V_MISSING_MANDATORY_FIELD", "$.temporal_interval.end_utc", "missing end_utc");
    else if (typeof e !== "string" || !RFC3339_UTC_RE.test(e)) sink.add("V_INVALID_FIELD_TYPE", "$.temporal_interval.end_utc", "must match RFC 3339 UTC shape");
    else eOk = true;
    if (sOk && eOk && Date.parse(String(s)) > Date.parse(String(e))) {
      sink.add("V_INCONSISTENT_INPUT", "$.temporal_interval.end_utc", "end must not precede start");
    } else if (sOk && eOk) {
      intervalOk = true;
    }
  }

  const unc = doc["clock_uncertainty_ms"];
  if (unc === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.clock_uncertainty_ms", 'missing mandatory field "clock_uncertainty_ms"');
  } else if (typeof unc !== "number" || !Number.isFinite(unc) || unc <= 0) {
    sink.add("V_INVALID_FIELD_TYPE", "$.clock_uncertainty_ms", "must be a finite number > 0");
  }

  const ls = doc["loss_semantics"];
  if (ls === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.loss_semantics", 'missing mandatory field "loss_semantics"');
  } else if (!(LOSS_SEMANTICS_VALUES as readonly string[]).includes(String(ls))) {
    sink.add("V_INVALID_FIELD_TYPE", "$.loss_semantics", `must be one of ${LOSS_SEMANTICS_VALUES.join(" | ")}`);
  }

  const rir = doc["route_inventory_ref"];
  if (rir === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.route_inventory_ref", 'missing mandatory field "route_inventory_ref"');
  } else {
    const r = checkRestrictedId(rir);
    if (!r.ok) sink.add("V_INVALID_ID", "$.route_inventory_ref", r.reason);
  }

  const planes = doc["observation_planes"];
  if (planes === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.observation_planes", 'missing mandatory field "observation_planes"');
  } else if (!Array.isArray(planes)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.observation_planes", "must be an array");
  } else if (planes.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.observation_planes", "at least one plane required");
  } else {
    planes.forEach((p, i) => {
      if (!(OBSERVATION_PLANES as readonly string[]).includes(String(p))) {
        sink.add("V_INVALID_FIELD_TYPE", `$.observation_planes[${i}]`, `must be one of ${OBSERVATION_PLANES.join(" | ")}`);
      }
    });
  }

  // Required controls: ≥1 of EACH kind, unique ids.
  const controlIds = new Set<string>();
  const kindsSeen = new Set<ControlKind>();
  const rc = doc["required_controls"];
  if (rc === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.required_controls", 'missing mandatory field "required_controls"');
  } else if (!Array.isArray(rc)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.required_controls", "must be an array");
  } else if (rc.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.required_controls", "at least one control required");
  } else {
    rc.forEach((entry, i) => {
      const p = `$.required_controls[${i}]`;
      if (!isPlainObject(entry)) {
        sink.add("V_NOT_AN_OBJECT", p, "control entry must be an object");
        return;
      }
      for (const k of Object.keys(entry)) {
        if (!CONTROL_ENTRY_ALLOWED.includes(k)) sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      const cid = entry["control_id"];
      const kind = entry["kind"];
      const cr = checkRestrictedId(cid);
      if (!cr.ok) {
        sink.add(cid === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID", `${p}.control_id`, cid === undefined ? 'missing mandatory field "control_id"' : (cr.ok ? "" : cr.reason));
      } else if (controlIds.has(cr.value)) {
        sink.add("V_DUPLICATE_ID", `${p}.control_id`, `duplicate control_id "${cr.value}"`);
      } else {
        controlIds.add(cr.value);
      }
      if (kind === undefined) {
        sink.add("V_MISSING_MANDATORY_FIELD", `${p}.kind`, 'missing mandatory field "kind"');
      } else if (!(CONTROL_KINDS as readonly string[]).includes(String(kind))) {
        sink.add("V_INVALID_FIELD_TYPE", `${p}.kind`, `must be one of ${CONTROL_KINDS.join(" | ")}`);
      } else {
        kindsSeen.add(kind as ControlKind);
      }
    });
    for (const k of CONTROL_KINDS) {
      if (!kindsSeen.has(k)) {
        sink.add(
          "V_CONTROL_KIND_MISSING",
          "$.required_controls",
          `no control of required kind "${k}" declared`,
        );
      }
    }
  }

  const pred = doc["predicates"];
  if (pred === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.predicates", 'missing mandatory field "predicates"');
  } else if (!isPlainObject(pred)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.predicates", "must be an object");
  } else {
    for (const k of Object.keys(pred)) {
      if (!PREDICATES_ALLOWED.includes(k)) sink.add("V_EXTRA_FIELD", `$.predicates.${k}`, "undeclared predicate");
    }
    for (const k of PREDICATES_ALLOWED) {
      if (!nonEmptyString(pred[k], 1024)) {
        sink.add(
          pred[k] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_FIELD_TYPE",
          `$.predicates.${k}`,
          pred[k] === undefined ? `missing mandatory predicate "${k}"` : `"${k}" must be a non-empty string ≤1024`,
        );
      }
    }
  }

  const prc = doc["permitted_result_classes"];
  if (prc === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.permitted_result_classes", 'missing mandatory field "permitted_result_classes"');
  } else if (!Array.isArray(prc)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.permitted_result_classes", "must be an array");
  } else if (prc.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.permitted_result_classes", "at least one class required");
  } else {
    prc.forEach((c, i) => {
      if (!(RESULT_CLASSES as readonly string[]).includes(String(c))) {
        sink.add("V_INVALID_FIELD_TYPE", `$.permitted_result_classes[${i}]`, `must be one of ${RESULT_CLASSES.join(" | ")}`);
      }
    });
  }

  void intervalOk;
  return { planId, controlIds };
}

/**
 * Validate a measurement-plan document.
 */
export function validateMeasurementPlan(doc: JsonValue): ControlsValidationResult {
  const sink = createSink();
  parsePlan(doc, sink);
  if (sink.issues.length > 0) return { ok: false, stage: "validate", issues: sink.issues };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Control-result application
// ---------------------------------------------------------------------------

export interface ControlResultEntry {
  readonly control_id: string;
  readonly outcome: "passed" | "failed" | "not_run";
}

export interface AppliedControlResults {
  /** Exactly one valid result per declared control, none failed. */
  readonly complete: boolean;
  readonly allPassed: boolean;
  readonly passedCount: number;
  readonly failedIds: readonly string[];
  readonly notRunIds: readonly string[];
  readonly missingIds: readonly string[];
  readonly unknownIds: readonly string[];
}

/**
 * Apply observed control outcomes to a plan's declared controls. Pure;
 * names every defect class separately. `!allPassed` feeds Slice 4b's
 * `control` failure class honestly — nothing is averaged or forgiven.
 */
export function applyControlResults(planDoc: JsonValue, results: readonly ControlResultEntry[]): AppliedControlResults {
  const sink = createSink();
  const view = parsePlan(planDoc, sink);
  const declared = view?.controlIds ?? new Set<string>();

  const failedIds: string[] = [];
  const notRunIds: string[] = [];
  const missingIds: string[] = [];
  const unknownIds: string[] = [];

  const seen = new Set<string>();
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r === undefined) continue;
    if (!declared.has(r.control_id)) {
      unknownIds.push(r.control_id);
      continue;
    }
    if (seen.has(r.control_id)) {
      unknownIds.push(r.control_id); // duplicate submission treated as unknown extra
      continue;
    }
    seen.add(r.control_id);
    if (r.outcome === "failed") failedIds.push(r.control_id);
    else if (r.outcome === "not_run") notRunIds.push(r.control_id);
  }
  for (const id of declared) {
    if (!seen.has(id)) missingIds.push(id);
  }

  const passedCount = declared.size - failedIds.length - notRunIds.length - missingIds.length;
  return {
    complete: missingIds.length === 0 && unknownIds.length === 0,
    allPassed:
      failedIds.length === 0 &&
      notRunIds.length === 0 &&
      missingIds.length === 0 &&
      unknownIds.length === 0 &&
      passedCount === declared.size &&
      declared.size > 0,
    passedCount,
    failedIds,
    notRunIds,
    missingIds,
    unknownIds,
  };
}

// ---------------------------------------------------------------------------
// Requirement-to-test matrix
// ---------------------------------------------------------------------------

function parseMatrix(doc: JsonValue, sink: Sink): { requirementIds: ReadonlySet<string>; mappings: ReadonlyArray<{ requirementId: string; planId: string }> } | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "requirement matrix must be a JSON object");
    return undefined;
  }
  for (const k of Object.keys(doc)) {
    if (!MATRIX_ALLOWED.includes(k)) {
      sink.add("V_EXTRA_FIELD", `$.${k}`, `field "${k}" is not declared by ${SUPPORTED_REQUIREMENT_MATRIX_SCHEMA}`);
    }
  }
  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"');
  } else if (sv !== SUPPORTED_REQUIREMENT_MATRIX_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      "$.$schema",
      `unsupported schema version "${String(sv)}" (supported: ${SUPPORTED_REQUIREMENT_MATRIX_SCHEMA})`,
    );
    return undefined;
  }

  let matrixOk = true;
  const mid = doc["matrix_id"];
  if (mid === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.matrix_id", 'missing mandatory field "matrix_id"');
    matrixOk = false;
  } else {
    const r = checkRestrictedId(mid);
    if (!r.ok) sink.add("V_INVALID_ID", "$.matrix_id", r.reason);
  }

  const requirementIds = new Set<string>();
  const reqs = doc["requirements"];
  if (reqs === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.requirements", 'missing mandatory field "requirements"');
    matrixOk = false;
  } else if (!Array.isArray(reqs)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.requirements", "must be an array");
    matrixOk = false;
  } else if (reqs.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.requirements", "at least one requirement required");
    matrixOk = false;
  } else {
    reqs.forEach((r, i) => {
      const p = `$.requirements[${i}]`;
      if (!isPlainObject(r)) {
        sink.add("V_NOT_AN_OBJECT", p, "requirement must be an object");
        return;
      }
      for (const k of Object.keys(r)) {
        if (!REQUIREMENT_ALLOWED.includes(k)) sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      const rid = checkRestrictedId(r["requirement_id"]);
      if (!rid.ok) {
        sink.add(r["requirement_id"] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID", `${p}.requirement_id`, r["requirement_id"] === undefined ? 'missing mandatory field "requirement_id"' : (rid.ok ? "" : rid.reason));
      } else if (requirementIds.has(rid.value)) {
        sink.add("V_DUPLICATE_ID", `${p}.requirement_id`, `duplicate requirement_id "${rid.value}"`);
      } else {
        requirementIds.add(rid.value);
      }
      if (!nonEmptyString(r["statement"], 2048)) {
        sink.add(
          r["statement"] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_FIELD_TYPE",
          `${p}.statement`,
          r["statement"] === undefined ? 'missing mandatory field "statement"' : '"statement" must be non-empty ≤2048',
        );
      }
    });
  }

  const mappings: { requirementId: string; planId: string }[] = [];
  const mapsRaw = doc["mappings"];
  if (mapsRaw === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.mappings", 'missing mandatory field "mappings"');
    matrixOk = false;
  } else if (!Array.isArray(mapsRaw)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.mappings", "must be an array");
    matrixOk = false;
  } else {
    mapsRaw.forEach((m, i) => {
      const p = `$.mappings[${i}]`;
      if (!isPlainObject(m)) {
        sink.add("V_NOT_AN_OBJECT", p, "mapping must be an object");
        return;
      }
      for (const k of Object.keys(m)) {
        if (!MAPPING_ALLOWED.includes(k)) sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      const rid = checkRestrictedId(m["requirement_id"]);
      const pid = checkRestrictedId(m["plan_id"]);
      if (!rid.ok) sink.add("V_INVALID_ID", `${p}.requirement_id`, rid.ok ? "" : rid.reason);
      if (!pid.ok) sink.add("V_INVALID_ID", `${p}.plan_id`, pid.ok ? "" : pid.reason);
      if (rid.ok && pid.ok) mappings.push({ requirementId: rid.value, planId: pid.value });
    });
  }

  if (!matrixOk) return undefined;
  return { requirementIds, mappings };
}

/**
 * Validate a requirement matrix against a map of plan documents
 * (plan_id → parsed document). Names EVERY defect: dangling refs, unmapped
 * requirements, unmapped plans, and structurally invalid plans.
 */
export function validateRequirementMatrix(matrixDoc: JsonValue, plansById: ReadonlyMap<string, JsonValue>): ControlsValidationResult {
  const sink = createSink();

  const m = parseMatrix(matrixDoc, sink);
  if (m === undefined) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }

  // Plan documents referenced must exist AND be structurally valid.
  for (const [pid, planDoc] of plansById) {
    const planSink = createSink();
    parsePlan(planDoc, planSink);
    if (planSink.issues.length > 0 || planDoc === null) {
      sink.add(
        "V_INVALID_FIELD_TYPE",
        `#plans.${pid}`,
        `referenced plan has ${planSink.issues.length} structural issue(s)`,
      );
    }
  }

  const mappedRequirements = new Set<string>();
  const mappedPlans = new Set<string>();
  for (const mapping of m.mappings) {
    if (!m.requirementIds.has(mapping.requirementId)) {
      sink.add(
        "V_UNRESOLVED_REFERENCE",
        "$.mappings",
        `mapping references unknown requirement "${mapping.requirementId}"`,
      );
      continue;
    }
    if (!plansById.has(mapping.planId)) {
      sink.add(
        "V_UNRESOLVED_REFERENCE",
        "$.mappings",
        `mapping references unknown plan "${mapping.planId}"`,
      );
      continue;
    }
    mappedRequirements.add(mapping.requirementId);
    mappedPlans.add(mapping.planId);
  }
  for (const rid of m.requirementIds) {
    if (!mappedRequirements.has(rid)) {
      sink.add("V_UNRESOLVED_REFERENCE", "#requirements", `requirement "${rid}" has no test mapping`);
    }
  }
  for (const pid of plansById.keys()) {
    if (!mappedPlans.has(pid)) {
      sink.add("V_UNMAPPED_PLAN", "#plans", `plan "${pid}" exists but is never mapped to a requirement`);
    }
  }

  if (sink.issues.length > 0) return { ok: false, stage: "validate", issues: sink.issues };
  return { ok: true };
}
