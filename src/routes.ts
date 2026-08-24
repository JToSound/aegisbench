/**
 * AegisBench — route inventory and coverage-closure model (M1 Slice 1).
 *
 * Contract reference: MASTER_PROMPT.md §5 — "Routes use exactly
 * mediated_tested | mediated_untested | observed_only | excluded_declared |
 * unknown_possible | unsupported_by_subject"; "Only coverage_closed_for_route_set
 * may support a bounded negative claim. It SHALL name every included route,
 * excluded route, unknown_possible route, process identity assumption,
 * enforcement point, observer liveness evidence, interval, clock uncertainty,
 * and residual uncertainty."
 *
 * Binding decisions pinned in docs/implementation-plan.md (M1 Slice 1):
 *  - closure id lists are DERIVED mechanically from the paired inventory and
 *    validated by exact equality — no hand-maintained coverage lists;
 *  - `mediated_untested` / `unsupported_by_subject` ids appear in NO closure
 *    list: visibly uncovered by construction;
 *  - the bounded-negative-claim gate requires complete validation.
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";

export const SUPPORTED_ROUTE_INVENTORY_SCHEMA = "ab.route-inventory/1";
export const SUPPORTED_COVERAGE_CLOSURE_SCHEMA = "ab.coverage-closure/1";

/** §5 closed route vocabulary — exact strings, nothing else. */
export const ROUTE_CLASSIFICATIONS = [
  "mediated_tested",
  "mediated_untested",
  "observed_only",
  "excluded_declared",
  "unknown_possible",
  "unsupported_by_subject",
] as const;
export type RouteClassification = (typeof ROUTE_CLASSIFICATIONS)[number];

export type RouteIssueCode =
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
  | "V_ROUTE_LIST_MISMATCH";

export interface RouteIssue {
  readonly code: RouteIssueCode;
  readonly path: string;
  readonly message: string;
}

export type RouteValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly RouteIssue[] };

const INVENTORY_ALLOWED_FIELDS: readonly string[] = ["$schema", "inventory_id", "routes"];
const ROUTE_ENTRY_ALLOWED_FIELDS: readonly string[] = ["route_id", "classification", "description"];

const CLOSURE_ALLOWED_FIELDS: readonly string[] = [
  "$schema",
  "closure_id",
  "based_on_inventory_id",
  "included_routes",
  "excluded_routes",
  "unknown_possible_routes",
  "process_identity_assumption",
  "enforcement_point",
  "observer_liveness_evidence",
  "interval_start_utc",
  "interval_end_utc",
  "clock_uncertainty_ms",
  "residual_uncertainty",
];

const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

interface Sink {
  readonly issues: RouteIssue[];
  add(code: RouteIssueCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: RouteIssue[] = [];
  return { issues, add(code, path, message) { issues.push({ code, path, message }); } };
}

function isPlainObject(v: JsonValue): v is { readonly [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isClassification(v: JsonValue): v is RouteClassification {
  return typeof v === "string" && (ROUTE_CLASSIFICATIONS as readonly string[]).includes(v);
}

function rejectExtras(
  sink: Sink,
  obj: { readonly [key: string]: JsonValue },
  allowed: readonly string[],
  parentPath: string,
  schemaName: string,
): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      sink.add("V_EXTRA_FIELD", `${parentPath}.${k}`, `field "${k}" is not declared by ${schemaName}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

interface InventoryEntry {
  readonly routeId: string;
  readonly classification: RouteClassification;
}

interface InventoryView {
  readonly inventoryId: string;
  readonly entries: readonly InventoryEntry[];
}

/**
 * Validate a parsed document as `ab.route-inventory/1`.
 */
export function validateRouteInventory(doc: JsonValue): RouteValidationResult {
  const sink = createSink();
  parseInventory(doc, sink);
  if (sink.issues.length > 0) return { ok: false, stage: "validate", issues: sink.issues };
  return { ok: true };
}

function parseInventory(doc: JsonValue, sink: Sink): InventoryView | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "route inventory must be a JSON object");
    return undefined;
  }
  rejectExtras(sink, doc, INVENTORY_ALLOWED_FIELDS, "$", SUPPORTED_ROUTE_INVENTORY_SCHEMA);

  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"');
  } else if (sv !== SUPPORTED_ROUTE_INVENTORY_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      "$.$schema",
      `unsupported schema version "${String(sv)}" (supported: ${SUPPORTED_ROUTE_INVENTORY_SCHEMA})`,
    );
    return undefined;
  }

  let inventoryId = "";
  const invId = doc["inventory_id"];
  if (invId === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.inventory_id", 'missing mandatory field "inventory_id"');
  } else {
    const r = checkRestrictedId(invId);
    if (!r.ok) sink.add("V_INVALID_ID", "$.inventory_id", r.reason);
    else inventoryId = r.value;
  }

  const routesRaw = doc["routes"];
  if (routesRaw === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.routes", 'missing mandatory field "routes"');
    return undefined;
  }
  if (!Array.isArray(routesRaw)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.routes", '"routes" must be an array');
    return undefined;
  }
  if (routesRaw.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.routes", '"routes" must contain at least one entry');
    return undefined;
  }

  const entries: InventoryEntry[] = [];
  const seenIds = new Set<string>();
  for (let i = 0; i < routesRaw.length; i++) {
    const raw = routesRaw[i];
    const path = `$.routes[${i}]`;
    if (!isPlainObject(raw)) {
      sink.add("V_NOT_AN_OBJECT", path, "route entry must be an object");
      continue;
    }
    rejectExtras(sink, raw, ROUTE_ENTRY_ALLOWED_FIELDS, path, SUPPORTED_ROUTE_INVENTORY_SCHEMA);

    let routeId = "";
    const rid = raw["route_id"];
    if (rid === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `${path}.route_id`, 'missing mandatory field "route_id"');
    } else {
      const r = checkRestrictedId(rid);
      if (!r.ok) sink.add("V_INVALID_ID", `${path}.route_id`, r.reason);
      else if (seenIds.has(r.value)) {
        sink.add("V_DUPLICATE_ID", `${path}.route_id`, `duplicate route_id "${r.value}"`);
      } else {
        seenIds.add(r.value);
        routeId = r.value;
      }
    }

    const cls = raw["classification"];
    if (cls === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `${path}.classification`, 'missing mandatory field "classification"');
    } else if (!isClassification(cls)) {
      sink.add(
        "V_INVALID_FIELD_TYPE",
        `${path}.classification`,
        `must be one of ${ROUTE_CLASSIFICATIONS.join(" | ")}`,
      );
    } else if (routeId !== "") {
      entries.push({ routeId, classification: cls });
    }

    const desc = raw["description"];
    if (desc !== undefined && typeof desc !== "string") {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.description`, "must be a string when present");
    }
  }

  return { inventoryId, entries };
}

// ---------------------------------------------------------------------------
// Mechanical closure derivation
// ---------------------------------------------------------------------------

/** Classifications whose ids are INCLUDED in a coverage closure. */
const INCLUDED_CLASSIFICATIONS: readonly RouteClassification[] = ["mediated_tested", "observed_only"];

export interface CoverageClosureSkeleton {
  readonly $schema: typeof SUPPORTED_COVERAGE_CLOSURE_SCHEMA;
  readonly included_routes: readonly string[];
  readonly excluded_routes: readonly string[];
  readonly unknown_possible_routes: readonly string[];
}

/**
 * Mechanically derive the three id lists from a validated inventory, in
 * inventory order. `mediated_untested` and `unsupported_by_subject` appear in
 * NO list — visibly uncovered by construction.
 */
export function deriveCoverageClosureLists(view: InventoryView): Pick<CoverageClosureSkeleton, "included_routes" | "excluded_routes" | "unknown_possible_routes"> {
  const included: string[] = [];
  const excluded: string[] = [];
  const unknownPossible: string[] = [];
  for (const e of view.entries) {
    if (INCLUDED_CLASSIFICATIONS.includes(e.classification)) included.push(e.routeId);
    else if (e.classification === "excluded_declared") excluded.push(e.routeId);
    else if (e.classification === "unknown_possible") unknownPossible.push(e.routeId);
  }
  return { included_routes: included, excluded_routes: excluded, unknown_possible_routes: unknownPossible };
}

// ---------------------------------------------------------------------------
// Closure validation + bounded-negative-claim gate
// ---------------------------------------------------------------------------

function parseClosure(doc: JsonValue, sink: Sink): { closureId: string; basedOn: string; included: JsonValue; excluded: JsonValue; unknown: JsonValue } | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "coverage closure must be a JSON object");
    return undefined;
  }
  rejectExtras(sink, doc, CLOSURE_ALLOWED_FIELDS, "$", SUPPORTED_COVERAGE_CLOSURE_SCHEMA);

  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"');
  } else if (sv !== SUPPORTED_COVERAGE_CLOSURE_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      "$.$schema",
      `unsupported schema version "${String(sv)}" (supported: ${SUPPORTED_COVERAGE_CLOSURE_SCHEMA})`,
    );
    return undefined;
  }

  let closureId = "";
  const cid = doc["closure_id"];
  if (cid === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.closure_id", 'missing mandatory field "closure_id"');
  } else {
    const r = checkRestrictedId(cid);
    if (!r.ok) sink.add("V_INVALID_ID", "$.closure_id", r.reason);
    else closureId = r.value;
  }

  let basedOn = "";
  const bio = doc["based_on_inventory_id"];
  if (bio === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.based_on_inventory_id", 'missing mandatory field "based_on_inventory_id"');
  } else {
    const r = checkRestrictedId(bio);
    if (!r.ok) sink.add("V_INVALID_ID", "$.based_on_inventory_id", r.reason);
    else basedOn = r.value;
  }

  for (const key of ["included_routes", "excluded_routes", "unknown_possible_routes"] as const) {
    if (doc[key] === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `$.${key}`, `missing mandatory field "${key}"`);
    } else if (!Array.isArray(doc[key])) {
      sink.add("V_INVALID_FIELD_TYPE", `$.${key}`, `"${key}" must be an array`);
    }
  }

  for (const key of ["process_identity_assumption", "enforcement_point", "residual_uncertainty"] as const) {
    const v = doc[key];
    if (v === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `$.${key}`, `missing mandatory field "${key}"`);
    } else if (typeof v !== "string" || v.length === 0) {
      sink.add("V_INVALID_FIELD_TYPE", `$.${key}`, `"${key}" must be a non-empty string`);
    }
  }

  const live = doc["observer_liveness_evidence"];
  if (live === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.observer_liveness_evidence", 'missing mandatory field "observer_liveness_evidence"');
  } else if (!Array.isArray(live)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.observer_liveness_evidence", "must be an array");
  } else if (live.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.observer_liveness_evidence", "must contain at least one item");
  } else if (live.some((x) => typeof x !== "string" || x.length === 0)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.observer_liveness_evidence[i]", "all items must be non-empty strings");
  }

  const s = doc["interval_start_utc"];
  const e2 = doc["interval_end_utc"];
  let startOk = false;
  let endOk = false;
  if (s === undefined) sink.add("V_MISSING_MANDATORY_FIELD", "$.interval_start_utc", 'missing mandatory field "interval_start_utc"');
  else if (typeof s !== "string" || !RFC3339_UTC_RE.test(s)) sink.add("V_INVALID_FIELD_TYPE", "$.interval_start_utc", "must match RFC 3339 UTC shape (…Z)");
  else startOk = true;
  if (e2 === undefined) sink.add("V_MISSING_MANDATORY_FIELD", "$.interval_end_utc", 'missing mandatory field "interval_end_utc"');
  else if (typeof e2 !== "string" || !RFC3339_UTC_RE.test(e2)) sink.add("V_INVALID_FIELD_TYPE", "$.interval_end_utc", "must match RFC 3339 UTC shape (…Z)");
  else endOk = true;
  if (startOk && endOk && String(s) > String(e2)) {
    sink.add("V_INCONSISTENT_INPUT", "$.interval_end_utc", "interval_end_utc must not precede interval_start_utc");
  }

  const unc = doc["clock_uncertainty_ms"];
  if (unc === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.clock_uncertainty_ms", 'missing mandatory field "clock_uncertainty_ms"');
  } else if (typeof unc !== "number" || !Number.isFinite(unc) || unc <= 0) {
    sink.add("V_INVALID_FIELD_TYPE", "$.clock_uncertainty_ms", "must be a finite number > 0");
  }

  return {
    closureId,
    basedOn,
    included: doc["included_routes"] ?? [],
    excluded: doc["excluded_routes"] ?? [],
    unknown: doc["unknown_possible_routes"] ?? [],
  };
}

function idListIssues(sink: Sink, list: JsonValue, path: string): Set<string> {
  const ids = new Set<string>();
  if (!Array.isArray(list)) return ids;
  for (let i = 0; i < list.length; i++) {
    const r = checkRestrictedId(list[i]);
    if (!r.ok) {
      sink.add("V_INVALID_ID", `${path}[${i}]`, r.reason);
      continue;
    }
    if (ids.has(r.value)) {
      sink.add("V_DUPLICATE_ID", `${path}[${i}]`, `duplicate id "${r.value}" in ${path}`);
    } else {
      ids.add(r.value);
    }
  }
  return ids;
}

/**
 * Validate a coverage-closure document against its paired route inventory:
 * structure, narrative fields, exact equality of each derived id list, and
 * cross-list disjointness implied by the derivation.
 */
export function validateCoverageClosure(closureDoc: JsonValue, inventoryDoc: JsonValue): RouteValidationResult {
  const sink = createSink();
  const inv = parseInventory(inventoryDoc, sink);
  const clo = parseClosure(closureDoc, sink);
  // Early return ONLY when a document view is unusable (version gates).
  // Otherwise keep collecting: narrative issues must not hide list mismatches.
  if (inv === undefined || clo === undefined) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }

  // Reference integrity: closure must name its inventory.
  if (clo.basedOn !== "" && inv.inventoryId !== "" && clo.basedOn !== inv.inventoryId) {
    sink.add(
      "V_UNRESOLVED_REFERENCE",
      "$.based_on_inventory_id",
      `"${clo.basedOn}" does not match the provided inventory "${inv.inventoryId}"`,
    );
  }

  const expected = deriveCoverageClosureLists(inv);
  const includedSet = idListIssues(sink, clo.included, "$.included_routes");
  const excludedSet = idListIssues(sink, clo.excluded, "$.excluded_routes");
  const unknownSet = idListIssues(sink, clo.unknown, "$.unknown_possible_routes");

  const sameMembers = (a: ReadonlySet<string>, b: readonly string[]): boolean =>
    a.size === b.length && b.every((x) => a.has(x));

  if (!sameMembers(includedSet, expected.included_routes)) {
    sink.add(
      "V_ROUTE_LIST_MISMATCH",
      "$.included_routes",
      `expected [${expected.included_routes.join(", ")}] from inventory classifications mediated_tested/observed_only`,
    );
  }
  if (!sameMembers(excludedSet, expected.excluded_routes)) {
    sink.add(
      "V_ROUTE_LIST_MISMATCH",
      "$.excluded_routes",
      `expected [${expected.excluded_routes.join(", ")}] from classification excluded_declared`,
    );
  }
  if (!sameMembers(unknownSet, expected.unknown_possible_routes)) {
    sink.add(
      "V_ROUTE_LIST_MISMATCH",
      "$.unknown_possible_routes",
      `expected [${expected.unknown_possible_routes.join(", ")}] from classification unknown_possible`,
    );
  }

  // Disjointness: an id may appear in only one list.
  for (const x of includedSet) {
    if (excludedSet.has(x) || unknownSet.has(x)) {
      sink.add("V_INCONSISTENT_INPUT", "$.included_routes", `"${x}" appears in more than one closure list`);
    }
  }
  for (const x of excludedSet) {
    if (unknownSet.has(x)) {
      sink.add("V_INCONSISTENT_INPUT", "$.excluded_routes", `"${x}" appears in more than one closure list`);
    }
  }

  if (sink.issues.length > 0) return { ok: false, stage: "validate", issues: sink.issues };
  return { ok: true };
}

export type BoundedNegativeClaimSupport =
  | { readonly supported: true }
  | { readonly supported: false; readonly missing: readonly string[] };

/**
 * Gate: only a fully valid coverage closure supports a bounded negative
 * claim (§5). Every failed requirement is named in `missing[]`.
 */
export function supportsBoundedNegativeClaim(closureDoc: JsonValue, inventoryDoc: JsonValue): BoundedNegativeClaimSupport {
  const r = validateCoverageClosure(closureDoc, inventoryDoc);
  if (r.ok) return { supported: true };
  return {
    supported: false,
    missing: r.issues.map((i) => `${i.code} @ ${i.path}: ${i.message}`),
  };
}
