/**
 * AegisBench — versioned schema + semantic validation (M0 Slice 1).
 *
 * Contract references: MASTER_PROMPT.md §3 M0 ("schema and semantic invariant
 * validation") and §7 ("Schema validation alone is insufficient"; unknown
 * schema versions and missing mandatory fields can never produce pass).
 *
 * Slice-1 envelope: `ab.evidence-envelope/1` — the minimal carrier that later
 * slices grow into a full evidence bundle. Validation is two-phase:
 *   phase A: structural schema check (types, mandatory fields, no undeclared
 *            fields);
 *   phase B: semantic invariants (restricted-ID syntax; ID uniqueness within
 *            their namespaces).
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";

/** The only bundle schema version this build understands. */
export const SUPPORTED_SCHEMA_VERSION = "ab.evidence-envelope/1";

/** Stable machine-readable failure codes emitted by this module. */
export type SchemaErrorCode =
  | "V_NOT_AN_OBJECT"
  | "V_MISSING_MANDATORY_FIELD"
  | "V_INVALID_FIELD_TYPE"
  | "V_EMPTY_ARRAY"
  | "V_UNKNOWN_SCHEMA_VERSION"
  | "V_SCHEMA_VERSION_NOT_STRING"
  | "V_INVALID_ID"
  | "V_DUPLICATE_ID"
  | "V_UNRESOLVED_REFERENCE"
  | "V_EXTRA_FIELD";

export interface ValidationIssue {
  readonly code: SchemaErrorCode;
  /** Dotted path to the offending location, e.g. `$.scenarios[1].id`. */
  readonly path: string;
  readonly message: string;
}

export type ValidationResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly stage: "validate";
      readonly issues: readonly ValidationIssue[];
    };

interface Sink {
  readonly issues: ValidationIssue[];
  add(code: SchemaErrorCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: ValidationIssue[] = [];
  return {
    issues,
    add(code, path, message) {
      issues.push({ code, path, message });
    },
  };
}

function isPlainObject(v: JsonValue): v is { readonly [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Structural helpers
// ---------------------------------------------------------------------------

function requireString(
  sink: Sink,
  obj: { readonly [key: string]: JsonValue },
  key: string,
  parentPath: string,
): boolean {
  const v = obj[key];
  if (v === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `${parentPath}.${key}`, `missing mandatory field "${key}"`);
    return false;
  }
  if (typeof v !== "string") {
    sink.add("V_INVALID_FIELD_TYPE", `${parentPath}.${key}`, `"${key}" must be a string`);
    return false;
  }
  return true;
}

/** Declared-key enforcement: any key outside `allowed` is reported. */
function rejectExtraFields(
  sink: Sink,
  obj: { readonly [key: string]: JsonValue },
  allowed: readonly string[],
  parentPath: string,
): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      sink.add(
        "V_EXTRA_FIELD",
        `${parentPath}.${k}`,
        `field "${k}" is not declared by ${SUPPORTED_SCHEMA_VERSION}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Semantic helpers
// ---------------------------------------------------------------------------

interface IdBinding {
  /** Namespace, e.g. "bundle", "scenario". */
  readonly namespace: string;
  readonly id: string;
  /** Where the ID was declared (for precise duplicate reporting). */
  readonly path: string;
}

function collectValidatedId(
  sink: Sink,
  raw: JsonValue,
  path: string,
  namespace: string,
  ids: IdBinding[],
): void {
  const r = checkRestrictedId(raw);
  if (!r.ok) {
    sink.add("V_INVALID_ID", path, r.reason);
    return;
  }
  ids.push({ namespace, id: r.value, path });
}

/** Reports every second-and-later occurrence of an identical (namespace,id). */
function reportDuplicateIds(sink: Sink, ids: readonly IdBinding[]): void {
  const firstSeen = new Map<string, number>();
  for (let i = 0; i < ids.length; i++) {
    const b = ids[i] as IdBinding;
    const k = `${b.namespace}:${b.id}`;
    if (firstSeen.has(k)) {
      sink.add(
        "V_DUPLICATE_ID",
        b.path,
        `duplicate id "${b.id}" in namespace "${b.namespace}"`,
      );
    } else {
      firstSeen.set(k, i);
    }
  }
}

// ---------------------------------------------------------------------------
// ab.evidence-envelope/1
// ---------------------------------------------------------------------------

const ROOT_ALLOWED_FIELDS: readonly string[] = [
  "$schema",
  "bundle_id",
  "created_utc",
  "scenarios",
  "depends_on",
];
const SCENARIO_ALLOWED_FIELDS: readonly string[] = ["id", "title", "requirement_ids"];

/**
 * {
 *   "$schema":       "ab.evidence-envelope/1",
 *   "bundle_id":     <restricted-id>,
 *   "created_utc":   <string>,
 *   "scenarios":     [ { "id": <restricted-id>,
 *                        "title": <string>,
 *                        "requirement_ids": [<string>, ... non-empty] }, ...
 *                      ] non-empty,
 *   "depends_on"?:   [ <restricted-id>, ... ]   // optional
 * }
 */
function validateScenario(sink: Sink, scenario: JsonValue, index: number, ids: IdBinding[]): void {
  const path = `$.scenarios[${index}]`;
  if (!isPlainObject(scenario)) {
    sink.add("V_NOT_AN_OBJECT", path, "scenario must be a JSON object");
    return;
  }
  rejectExtraFields(sink, scenario, SCENARIO_ALLOWED_FIELDS, path);
  if (requireString(sink, scenario, "id", path)) {
    collectValidatedId(sink, scenario["id"] as JsonValue, `${path}.id`, "scenario", ids);
  }
  requireString(sink, scenario, "title", path);
  const reqIds = scenario["requirement_ids"];
  if (reqIds === undefined) {
    sink.add(
      "V_MISSING_MANDATORY_FIELD",
      `${path}.requirement_ids`,
      'missing mandatory field "requirement_ids"',
    );
  } else if (!Array.isArray(reqIds)) {
    sink.add("V_INVALID_FIELD_TYPE", `${path}.requirement_ids`, '"requirement_ids" must be an array');
  } else if (reqIds.length === 0) {
    sink.add("V_EMPTY_ARRAY", `${path}.requirement_ids`, '"requirement_ids" must contain at least one entry');
  } else {
    for (let i = 0; i < reqIds.length; i++) {
      if (typeof reqIds[i] !== "string") {
        sink.add(
          "V_INVALID_FIELD_TYPE",
          `${path}.requirement_ids[${i}]`,
          "requirement_ids entries must be strings",
        );
      }
    }
  }
}

function validateStructure(sink: Sink, doc: JsonValue, ids: IdBinding[]): void {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "document must be a JSON object");
    return;
  }

  // Versioned gate FIRST: unknown versions never proceed to field checks.
  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `$.$schema`, 'missing mandatory field "$schema"');
  } else if (typeof sv !== "string") {
    sink.add("V_SCHEMA_VERSION_NOT_STRING", `$.$schema`, '"$schema" must be a string');
  } else if (sv !== SUPPORTED_SCHEMA_VERSION) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      `$.$schema`,
      `unsupported schema version "${sv}" (supported: ${SUPPORTED_SCHEMA_VERSION})`,
    );
    return;
  }

  rejectExtraFields(sink, doc, ROOT_ALLOWED_FIELDS, "$");

  if (requireString(sink, doc, "bundle_id", "$")) {
    collectValidatedId(sink, doc["bundle_id"] as JsonValue, "$.bundle_id", "bundle", ids);
  }
  requireString(sink, doc, "created_utc", "$");

  const scenariosRaw = doc["scenarios"];
  if (scenariosRaw === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.scenarios", 'missing mandatory field "scenarios"');
  } else if (!Array.isArray(scenariosRaw)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.scenarios", '"scenarios" must be an array');
  } else if (scenariosRaw.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.scenarios", '"scenarios" must contain at least one scenario');
  } else {
    for (let i = 0; i < scenariosRaw.length; i++) {
      validateScenario(sink, scenariosRaw[i] as JsonValue, i, ids);
    }
  }

  // Optional field with strict shape; entries use the restricted-ID syntax.
  const dependsOn = doc["depends_on"];
  if (dependsOn !== undefined) {
    if (!Array.isArray(dependsOn)) {
      sink.add("V_INVALID_FIELD_TYPE", "$.depends_on", '"depends_on" must be an array when present');
    } else {
      for (let i = 0; i < dependsOn.length; i++) {
        collectValidatedId(
          sink,
          dependsOn[i] as JsonValue,
          `$.depends_on[${i}]`,
          "bundle_ref",
          ids,
        );
      }
    }
  }
}

/**
 * Validate a parsed document against `ab.evidence-envelope/1` plus semantic
 * invariants. Collects ALL violations (does not stop at the first).
 *
 * Note (Slice 1 boundary): `V_UNRESOLVED_REFERENCE` is reserved for later
 * slices, where evidence cross-references exist to resolve. Within one
 * envelope there is nothing to resolve yet.
 */
export function validateEnvelope(doc: JsonValue): ValidationResult {
  const sink = createSink();
  const ids: IdBinding[] = [];
  validateStructure(sink, doc, ids);
  reportDuplicateIds(sink, ids);

  if (sink.issues.length > 0) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }
  return { ok: true };
}
