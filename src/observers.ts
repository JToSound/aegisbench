/**
 * AegisBench — observer declarations and independence vectors
 * (M1 Slice 3).
 *
 * Contract reference: MASTER_PROMPT.md §6 — per-observer declaration of
 * version/implementation digest/bootstrap provenance, observation plane,
 * enforcement capability, loss semantics; nine ownership custodies; host
 * privilege inventory; the nine-dimension independence vector; FCZ graph,
 * blind spots, liveness/health checks, fault injections. "Evidence is
 * independently corroborating only when …" — judged here mechanically.
 * "Do not use an ordinal independence score." — none exists in this module.
 *
 * Binding decisions pinned in docs/implementation-plan.md (M1 Slice 3).
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";
import type { LossSemantics } from "./events.ts";

export const SUPPORTED_OBSERVER_SCHEMA = "ab.observer-declaration/1";

export const OBSERVATION_PLANES = [
  "process_ipc",
  "filesystem",
  "api_boundary",
  "admin_plane",
  "network_loopback",
  "clock_service",
] as const;
export type ObservationPlane = (typeof OBSERVATION_PLANES)[number];

export const OWNER_CUSTODIES = [
  "process",
  "runtime",
  "admin_plane",
  "configuration",
  "artifact_writer",
  "clock",
  "policy_source",
  "fixture_source",
  "keys",
] as const;

export const HOST_PRIVILEGES = [
  "write",
  "read",
  "signal",
  "debug",
  "lifecycle",
  "configuration",
  "sockets",
  "mounts",
] as const;

export const INDEPENDENCE_DIMENSIONS = [
  "code",
  "configuration",
  "lifecycle",
  "data_path",
  "artifact_path",
  "clock",
  "policy",
  "administration",
  "key_custody",
] as const;

export type ObserverIssueCode =
  | "V_NOT_AN_OBJECT"
  | "V_UNKNOWN_SCHEMA_VERSION"
  | "V_MISSING_MANDATORY_FIELD"
  | "V_INVALID_FIELD_TYPE"
  | "V_EMPTY_ARRAY"
  | "V_EXTRA_FIELD"
  | "V_INVALID_ID"
  | "V_DUPLICATE_ID"
  | "V_UNRESOLVED_REFERENCE"
  | "V_INCONSISTENT_INPUT";

export interface ObserverIssue {
  readonly code: ObserverIssueCode;
  readonly path: string;
  readonly message: string;
}

export type ObserverValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly ObserverIssue[] };

const TOP_ALLOWED: readonly string[] = [
  "$schema",
  "observer_id",
  "version",
  "implementation_digest",
  "bootstrap_provenance",
  "source",
  "observation_plane",
  "enforcement_capability",
  "loss_semantics",
  "owners",
  "host_privileges",
  "independence_vector",
  "fcz_nodes",
  "fcz_edges",
  "blind_spots",
  "unmitigated_forge_suppress_fcz_ids",
  "liveness_checks",
  "health_checks",
  "fault_injections",
  "host_control_paths_declared",
];

const HEX_64_RE = /^[0-9a-f]{64}$/;
const ID_FIELDS: readonly string[] = ["observer_id", "version"];

interface Sink {
  readonly issues: ObserverIssue[];
  add(code: ObserverIssueCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: ObserverIssue[] = [];
  return { issues, add(code, path, message) { issues.push({ code, path, message }); } };
}

function isPlainObject(v: JsonValue): v is { readonly [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireAllFields(
  sink: Sink,
  obj: { readonly [key: string]: JsonValue },
  fields: readonly string[],
  parentPath: string,
): boolean {
  let ok = true;
  for (const f of fields) {
    if (obj[f] === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `${parentPath}.${f}`, `missing mandatory field "${f}"`);
      ok = false;
    }
  }
  return ok;
}

function requireBooleanMap(
  sink: Sink,
  raw: JsonValue,
  keys: readonly string[],
  path: string,
  what: string,
): boolean {
  if (!isPlainObject(raw)) {
    sink.add("V_INVALID_FIELD_TYPE", path, `"${what}" must be an object`);
    return false;
  }
  for (const k of Object.keys(raw)) {
    if (!keys.includes(k)) {
      sink.add("V_EXTRA_FIELD", `${path}.${k}`, `undeclared ${what} dimension "${k}"`);
    }
  }
  let allOk = true;
  for (const k of keys) {
    const v = raw[k];
    if (v === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `${path}.${k}`, `missing "${k}"`);
      allOk = false;
    } else if (typeof v !== "boolean") {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.${k}`, "must be a boolean");
      allOk = false;
    }
  }
  return allOk;
}

function requireStringMap(
  sink: Sink,
  raw: JsonValue,
  keys: readonly string[],
  path: string,
  what: string,
): boolean {
  if (!isPlainObject(raw)) {
    sink.add("V_INVALID_FIELD_TYPE", path, `"${what}" must be an object`);
    return false;
  }
  for (const k of Object.keys(raw)) {
    if (!keys.includes(k)) {
      sink.add("V_EXTRA_FIELD", `${path}.${k}`, `undeclared custody "${k}"`);
    }
  }
  let allOk = true;
  for (const k of keys) {
    const v = raw[k];
    if (v === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `${path}.${k}`, `missing custody "${k}"`);
      allOk = false;
    } else if (typeof v !== "string" || v.length === 0 || v.length > 256) {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.${k}`, "must be a non-empty principal ≤256 chars");
      allOk = false;
    }
  }
  return allOk;
}

/** Internal validated view used by the corroboration judgment. */
export interface ObserverView {
  readonly observerId: string;
  readonly observationPlane: ObservationPlane;
  readonly implementationDigestOk: boolean;
  readonly bootstrapProvenance: string;
  readonly fczIds: ReadonlySet<string>;
  readonly unmitigatedIds: ReadonlySet<string>;
  readonly livenessCount: number;
  readonly healthCount: number;
  readonly hostControlPathsEmpty: boolean;
  readonly debugOrLifecyclePrivilege: boolean;
  readonly independenceVectorComplete: boolean;
  readonly hasDemonstratingFaultInjection: boolean;
}

function parseDeclaration(doc: JsonValue, sink: Sink): ObserverView | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "observer declaration must be a JSON object");
    return undefined;
  }
  for (const k of Object.keys(doc)) {
    if (!TOP_ALLOWED.includes(k)) {
      sink.add("V_EXTRA_FIELD", `$.${k}`, `field "${k}" is not declared by ${SUPPORTED_OBSERVER_SCHEMA}`);
    }
  }

  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"');
  } else if (sv !== SUPPORTED_OBSERVER_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      "$.$schema",
      `unsupported schema version "${String(sv)}" (supported: ${SUPPORTED_OBSERVER_SCHEMA})`,
    );
    return undefined;
  }

  for (const f of ID_FIELDS) {
    const r = checkRestrictedId(doc[f]);
    if (!r.ok) {
      sink.add(
        doc[f] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID",
        `$.${f}`,
        doc[f] === undefined ? `missing mandatory field "${f}"` : (r.ok ? "" : r.reason),
      );
    }
  }
  const observerId = checkRestrictedId(doc["observer_id"]).ok ? String(doc["observer_id"]) : "";

  // implementation_digest shape (declared only).
  let implementationDigestOk = false;
  const idg = doc["implementation_digest"];
  if (idg === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.implementation_digest", 'missing mandatory field "implementation_digest"');
  } else if (!isPlainObject(idg)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.implementation_digest", "must be an object");
  } else {
    if (idg["algorithm"] !== "sha256") sink.add("V_INVALID_FIELD_TYPE", "$.implementation_digest.algorithm", 'must be "sha256"');
    if (typeof idg["label"] !== "string" || String(idg["label"]).length === 0) {
      sink.add("V_INVALID_FIELD_TYPE", "$.implementation_digest.label", "must be a non-empty string");
    }
    implementationDigestOk =
      idg["algorithm"] === "sha256" &&
      typeof idg["label"] === "string" &&
      typeof idg["value_hex"] === "string" &&
      HEX_64_RE.test(String(idg["value_hex"]));
    if (!implementationDigestOk && typeof idg["value_hex"] === "string") {
      sink.add("V_INVALID_FIELD_TYPE", "$.implementation_digest.value_hex", "must be 64 lowercase hex chars");
    }
  }

  for (const [key, maxLen] of [["bootstrap_provenance", 512], ["source", 256]] as const) {
    const v = doc[key];
    if (v !== undefined && (typeof v !== "string" || v.length === 0 || v.length > maxLen)) {
      sink.add("V_INVALID_FIELD_TYPE", `$.${key}`, `must be a non-empty string ≤${maxLen}`);
    }
  }

  const plane = doc["observation_plane"];
  const planeOk =
    typeof plane === "string" && (OBSERVATION_PLANES as readonly string[]).includes(plane);
  if (plane === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.observation_plane", 'missing mandatory field "observation_plane"');
  } else if (!planeOk) {
    sink.add("V_INVALID_FIELD_TYPE", "$.observation_plane", `must be one of ${OBSERVATION_PLANES.join(" | ")}`);
  }

  const ec = doc["enforcement_capability"];
  if (ec === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.enforcement_capability", 'missing mandatory field "enforcement_capability"');
  } else if (typeof ec !== "boolean") {
    sink.add("V_INVALID_FIELD_TYPE", "$.enforcement_capability", "must be a boolean");
  }

  const ls = doc["loss_semantics"];
  const LS = ["lossless", "lossy_bounded", "lossy_unbounded"];
  if (ls === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.loss_semantics", 'missing mandatory field "loss_semantics"');
  } else if (typeof ls !== "string" || !LS.includes(ls)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.loss_semantics", `must be one of ${LS.join(" | ")}`);
  }

  const ownersComplete = requireStringMap(sink, doc["owners"] ?? {}, OWNER_CUSTODIES, "$.owners", "owners");
  void ownersComplete;

  const hpRaw: JsonValue = doc["host_privileges"] ?? null;
  const hpOk = requireBooleanMap(sink, isPlainObject(hpRaw) ? hpRaw : {}, HOST_PRIVILEGES, "$.host_privileges", "host_privileges");

  const ivRaw: JsonValue = doc["independence_vector"] ?? null;
  const ivOk = requireBooleanMap(sink, isPlainObject(ivRaw) ? ivRaw : {}, INDEPENDENCE_DIMENSIONS, "$.independence_vector", "independence_vector");

  // FCZ graph.
  const fczIds = new Set<string>();
  let graphOk = true;
  const nodes = doc["fcz_nodes"];
  if (nodes === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.fcz_nodes", 'missing mandatory field "fcz_nodes"');
    graphOk = false;
  } else if (!Array.isArray(nodes)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.fcz_nodes", "must be an array");
    graphOk = false;
  } else if (nodes.length === 0) {
    sink.add("V_EMPTY_ARRAY", "$.fcz_nodes", "at least one FCZ node is required");
    graphOk = false;
  } else {
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const p = `$.fcz_nodes[${i}]`;
      if (!isPlainObject(n)) {
        sink.add("V_NOT_AN_OBJECT", p, "FCZ node must be an object");
        graphOk = false;
        continue;
      }
      for (const k of Object.keys(n)) {
        if (k !== "fcz_id" && k !== "description") sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      const r = checkRestrictedId(n["fcz_id"]);
      if (!r.ok) {
        sink.add(n["fcz_id"] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID", `${p}.fcz_id`, n["fcz_id"] === undefined ? 'missing mandatory field "fcz_id"' : (r.ok ? "" : r.reason));
        graphOk = false;
      } else {
        if (fczIds.has(r.value)) sink.add("V_DUPLICATE_ID", `${p}.fcz_id`, `duplicate fcz_id "${r.value}"`);
        fczIds.add(r.value);
      }
      if (typeof n["description"] !== "string" || n["description"].length === 0) {
        sink.add("V_INVALID_FIELD_TYPE", `${p}.description`, "must be a non-empty string");
        graphOk = false;
      }
    }
  }

  const edges = doc["fcz_edges"] ?? [];
  if (edges !== undefined && Array.isArray(edges)) {
    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      const p = `$.fcz_edges[${i}]`;
      if (!isPlainObject(e)) {
        sink.add("V_NOT_AN_OBJECT", p, "FCZ edge must be an object");
        continue;
      }
      for (const k of Object.keys(e)) {
        if (k !== "from_fcz_id" && k !== "to_fcz_id") sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      const from = checkRestrictedId(e["from_fcz_id"]);
      const to = checkRestrictedId(e["to_fcz_id"]);
      if (!from.ok) sink.add("V_INVALID_ID", `${p}.from_fcz_id`, e["from_fcz_id"] === undefined ? 'missing mandatory field "from_fcz_id"' : (from.ok ? "" : from.reason));
      if (!to.ok) sink.add("V_INVALID_ID", `${p}.to_fcz_id`, e["to_fcz_id"] === undefined ? 'missing mandatory field "to_fcz_id"' : (to.ok ? "" : to.reason));
      if (from.ok && !fczIds.has(from.value)) sink.add("V_UNRESOLVED_REFERENCE", `${p}.from_fcz_id`, `"${from.value}" does not resolve`);
      if (to.ok && !fczIds.has(to.value)) sink.add("V_UNRESOLVED_REFERENCE", `${p}.to_fcz_id`, `"${to.value}" does not resolve`);
    }
  } else if (edges !== undefined) {
    sink.add("V_INVALID_FIELD_TYPE", "$.fcz_edges", "must be an array when present");
    graphOk = false;
  }

  const blindSpots = doc["blind_spots"] ?? [];
  if (Array.isArray(blindSpots)) {
    for (let i = 0; i < blindSpots.length; i++) {
      const b = blindSpots[i];
      const p = `$.blind_spots[${i}]`;
      if (!isPlainObject(b)) {
        sink.add("V_NOT_AN_OBJECT", p, "blind spot must be an object");
        continue;
      }
      for (const k of Object.keys(b)) {
        if (k !== "fcz_id" && k !== "description") sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      if (b["fcz_id"] !== undefined) {
        const r = checkRestrictedId(b["fcz_id"]);
        if (!r.ok) sink.add("V_INVALID_ID", `${p}.fcz_id`, r.ok ? "" : r.reason);
        else if (!fczIds.has(r.value)) sink.add("V_UNRESOLVED_REFERENCE", `${p}.fcz_id`, `"${r.value}" does not resolve`);
      }
      if (typeof b["description"] !== "string" || b["description"].length === 0) {
        sink.add("V_INVALID_FIELD_TYPE", `${p}.description`, "must be a non-empty string");
      }
    }
  } else if (blindSpots !== undefined) {
    sink.add("V_INVALID_FIELD_TYPE", "$.blind_spots", "must be an array when present");
  }

  const unmitigatedIds = new Set<string>();
  const um = doc["unmitigated_forge_suppress_fcz_ids"];
  if (um === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.unmitigated_forge_suppress_fcz_ids", 'missing mandatory field');
  } else if (!Array.isArray(um)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.unmitigated_forge_suppress_fcz_ids", "must be an array");
  } else {
    for (let i = 0; i < um.length; i++) {
      const r = checkRestrictedId(um[i]);
      if (!r.ok) {
        sink.add(um[i] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID", `$.unmitigated_forge_suppress_fcz_ids[${i}]`, um[i] === undefined ? "missing entry" : (r.ok ? "" : r.reason));
      } else {
        if (!fczIds.has(r.value)) sink.add("V_UNRESOLVED_REFERENCE", `$.unmitigated_forge_suppress_fcz_ids[${i}]`, `"${r.value}" does not resolve`);
        unmitigatedIds.add(r.value);
      }
    }
  }

  const checks = (key: string): number => {
    const arr = doc[key];
    if (arr === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `$.${key}`, `missing mandatory field "${key}"`);
      return 0;
    }
    if (!Array.isArray(arr)) {
      sink.add("V_INVALID_FIELD_TYPE", `$.${key}`, "must be an array");
      return 0;
    }
    let count = 0;
    for (let i = 0; i < arr.length; i++) {
      const c = arr[i];
      const p = `$.${key}[${i}]`;
      if (!isPlainObject(c)) {
        sink.add("V_NOT_AN_OBJECT", p, "check entry must be an object");
        continue;
      }
      for (const k of Object.keys(c)) {
        if (k !== "check_id" && k !== "description") sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
      }
      const cid = checkRestrictedId(c["check_id"]);
      if (!cid.ok) sink.add(c["check_id"] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID", `${p}.check_id`, c["check_id"] === undefined ? 'missing mandatory field "check_id"' : (cid.ok ? "" : cid.reason));
      if (typeof c["description"] !== "string" || c["description"].length === 0) {
        sink.add("V_INVALID_FIELD_TYPE", `${p}.description`, "must be a non-empty string");
      }
      count++;
    }
    return count;
  };
  const livenessCount = checks("liveness_checks");
  const healthCount = checks("health_checks");
  void healthCount;

  let hasDemonstratingFaultInjection = false;
  const fi = doc["fault_injections"];
  if (fi === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.fault_injections", 'missing mandatory field "fault_injections"');
  } else if (!Array.isArray(fi)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.fault_injections", "must be an array");
  } else {
    for (let i = 0; i < fi.length; i++) {
      const f = fi[i];
      const p = `$.fault_injections[${i}]`;
      if (!isPlainObject(f)) {
        sink.add("V_NOT_AN_OBJECT", p, "fault injection must be an object");
        continue;
      }
      for (const k of Object.keys(f)) {
        if (k !== "fault_id" && k !== "description" && k !== "demonstrates_loss_cannot_yield_pass") {
          sink.add("V_EXTRA_FIELD", `${p}.${k}`, "undeclared field");
        }
      }
      const fid = checkRestrictedId(f["fault_id"]);
      if (!fid.ok) sink.add(f["fault_id"] === undefined ? "V_MISSING_MANDATORY_FIELD" : "V_INVALID_ID", `${p}.fault_id`, f["fault_id"] === undefined ? 'missing mandatory field "fault_id"' : (fid.ok ? "" : fid.reason));
      if (typeof f["description"] !== "string" || f["description"].length === 0) {
        sink.add("V_INVALID_FIELD_TYPE", `${p}.description`, "must be a non-empty string");
      }
      const dlc = f["demonstrates_loss_cannot_yield_pass"];
      if (dlc === undefined) {
        sink.add("V_MISSING_MANDATORY_FIELD", `${p}.demonstrates_loss_cannot_yield_pass`, "missing mandatory flag");
      } else if (typeof dlc !== "boolean") {
        sink.add("V_INVALID_FIELD_TYPE", `${p}.demonstrates_loss_cannot_yield_pass`, "must be a boolean");
      } else if (dlc === true) {
        hasDemonstratingFaultInjection = true;
      }
    }
  }

  const hcp = doc["host_control_paths_declared"];
  if (hcp === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.host_control_paths_declared", 'missing mandatory field "host_control_paths_declared"');
  } else if (!Array.isArray(hcp)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.host_control_paths_declared", "must be an array");
  } else if (hcp.some((x) => typeof x !== "string" || x.length === 0)) {
    sink.add("V_INVALID_FIELD_TYPE", "$.host_control_paths_declared[i]", "all entries must be non-empty strings");
  }

  const ivNarrowed = isPlainObject(ivRaw) ? ivRaw : undefined;
  const independenceVectorComplete =
    ivOk &&
    ivNarrowed !== undefined &&
    (INDEPENDENCE_DIMENSIONS as readonly string[]).every((k) => ivNarrowed[k] === true);

  const hpNarrowed = isPlainObject(hpRaw) ? hpRaw : undefined;
  const debugOrLifecycle =
    hpOk &&
    hpNarrowed !== undefined &&
    (hpNarrowed["debug"] === true || hpNarrowed["lifecycle"] === true);

  return {
    observerId,
    observationPlane: planeOk ? (plane as ObservationPlane) : "api_boundary",
    implementationDigestOk,
    bootstrapProvenance: typeof doc["bootstrap_provenance"] === "string" ? String(doc["bootstrap_provenance"]) : "",
    fczIds,
    unmitigatedIds,
    livenessCount,
    healthCount,
    hostControlPathsEmpty:
      hcp === undefined ? false : Array.isArray(hcp) ? hcp.length === 0 : false,
    debugOrLifecyclePrivilege: debugOrLifecycle,
    independenceVectorComplete,
    hasDemonstratingFaultInjection,
  };
}

/**
 * Validate an observer declaration document.
 */
export function validateObserverDeclaration(doc: JsonValue): ObserverValidationResult {
  const sink = createSink();
  parseDeclaration(doc, sink);
  if (sink.issues.length > 0) return { ok: false, stage: "validate", issues: sink.issues };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Corroboration judgment — five mechanical conditions, no ordinal score
// ---------------------------------------------------------------------------

export interface CorroborationFailure {
  /** Which §6 condition failed, e.g. "distinct_mechanisms". */
  readonly condition: string;
  readonly detail: string;
}

export type CorroborationJudgment =
  | { readonly independentlyCorroborating: true }
  | { readonly independentlyCorroborating: false; readonly failures: readonly CorroborationFailure[] };

/**
 * Judge whether two VALID observer declarations provide independently
 * corroborating evidence per §6's four clauses + trust-path declaration.
 * Both documents are fully revalidated first.
 */
export function isIndependentlyCorroborating(aDoc: JsonValue, bDoc: JsonValue): CorroborationJudgment {
  const failures: CorroborationFailure[] = [];

  const va = (() => {
    const sink = createSink();
    const view = parseDeclaration(aDoc, sink);
    return { view, issues: sink.issues };
  })();
  const vb = (() => {
    const sink = createSink();
    const view = parseDeclaration(bDoc, sink);
    return { view, issues: sink.issues };
  })();

  if (va.view === undefined || va.issues.length > 0) {
    failures.push({ condition: "valid_declaration_a", detail: `observer A has ${va.issues.length} structural issue(s)` });
  }
  if (vb.view === undefined || vb.issues.length > 0) {
    failures.push({ condition: "valid_declaration_b", detail: `observer B has ${vb.issues.length} structural issue(s)` });
  }
  if (failures.length > 0) return { independentlyCorroborating: false, failures };

  const a = va.view as ObserverView;
  const b = vb.view as ObserverView;

  // 1. Distinct mechanisms: different planes OR disjoint FCZ sets.
  const planesDiffer = a.observationPlane !== b.observationPlane;
  let disjointFcz = true;
  for (const id of a.fczIds) {
    if (b.fczIds.has(id)) {
      disjointFcz = false;
      break;
    }
  }
  if (!(planesDiffer || disjointFcz)) {
    failures.push({
      condition: "distinct_mechanisms",
      detail: `same plane "${a.observationPlane}" with overlapping FCZ ids`,
    });
  }

  // 2. No shared unmitigated forge/suppress/reinterpret FCZ.
  for (const id of a.unmitigatedIds) {
    if (b.unmitigatedIds.has(id)) {
      failures.push({ condition: "no_shared_unmitigated_fcz", detail: `both observers declare unmitigated FCZ "${id}"` });
      break;
    }
  }

  // 3. The host cannot control either required observer.
  const hostCannotControlA = a.hostControlPathsEmpty && !a.debugOrLifecyclePrivilege;
  const hostCannotControlB = b.hostControlPathsEmpty && !b.debugOrLifecyclePrivilege;
  if (!hostCannotControlA || !hostCannotControlB) {
    failures.push({
      condition: "host_cannot_control_observer",
      detail: `host control possible: A=${!hostCannotControlA}, B=${!hostCannotControlB}`,
    });
  }

  // 4. Trust paths declared for both.
  const trustA = a.bootstrapProvenance.length > 0 && a.implementationDigestOk && a.independenceVectorComplete;
  const trustB = b.bootstrapProvenance.length > 0 && b.implementationDigestOk && b.independenceVectorComplete;
  if (!trustA || !trustB) {
    failures.push({
      condition: "trust_paths_declared",
      detail: `provenance+digest+full independence vector: A=${trustA}, B=${trustB}`,
    });
  }

  // 5. Fault controls show loss/corruption cannot yield pass.
  if (!a.hasDemonstratingFaultInjection || !b.hasDemonstratingFaultInjection) {
    failures.push({
      condition: "loss_cannot_yield_pass",
      detail: `demonstrating fault injection present: A=${a.hasDemonstratingFaultInjection}, B=${b.hasDemonstratingFaultInjection}`,
    });
  }

  if (failures.length > 0) return { independentlyCorroborating: false, failures };
  return { independentlyCorroborating: true };
}
