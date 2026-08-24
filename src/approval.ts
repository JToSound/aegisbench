/**
 * AegisBench — single-use integrity-bound approval capabilities
 * (M1 Slice 2).
 *
 * Contract reference: MASTER_PROMPT.md §6 — an approval SHALL bind approval/
 * issuer/subject/session/scenario IDs, policy version, action type,
 * canonicalization profile, exact normalized parameter digest, destination
 * identity, creation time, expiry, nonce, execution correlation, and
 * immutable consumption state; enforcement SHALL revalidate all bindings,
 * expiry, replay state, and consumption state immediately before the effect
 * boundary; any mismatch denies the action with redacted correlated evidence.
 *
 * Binding decisions pinned in docs/implementation-plan.md (M1 Slice 2):
 *  - `approval_digest` covers the binding-field set EXCLUDING the digest and
 *    the consumption tail (single-use flip never breaks binding integrity);
 *  - the boundary evaluation is pure and collects ALL violations;
 *  - denial records never interpolate request material into messages.
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { checkRestrictedId } from "./ids.ts";
import { canonicalize, type JsonValue } from "./canon.ts";
import { DIGEST_LABELS, domainDigestHex, verifyDigestHex } from "./digest.ts";

export const SUPPORTED_APPROVAL_SCHEMA = "ab.approval/1";
export const APPROVAL_CANON_PROFILE = "AB-JCS-1";

export type ApprovalIssueCode =
  | "V_NOT_AN_OBJECT"
  | "V_UNKNOWN_SCHEMA_VERSION"
  | "V_MISSING_MANDATORY_FIELD"
  | "V_INVALID_FIELD_TYPE"
  | "V_EXTRA_FIELD"
  | "V_INVALID_ID"
  | "V_DIGEST_MISMATCH"
  | "V_BINDING_MISMATCH"
  | "V_EXPIRED"
  | "V_NOT_YET_VALID"
  | "V_ALREADY_CONSUMED";

export interface ApprovalIssue {
  readonly code: ApprovalIssueCode;
  readonly path: string;
  readonly message: string;
}

export type ApprovalValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly ApprovalIssue[] };

export const APPROVAL_ALLOWED_FIELDS: readonly string[] = [
  "$schema",
  "approval_id",
  "issuer_id",
  "subject_id",
  "session_id",
  "scenario_id",
  "policy_version",
  "action_type",
  "canonicalization_profile",
  "parameter_digest",
  "destination_identity",
  "nonce",
  "execution_correlation",
  "created_utc",
  "expiry_utc",
  "approval_digest",
  "consumption_state",
];

const PARAMETER_DIGEST_ALLOWED_FIELDS: readonly string[] = ["algorithm", "label", "value_hex"];
const CONSUMPTION_ALLOWED_FIELDS: readonly string[] = ["consumed", "consumed_at_utc"];

const RESTRICTED_ID_FIELDS: readonly string[] = [
  "approval_id",
  "issuer_id",
  "subject_id",
  "session_id",
  "scenario_id",
  "policy_version",
  "action_type",
  "canonicalization_profile",
  "nonce",
  "execution_correlation",
];

/** Fields covered by the binding digest — everything except the two tails. */
const BINDING_FIELDS: readonly string[] = [
  "$schema",
  "approval_id",
  "issuer_id",
  "subject_id",
  "session_id",
  "scenario_id",
  "policy_version",
  "action_type",
  "canonicalization_profile",
  "parameter_digest",
  "destination_identity",
  "nonce",
  "execution_correlation",
  "created_utc",
  "expiry_utc",
];

const HEX_64_RE = /^[0-9a-f]{64}$/;
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function isPlainObject(v: JsonValue): v is { readonly [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Canonical text over ONLY the binding fields, in canonical key order. */
export function approvalBindingText(doc: { readonly [key: string]: JsonValue }): { readonly ok: true; readonly text: string } | { readonly ok: false } {
  const subset: Record<string, JsonValue> = {};
  for (const k of BINDING_FIELDS) {
    const v = doc[k];
    if (v === undefined) return { ok: false };
    subset[k] = v;
  }
  const c = canonicalize(subset);
  if (!c.ok) return { ok: false };
  return { ok: true, text: c.canonicalText };
}

function computeApprovalDigest(doc: { readonly [key: string]: JsonValue }): { readonly ok: true; readonly hex: string } | { readonly ok: false; readonly reason: string } {
  const b = approvalBindingText(doc);
  if (!b.ok) return { ok: false, reason: "binding fields missing or not canonicalizable" };
  const d = domainDigestHex(DIGEST_LABELS.approvalBinding, Buffer.from(b.text, "utf8"));
  if (!d.ok) return { ok: false, reason: d.errors[0]?.message ?? "digest failed" };
  return { ok: true, hex: d.hex };
}

interface Sink {
  readonly issues: ApprovalIssue[];
  add(code: ApprovalIssueCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: ApprovalIssue[] = [];
  return { issues, add(code, path, message) { issues.push({ code, path, message }); } };
}

// ---------------------------------------------------------------------------
// Structural validation (shape + integrity), shared by all entry points
// ---------------------------------------------------------------------------

function validateStructure(doc: JsonValue, sink: Sink): { readonly [key: string]: JsonValue } | undefined {
  if (!isPlainObject(doc)) {
    sink.add("V_NOT_AN_OBJECT", "$", "approval must be a JSON object");
    return undefined;
  }
  for (const k of Object.keys(doc)) {
    if (!APPROVAL_ALLOWED_FIELDS.includes(k)) {
      sink.add("V_EXTRA_FIELD", `$.${k}`, `field "${k}" is not declared by ${SUPPORTED_APPROVAL_SCHEMA}`);
    }
  }
  const sv = doc["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"');
  } else if (sv !== SUPPORTED_APPROVAL_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      "$.$schema",
      `unsupported schema version "${String(sv)}" (supported: ${SUPPORTED_APPROVAL_SCHEMA})`,
    );
    return undefined;
  }

  for (const f of BINDING_FIELDS) {
    if (f === "$schema") continue;
    if (doc[f] === undefined) {
      sink.add("V_MISSING_MANDATORY_FIELD", `$.${f}`, `missing mandatory field "${f}"`);
    }
  }
  if (doc["approval_digest"] === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.approval_digest", 'missing mandatory field "approval_digest"');
  }
  if (doc["consumption_state"] === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", "$.consumption_state", 'missing mandatory field "consumption_state"');
  }

  for (const f of RESTRICTED_ID_FIELDS) {
    const v = doc[f];
    if (v !== undefined) {
      const r = checkRestrictedId(v);
      if (!r.ok) sink.add("V_INVALID_ID", `$.${f}`, r.reason);
    }
  }

  const dest = doc["destination_identity"];
  if (dest !== undefined) {
    if (typeof dest !== "string" || dest.length === 0 || dest.length > 256 || /[\x00-\x1f\x7f]/.test(dest)) {
      sink.add("V_INVALID_FIELD_TYPE", "$.destination_identity", "must be a non-empty string ≤256 chars without ASCII control characters");
    }
  }

  for (const f of ["created_utc", "expiry_utc"] as const) {
    const v = doc[f];
    if (v !== undefined && (typeof v !== "string" || !RFC3339_UTC_RE.test(v))) {
      sink.add("V_INVALID_FIELD_TYPE", `$.${f}`, `"${f}" must match RFC 3339 UTC shape (…Z)`);
    }
  }

  const pd = doc["parameter_digest"];
  if (pd !== undefined) {
    if (!isPlainObject(pd)) {
      sink.add("V_INVALID_FIELD_TYPE", "$.parameter_digest", "must be an object");
    } else {
      for (const k of Object.keys(pd)) {
        if (!PARAMETER_DIGEST_ALLOWED_FIELDS.includes(k)) {
          sink.add("V_EXTRA_FIELD", `$.parameter_digest.${k}`, "undeclared field");
        }
      }
      if (pd["algorithm"] !== "sha256") {
        sink.add("V_INVALID_FIELD_TYPE", "$.parameter_digest.algorithm", 'must be "sha256"');
      }
      if (typeof pd["label"] !== "string" || pd["label"].length === 0) {
        sink.add("V_INVALID_FIELD_TYPE", "$.parameter_digest.label", "must be a non-empty string");
      }
      if (typeof pd["value_hex"] !== "string" || !HEX_64_RE.test(String(pd["value_hex"]))) {
        sink.add("V_INVALID_FIELD_TYPE", "$.parameter_digest.value_hex", "must be 64 lowercase hex chars");
      }
    }
  }

  const cs = doc["consumption_state"];
  if (cs !== undefined) {
    if (!isPlainObject(cs)) {
      sink.add("V_INVALID_FIELD_TYPE", "$.consumption_state", "must be an object");
    } else {
      for (const k of Object.keys(cs)) {
        if (!CONSUMPTION_ALLOWED_FIELDS.includes(k)) {
          sink.add("V_EXTRA_FIELD", `$.consumption_state.${k}`, "undeclared field");
        }
      }
      if (typeof cs["consumed"] !== "boolean") {
        sink.add("V_INVALID_FIELD_TYPE", "$.consumption_state.consumed", "must be a boolean");
      }
      if (cs["consumed_at_utc"] !== undefined && (typeof cs["consumed_at_utc"] !== "string" || !RFC3339_UTC_RE.test(String(cs["consumed_at_utc"])))) {
        sink.add("V_INVALID_FIELD_TYPE", "$.consumption_state.consumed_at_utc", "must match RFC 3339 UTC shape (…Z)");
      }
    }
  }

  // Integrity: recompute the binding digest.
  const dg = doc["approval_digest"];
  const recomputed = computeApprovalDigest(doc);
  if (dg !== undefined && recomputed.ok) {
    if (typeof dg !== "string" || !HEX_64_RE.test(dg) || !verifyDigestHex(recomputed.hex, dg)) {
      sink.add("V_DIGEST_MISMATCH", "$.approval_digest", "declared approval digest does not match the binding fields");
    }
  }

  // Ordering sanity when both timestamps are well-formed.
  const cRaw = doc["created_utc"];
  const eRaw = doc["expiry_utc"];
  if (
    typeof cRaw === "string" && RFC3339_UTC_RE.test(cRaw) &&
    typeof eRaw === "string" && RFC3339_UTC_RE.test(eRaw)
  ) {
    const created = Date.parse(cRaw);
    const expiry = Date.parse(eRaw);
    if (!(Number.isNaN(created) || Number.isNaN(expiry)) && expiry < created) {
      sink.add("V_INVALID_FIELD_TYPE", "$.expiry_utc", "expiry_utc must not precede created_utc");
    }
  }

  return isPlainObject(doc) ? doc : undefined;
}

/**
 * Validate an approval document's structure and self-integrity.
 */
export function validateApproval(doc: JsonValue): ApprovalValidationResult {
  const sink = createSink();
  const view = validateStructure(doc, sink);
  if (sink.issues.length > 0) return { ok: false, stage: "validate", issues: sink.issues };
  if (view === undefined) return { ok: false, stage: "validate", issues: sink.issues };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Issuance builder
// ---------------------------------------------------------------------------

export interface ApprovalIssuanceInput {
  readonly approvalId: string;
  readonly issuerId: string;
  readonly subjectId: string;
  readonly sessionId: string;
  readonly scenarioId: string;
  readonly policyVersion: string;
  readonly actionType: string;
  /** Canonical text of the exact approved parameters. */
  readonly parametersCanonicalText: string;
  readonly parameterDigestLabel?: string;
  readonly destinationIdentity: string;
  readonly nonce: string;
  readonly executionCorrelation: string;
  readonly createdUtc: string;
  readonly expiryUtc: string;
}

export function buildApproval(input: ApprovalIssuanceInput): { readonly ok: true; readonly approval: Record<string, JsonValue> } | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly ApprovalIssue[] } {
  // Digest of the approved parameters under their declared label.
  let paramDigest: string;
  try {
    const d = domainDigestHex(
      input.parameterDigestLabel ?? "canonical_payload",
      Buffer.from(input.parametersCanonicalText, "utf8"),
    );
    if (!d.ok) {
      return {
        ok: false,
        stage: "validate",
        issues: [{ code: "V_DIGEST_MISMATCH", path: "$.parameter_digest", message: d.errors[0]?.message ?? "digest failed" }],
      };
    }
    paramDigest = d.hex;
  } catch {
    return {
      ok: false,
      stage: "validate",
      issues: [{ code: "V_DIGEST_MISMATCH", path: "$.parameter_digest", message: "parameters must be provided as UTF-8 text" }],
    };
  }

  const base: Record<string, JsonValue> = {
    $schema: SUPPORTED_APPROVAL_SCHEMA,
    approval_id: input.approvalId,
    issuer_id: input.issuerId,
    subject_id: input.subjectId,
    session_id: input.sessionId,
    scenario_id: input.scenarioId,
    policy_version: input.policyVersion,
    action_type: input.actionType,
    canonicalization_profile: APPROVAL_CANON_PROFILE,
    parameter_digest: {
      algorithm: "sha256",
      label: input.parameterDigestLabel ?? "canonical_payload",
      value_hex: paramDigest,
    },
    destination_identity: input.destinationIdentity,
    nonce: input.nonce,
    execution_correlation: input.executionCorrelation,
    created_utc: input.createdUtc,
    expiry_utc: input.expiryUtc,
    consumption_state: { consumed: false },
  };

  const computed = computeApprovalDigest(base);
  if (!computed.ok) {
    return {
      ok: false,
      stage: "validate",
      issues: [{ code: "V_DIGEST_MISMATCH", path: "$.approval_digest", message: computed.reason }],
    };
  }
  const approval: Record<string, JsonValue> = { ...base, approval_digest: computed.hex };

  const sink = createSink();
  const view = validateStructure(approval, sink);
  if (sink.issues.length > 0 || view === undefined) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }
  return { ok: true, approval };
}

// ---------------------------------------------------------------------------
// Effect-boundary revalidation + single-use consumption
// ---------------------------------------------------------------------------

export interface EffectBoundaryRequest {
  readonly actionType: string;
  /** Canonical text of the ACTUAL parameters at the effect boundary. */
  readonly parametersCanonicalText: string;
  readonly destinationIdentity: string;
  readonly nowUtc: string;
  readonly executionCorrelation: string;
}

export type ApprovalDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly issues: readonly ApprovalIssue[] };

/**
 * Revalidation taken IMMEDIATELY BEFORE the effect boundary. Pure; collects
 * every violation; messages never embed request material.
 */
export function evaluateApprovalAtEffectBoundary(doc: JsonValue, req: EffectBoundaryRequest): ApprovalDecision {
  const sink = createSink();
  const fixedMessage = "request does not match the capability binding";
  const view = validateStructure(doc, sink);

  if (view !== undefined) {
    // Binding equalities (only meaningful on structurally valid documents).
    if (view["action_type"] !== req.actionType) {
      sink.add("V_BINDING_MISMATCH", "$.action_type", fixedMessage);
    }
    const pd = view["parameter_digest"];
    if (pd !== undefined && isPlainObject(pd) && typeof pd["label"] === "string") {
      const actual = domainDigestHex(pd["label"], Buffer.from(req.parametersCanonicalText, "utf8"));
      if (!actual.ok || !verifyDigestHex(String(pd["value_hex"]), actual.hex)) {
        sink.add("V_BINDING_MISMATCH", "$.parameter_digest", fixedMessage);
      }
    }
    if (view["destination_identity"] !== req.destinationIdentity) {
      sink.add("V_BINDING_MISMATCH", "$.destination_identity", fixedMessage);
    }
    if (view["execution_correlation"] !== req.executionCorrelation) {
      sink.add("V_BINDING_MISMATCH", "$.execution_correlation", fixedMessage);
    }

    const nowOk = typeof req.nowUtc === "string" && RFC3339_UTC_RE.test(req.nowUtc);
    if (!nowOk) {
      sink.add("V_BINDING_MISMATCH", "#request.now_utc", "request time must match RFC 3339 UTC shape (…Z)");
    } else {
      const now = Date.parse(req.nowUtc);
      const cRaw = view["created_utc"];
      const eRaw = view["expiry_utc"];
      if (typeof cRaw === "string" && RFC3339_UTC_RE.test(cRaw)) {
        if (now < Date.parse(cRaw)) sink.add("V_NOT_YET_VALID", "$.created_utc", "approval is not yet valid");
      }
      if (typeof eRaw === "string" && RFC3339_UTC_RE.test(eRaw)) {
        if (now > Date.parse(eRaw)) sink.add("V_EXPIRED", "$.expiry_utc", "approval has expired");
      }
    }

    const cs = view["consumption_state"];
    if (cs !== undefined && isPlainObject(cs) && cs["consumed"] === true) {
      sink.add("V_ALREADY_CONSUMED", "$.consumption_state.consumed", "single-use approval already consumed");
    }
  }

  if (sink.issues.length > 0) return { allowed: false, issues: sink.issues };
  return { allowed: true };
}

export function consumeApproval(doc: JsonValue, consumedAtUtc: string): { readonly ok: true; readonly consumed: Record<string, JsonValue> } | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly ApprovalIssue[] } {
  const sink = createSink();
  const view = validateStructure(doc, sink);
  if (view === undefined) return { ok: false, stage: "validate", issues: sink.issues };
  const cs = view["consumption_state"];
  if (cs !== undefined && isPlainObject(cs) && cs["consumed"] === true) {
    return {
      ok: false,
      stage: "validate",
      issues: [{ code: "V_ALREADY_CONSUMED", path: "$.consumption_state.consumed", message: "already consumed" }],
    };
  }
  if (!RFC3339_UTC_RE.test(consumedAtUtc)) {
    return {
      ok: false,
      stage: "validate",
      issues: [{ code: "V_INVALID_FIELD_TYPE", path: "#consumed_at_utc", message: "must match RFC 3339 UTC shape (…Z)" }],
    };
  }
  // Immutable update: new object; input untouched.
  const consumed: Record<string, JsonValue> = {
    ...(doc as { readonly [key: string]: JsonValue }),
    consumption_state: { consumed: true, consumed_at_utc: consumedAtUtc },
  };
  return { ok: true, consumed };
}
