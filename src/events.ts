/**
 * AegisBench — versioned event envelope `ab.event/1` + trace invariants
 * (M0 Slice 3).
 *
 * Contract references: MASTER_PROMPT.md §6 (mandatory event fields),
 * §3 M0 ("normalized event envelope and decision trace" — envelope half),
 * §7 semantic invariants (unique IDs, no unresolved evidence references,
 * acyclic relations).
 *
 * Binding decisions pinned in docs/implementation-plan.md (Slice 3):
 *  - mandatory: event_id, correlation_nonce, producer_id, event_source,
 *    loss_semantics, payload, payload_digest;
 *  - optional: sequence (int 0..2^53-1), timestamp_utc (RFC 3339 UTC shape),
 *    timestamp_uncertainty_ms (requires timestamp_utc), causal_predecessors;
 *  - loss_semantics ∈ lossless | lossy_bounded | lossy_unbounded;
 *  - payload_digest = { algorithm:"sha256", label:"canonical_payload",
 *    value_hex:<64 lowercase hex> }; the verifier RECANONICALIZES payload and
 *    recomputes the Slice 2 domain digest — mismatch ⇒ V_DIGEST_MISMATCH.
 * Trace-level: unique event_id, resolvable non-self acyclic predecessors,
 * strictly increasing per-producer sequence in trace order.
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";
import { canonicalize, type CanonErrorCode } from "./canon.ts";
import {
  DIGEST_LABELS,
  canonicalPayloadDigest,
  verifyDigestHex,
} from "./digest.ts";
import type { SchemaErrorCode } from "./schema.ts";

/** The only event-envelope schema version this build understands. */
export const SUPPORTED_EVENT_SCHEMA = "ab.event/1";

/** Closed set of permitted loss-semantics values (§6 "event-loss semantics"). */
export const LOSS_SEMANTICS_VALUES = ["lossless", "lossy_bounded", "lossy_unbounded"] as const;
export type LossSemantics = (typeof LOSS_SEMANTICS_VALUES)[number];

export type EventIssueCode =
  | SchemaErrorCode
  | CanonErrorCode
  | "V_DIGEST_MISMATCH"
  | "V_CAUSAL_SELF_REFERENCE"
  | "V_CAUSAL_CYCLE"
  | "V_SEQUENCE_NOT_MONOTONIC";

export interface EventIssue {
  readonly code: EventIssueCode;
  readonly path: string;
  readonly message: string;
}

export type EventValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly EventIssue[] };

const EVENT_OK: EventValidationResult = { ok: true };

const EVENT_ALLOWED_FIELDS: readonly string[] = [
  "$schema",
  "event_id",
  "correlation_nonce",
  "producer_id",
  "event_source",
  "loss_semantics",
  "payload",
  "payload_digest",
  "sequence",
  "timestamp_utc",
  "timestamp_uncertainty_ms",
  "causal_predecessors",
];

const PAYLOAD_DIGEST_ALLOWED_FIELDS: readonly string[] = ["algorithm", "label", "value_hex"];

const HEX_64_RE = /^[0-9a-f]{64}$/;
/** Minimal RFC 3339 UTC shape gate; full calendar validation deferred. */
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER; // 2^53-1

interface Sink {
  readonly issues: EventIssue[];
  add(code: EventIssueCode, path: string, message: string): void;
}

function createSink(): Sink {
  const issues: EventIssue[] = [];
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

function rejectExtraFields(sink: Sink, obj: { readonly [key: string]: JsonValue }, allowed: readonly string[], parentPath: string): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      sink.add("V_EXTRA_FIELD", `${parentPath}.${k}`, `field "${k}" is not declared by ${SUPPORTED_EVENT_SCHEMA}`);
    }
  }
}

function requireStringField(sink: Sink, obj: { readonly [key: string]: JsonValue }, key: string, parentPath: string): boolean {
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

function requireRestrictedIdField(sink: Sink, obj: { readonly [key: string]: JsonValue }, key: string, parentPath: string): void {
  if (!requireStringField(sink, obj, key, parentPath)) return;
  const r = checkRestrictedId(obj[key]);
  if (!r.ok) sink.add("V_INVALID_ID", `${parentPath}.${key}`, r.reason);
}

/** Internal view of a validated-enough event for trace-level checks. */
interface EventView {
  readonly index: number;
  readonly path: string;
  eventId: string | undefined;
  producerId: string | undefined;
  sequence: number | undefined;
  predecessors: string[];
}

function validatePayloadDigestObject(
  sink: Sink,
  raw: JsonValue,
  path: string,
): { readonly valueHex: string } | undefined {
  if (!isPlainObject(raw)) {
    sink.add("V_INVALID_FIELD_TYPE", path, '"payload_digest" must be an object');
    return undefined;
  }
  rejectExtraFields(sink, raw, PAYLOAD_DIGEST_ALLOWED_FIELDS, path);
  let wellFormed = true;
  const algorithm = raw["algorithm"];
  if (algorithm !== "sha256") {
    sink.add("V_INVALID_FIELD_TYPE", `${path}.algorithm`, 'must be "sha256"');
    wellFormed = false;
  }
  const label = raw["label"];
  if (label !== DIGEST_LABELS.canonicalPayload) {
    sink.add("V_INVALID_FIELD_TYPE", `${path}.label`, `must be "${DIGEST_LABELS.canonicalPayload}"`);
    wellFormed = false;
  }
  const valueHex = raw["value_hex"];
  if (typeof valueHex !== "string" || !HEX_64_RE.test(valueHex)) {
    sink.add("V_INVALID_FIELD_TYPE", `${path}.value_hex`, "must be 64 lowercase hex chars");
    wellFormed = false;
  }
  return wellFormed && typeof valueHex === "string" ? { valueHex } : undefined;
}

function validateOneEvent(sink: Sink, event: JsonValue, path: string): EventView {
  const view: EventView = {
    index: Number(path.slice(path.lastIndexOf("[") + 1, path.lastIndexOf("]"))) || 0,
    path,
    eventId: undefined,
    producerId: undefined,
    sequence: undefined,
    predecessors: [],
  };
  if (!isPlainObject(event)) {
    sink.add("V_NOT_AN_OBJECT", path, "event must be a JSON object");
    return view;
  }
  rejectExtraFields(sink, event, EVENT_ALLOWED_FIELDS, path);

  // Versioned gate FIRST.
  const sv = event["$schema"];
  if (sv === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `${path}.$schema`, 'missing mandatory field "$schema"');
  } else if (typeof sv !== "string") {
    sink.add("V_SCHEMA_VERSION_NOT_STRING", `${path}.$schema`, '"$schema" must be a string');
  } else if (sv !== SUPPORTED_EVENT_SCHEMA) {
    sink.add(
      "V_UNKNOWN_SCHEMA_VERSION",
      `${path}.$schema`,
      `unsupported schema version "${sv}" (supported: ${SUPPORTED_EVENT_SCHEMA})`,
    );
    return view;
  }

  requireRestrictedIdField(sink, event, "event_id", path);
  requireRestrictedIdField(sink, event, "correlation_nonce", path);
  requireRestrictedIdField(sink, event, "producer_id", path);
  requireRestrictedIdField(sink, event, "event_source", path);

  const ls = event["loss_semantics"];
  if (ls === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `${path}.loss_semantics`, 'missing mandatory field "loss_semantics"');
  } else if (
    typeof ls !== "string" ||
    !(LOSS_SEMANTICS_VALUES as readonly string[]).includes(ls)
  ) {
    sink.add(
      "V_INVALID_FIELD_TYPE",
      `${path}.loss_semantics`,
      `must be one of ${LOSS_SEMANTICS_VALUES.join(" | ")}`,
    );
  }

  const payload = event["payload"];
  if (payload === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `${path}.payload`, 'missing mandatory field "payload"');
  }
  const digestObj = event["payload_digest"];
  if (digestObj === undefined) {
    sink.add("V_MISSING_MANDATORY_FIELD", `${path}.payload_digest`, 'missing mandatory field "payload_digest"');
  }

  // Integrity binding: recompute the AB-JCS-1 digest over the INLINE payload.
  if (payload !== undefined && digestObj !== undefined) {
    const parsed = validatePayloadDigestObject(sink, digestObj, `${path}.payload_digest`);
    if (parsed !== undefined) {
      const canon = canonicalize(payload);
      if (!canon.ok) {
        for (const ce of canon.errors) {
          sink.add(ce.code as EventIssueCode, `${path}.payload`, ce.message);
        }
      } else {
        const d = canonicalPayloadDigest(canon.canonicalText);
        if (!d.ok) {
          sink.add("V_DIGEST_MISMATCH", `${path}.payload_digest.value_hex`, "digest computation failed");
        } else if (!verifyDigestHex(parsed.valueHex, d.hex)) {
          sink.add(
            "V_DIGEST_MISMATCH",
            `${path}.payload_digest.value_hex`,
            "declared digest does not match recomputed AB-JCS-1 digest of inline payload",
          );
        }
      }
    }
  }

  const seqRaw = event["sequence"];
  if (seqRaw !== undefined) {
    if (
      typeof seqRaw !== "number" ||
      !Number.isInteger(seqRaw) ||
      seqRaw < 0 ||
      seqRaw > MAX_SEQUENCE
    ) {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.sequence`, "must be an integer between 0 and 2^53-1");
    } else {
      view.sequence = seqRaw;
    }
  }

  const tsRaw = event["timestamp_utc"];
  if (tsRaw !== undefined) {
    if (typeof tsRaw !== "string" || !RFC3339_UTC_RE.test(tsRaw)) {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.timestamp_utc`, "must match RFC 3339 UTC shape (…Z)");
    }
  }
  const uncRaw = event["timestamp_uncertainty_ms"];
  if (uncRaw !== undefined) {
    if (tsRaw === undefined) {
      sink.add(
        "V_MISSING_MANDATORY_FIELD",
        `${path}.timestamp_utc`,
        '"timestamp_uncertainty_ms" requires "timestamp_utc"',
      );
    }
    if (typeof uncRaw !== "number" || !Number.isFinite(uncRaw) || uncRaw <= 0) {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.timestamp_uncertainty_ms`, "must be a finite number > 0");
    }
  }

  const predsRaw = event["causal_predecessors"];
  if (predsRaw !== undefined) {
    if (!Array.isArray(predsRaw)) {
      sink.add("V_INVALID_FIELD_TYPE", `${path}.causal_predecessors`, "must be an array when present");
    } else {
      const preds: string[] = [];
      for (let i = 0; i < predsRaw.length; i++) {
        const r = checkRestrictedId(predsRaw[i]);
        if (!r.ok) {
          sink.add("V_INVALID_ID", `${path}.causal_predecessors[${i}]`, r.reason);
        } else {
          preds.push(r.value);
        }
      }
      view.predecessors = preds;
    }
  }

  const eid = event["event_id"];
  if (typeof eid === "string") view.eventId = eid;
  const pid = event["producer_id"];
  if (typeof pid === "string") view.producerId = pid;
  return view;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate a single event object against `ab.event/1`, including the inline
 * payload-digest integrity binding. Collects ALL violations.
 */
export function validateEvent(event: JsonValue): EventValidationResult {
  const sink = createSink();
  validateOneEvent(sink, event, "$");
  if (sink.issues.length > 0) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }
  return EVENT_OK;
}

/** Reports every second-and-later occurrence of an identical event_id. */
function reportDuplicateEventIds(sink: Sink, views: readonly EventView[]): void {
  const firstSeen = new Map<string, number>();
  for (let i = 0; i < views.length; i++) {
    const v = views[i] as EventView;
    if (v.eventId === undefined) continue;
    if (firstSeen.has(v.eventId)) {
      sink.add("V_DUPLICATE_ID", `${v.path}.event_id`, `duplicate event_id "${v.eventId}"`);
    } else {
      firstSeen.set(v.eventId, i);
    }
  }
}

function checkPredecessorResolution(sink: Sink, views: readonly EventView[]): void {
  const known = new Set<string>();
  for (const v of views) {
    if (v.eventId !== undefined) known.add(v.eventId);
  }
  for (const v of views) {
    for (let i = 0; i < v.predecessors.length; i++) {
      const p = v.predecessors[i] as string;
      if (p === v.eventId) {
        sink.add(
          "V_CAUSAL_SELF_REFERENCE",
          `${v.path}.causal_predecessors[${i}]`,
          `event "${p ?? "?"}" cannot be its own causal predecessor`,
        );
      } else if (!known.has(p)) {
        sink.add(
          "V_UNRESOLVED_REFERENCE",
          `${v.path}.causal_predecessors[${i}]`,
          `predecessor "${p}" does not resolve within this trace`,
        );
      }
    }
  }
}

/**
 * Deterministic DFS cycle detection over edges event→predecessor. Visits
 * nodes in trace order and predecessors in declaration order; reports the
 * first back-edge found, once.
 */
function detectCausalCycle(sink: Sink, views: readonly EventView[]): void {
  const byId = new Map<string, EventView>();
  for (const v of views) {
    if (v.eventId !== undefined && !byId.has(v.eventId)) byId.set(v.eventId, v);
  }
  const WHITE = 0;
  const GRAY = 1;
  const BLACK = 2;
  const color = new Map<EventView, number>();

  const visit = (v: EventView): boolean => {
    color.set(v, GRAY);
    for (let i = 0; i < v.predecessors.length; i++) {
      const target = byId.get(v.predecessors[i] as string);
      if (target === undefined) continue;
      const c = color.get(target) ?? WHITE;
      if (c === GRAY) {
        sink.add(
          "V_CAUSAL_CYCLE",
          `${target.path}.causal_predecessors`,
          `causal cycle detected at predecessor "${target.eventId ?? "?"}" of event "${v.eventId ?? "?"}"`,
        );
        return false; // stop at first back-edge
      }
      if (c === WHITE && !visit(target)) return false;
    }
    color.set(v, BLACK);
    return true;
  };

  for (const v of views) {
    if ((color.get(v) ?? WHITE) === WHITE && !visit(v)) return;
  }
}

function checkSequenceMonotonicity(sink: Sink, views: readonly EventView[]): void {
  const lastByProducer = new Map<string, number>();
  for (const v of views) {
    if (v.sequence === undefined || v.producerId === undefined) continue;
    const last = lastByProducer.get(v.producerId);
    if (last !== undefined && v.sequence <= last) {
      sink.add(
        "V_SEQUENCE_NOT_MONOTONIC",
        `${v.path}.sequence`,
        `sequence ${v.sequence} not greater than previous ${last} for producer "${v.producerId}" in trace order`,
      );
    }
    lastByProducer.set(v.producerId, v.sequence);
  }
}

/**
 * Validate an ordered list of events as an event trace: per-event schema +
 * integrity binding, then trace-level invariants (unique IDs, resolvable
 * non-self acyclic predecessors, per-producer monotonic sequences).
 */
export function validateEventTrace(events: readonly JsonValue[]): EventValidationResult {
  const sink = createSink();
  const views: EventView[] = [];
  for (let i = 0; i < events.length; i++) {
    views.push(validateOneEvent(sink, events[i] as JsonValue, `$.events[${i}]`));
  }
  reportDuplicateEventIds(sink, views);
  checkPredecessorResolution(sink, views);
  detectCausalCycle(sink, views);
  checkSequenceMonotonicity(sink, views);

  if (sink.issues.length > 0) {
    return { ok: false, stage: "validate", issues: sink.issues };
  }
  return EVENT_OK;
}

/**
 * Convenience for producers/tests: build a correct payload_digest object for
 * an arbitrary JSON value (canonicalizes, then applies the Slice 2 digest).
 */
export function buildPayloadDigest(
  payload: JsonValue,
): { readonly ok: true; readonly digest: { readonly algorithm: "sha256"; readonly label: string; readonly value_hex: string } } | { readonly ok: false; readonly stage: "digest"; readonly errors: readonly { readonly code: string; readonly message: string }[] } {
  const canon = canonicalize(payload);
  if (!canon.ok) {
    return { ok: false, stage: "digest", errors: canon.errors.map((e) => ({ code: e.code, message: e.message })) };
  }
  const d = canonicalPayloadDigest(canon.canonicalText);
  if (!d.ok) {
    return { ok: false, stage: "digest", errors: d.errors.map((e) => ({ code: e.code, message: e.message })) };
  }
  return {
    ok: true,
    digest: { algorithm: "sha256", label: DIGEST_LABELS.canonicalPayload, value_hex: d.hex },
  };
}
