/**
 * AegisBench — AB-JCS-1 domain-separated SHA-256 integrity digests (M0 Slice 2).
 *
 * Contract reference: MASTER_PROMPT.md §7 ("SHA-256 domain separation
 * labels") and §3 M0 ("SHA-256 domain-separated integrity digests").
 *
 * Normative byte layout (docs/implementation-plan.md, Slice 2):
 *
 *   digest = SHA-256( UTF8("AB-JCS-1")
 *                   || uint32be(byteLength(label))
 *                   || UTF8(label)
 *                   || uint32be(byteLength(payload))
 *                   || payload )
 *
 * Length prefixes make the (label, payload) split unambiguous. Digests detect
 * changes relative to known data; they prove neither authorship nor trusted
 * provenance (contract §7). Signatures/trust roots are later requirements.
 *
 * Zero dependencies. Erasable TS syntax only (Node 22 strip-only mode).
 */

import { createHash, timingSafeEqual } from "node:crypto";

/** Fixed domain prefix identifying the AegisBench AB-JCS-1 digest domain. */
export const DIGEST_DOMAIN_PREFIX = "AB-JCS-1";

/**
 * Registered digest labels (versioned registry; extend only by appending).
 * Each label names WHAT is hashed; consumers must use registry entries,
 * never ad-hoc strings, so artifacts stay verifiable across versions.
 */
export const DIGEST_LABELS = {
  /** Over the UTF-8 bytes of an AB-JCS-1 canonical text document. */
  canonicalPayload: "canonical_payload",
  /** Over the canonical text of a redaction ruleset document (Slice 4a). */
  redactionRuleset: "redaction_ruleset",
  /** Over the UTF-8 bytes of the mandatory assurance notice text (Slice 5a). */
  assuranceNotice: "assurance_notice",
  /** Over the canonical text of an approval binding-field set (M1 Slice 2). */
  approvalBinding: "approval_binding",
} as const;

/** Digest-label grammar: lowercase lead letter, then [a-z0-9_.-], max 64. */
export const DIGEST_LABEL_PATTERN = "^[a-z][a-z0-9_.-]{0,63}$";
const LABEL_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
const LABEL_MAX_LEN = 64;

const HEX_64_RE = /^[0-9a-f]{64}$/;

const utf8 = new TextEncoder();

export type DigestErrorCode = "D_INVALID_LABEL" | "D_LABEL_TOO_LONG" | "D_PAYLOAD_TYPE";

export interface DigestIssue {
  readonly code: DigestErrorCode;
  readonly message: string;
}

export type DigestResult =
  | { readonly ok: true; readonly label: string; readonly hex: string }
  | { readonly ok: false; readonly stage: "digest"; readonly errors: readonly DigestIssue[] };

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

type LabelCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: DigestErrorCode; readonly message: string };

function validateLabel(label: unknown): LabelCheck {
  if (typeof label !== "string") {
    return { ok: false, code: "D_INVALID_LABEL", message: "label must be a string" };
  }
  if (label.length > LABEL_MAX_LEN) {
    return {
      ok: false,
      code: "D_LABEL_TOO_LONG",
      message: `label exceeds ${LABEL_MAX_LEN} characters`,
    };
  }
  if (!LABEL_RE.test(label)) {
    return {
      ok: false,
      code: "D_INVALID_LABEL",
      message: `label must match ${DIGEST_LABEL_PATTERN}`,
    };
  }
  return { ok: true };
}

/**
 * Compute the AB-JCS-1 domain-separated SHA-256 of `payload` under `label`.
 * Deterministic and pure: identical inputs yield identical hex everywhere.
 */
export function domainDigestHex(label: string, payload: Uint8Array): DigestResult {
  const lv = validateLabel(label);
  if (!lv.ok) {
    return { ok: false, stage: "digest", errors: [{ code: lv.code, message: lv.message }] };
  }
  if (!ArrayBuffer.isView(payload)) {
    return {
      ok: false,
      stage: "digest",
      errors: [{ code: "D_PAYLOAD_TYPE", message: "payload must be a Uint8Array" }],
    };
  }
  const labelBytes = utf8.encode(label);
  const input = concat([
    utf8.encode(DIGEST_DOMAIN_PREFIX),
    u32be(labelBytes.length),
    labelBytes,
    u32be(payload.length),
    payload,
  ]);
  const hex = createHash("sha256").update(input).digest("hex");
  return { ok: true, label, hex };
}

/** Convenience: digest of AB-JCS-1 canonical text under its registered label. */
export function canonicalPayloadDigest(canonicalText: string): DigestResult {
  return domainDigestHex(DIGEST_LABELS.canonicalPayload, utf8.encode(canonicalText));
}

/**
 * Constant-time verification of two lowercase-hex digests.
 * Malformed expectations are a mismatch, never an exception.
 */
export function verifyDigestHex(expectedHex: string, actualHex: string): boolean {
  if (!HEX_64_RE.test(expectedHex) || !HEX_64_RE.test(actualHex)) return false;
  try {
    return timingSafeEqual(Buffer.from(expectedHex, "hex"), Buffer.from(actualHex, "hex"));
  } catch {
    return false;
  }
}
