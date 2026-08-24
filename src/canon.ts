/**
 * AegisBench — AB-JCS-1 deterministic canonicalization interface (M0 Slice 1).
 *
 * Contract reference: MASTER_PROMPT.md §7 — AB-JCS-1 defines UTF-8, I-JSON
 * constraints, finite numbers, size limits, canonical field ordering, and
 * domain-separation labels. This slice delivers the canonicalization
 * INTERFACE plus its reference implementation skeleton; SHA-256
 * domain-separated digest consumption arrives in Slice 2.
 *
 * Binding decisions pinned in docs/implementation-plan.md:
 *  - output is UTF-8 text with no insignificant whitespace;
 *  - object members sorted lexicographically by UTF-16 code unit order
 *    (the ordering ECMAScript's default Array#sort applies to strings);
 *  - strings serialized with JSON.stringify's minimal escaping;
 *  - numbers use ECMAScript Number::toString shortest round-trip form,
 *    which RFC 8785 adopts verbatim, so AB-JCS-1 matches RFC 8785 output
 *    for every value inside RFC 8785's data model;
 *  - `-0` and non-finite numbers are rejected (never silently normalized).
 *
 * Pure module: no I/O, no clock, no randomness, zero dependencies.
 */

/**
 * Canonical JSON value type re-exported for downstream modules (canon owns
 * the canonical data model; json.ts keeps the input-layer view).
 */
export type { JsonValue } from "./json.ts";
import type { JsonValue } from "./json.ts";

import { STRICT_LIMITS } from "./json.ts";

export const CANON_PROFILE_ID = "AB-JCS-1";

/** Stable machine-readable failure codes for the canonicalizer. */
export type CanonErrorCode =
  | "C_NOT_FINITE"
  | "C_NEGATIVE_ZERO"
  | "C_DEPTH_EXCEEDED"
  | "C_CONTAINER_TOO_LARGE"
  | "C_STRING_TOO_LONG";

export type CanonError = {
  readonly code: CanonErrorCode;
  readonly message: string;
  readonly path: string;
};

export type CanonResult =
  | { readonly ok: true; readonly profile: typeof CANON_PROFILE_ID; readonly canonicalText: string }
  | {
      readonly ok: false;
      readonly stage: "canon";
      readonly errors: readonly CanonError[];
    };

function canonErr(code: CanonErrorCode, message: string, path: string): CanonError {
  const e: CanonError = { code, message, path };
  return e;
}

function serializeString(s: string): string {
  // JSON.stringify emits the shortest deterministic escape set (", \, and
  // control characters); it never emits lone surrogates for scalar inputs.
  return JSON.stringify(s);
}

function serializeNumber(n: number, path: string, errors: CanonError[]): string {
  if (!Number.isFinite(n)) {
    errors.push(canonErr("C_NOT_FINITE", "Non-finite number cannot be canonicalized", path));
    return "";
  }
  if (Object.is(n, -0)) {
    errors.push(canonErr("C_NEGATIVE_ZERO", "Negative zero is rejected by AB-JCS-1", path));
    return "";
  }
  return String(n);
}

function walk(
  value: JsonValue,
  path: string,
  depth: number,
  out: string[],
  errors: CanonError[],
): void {
  switch (typeof value) {
    case "string":
      if (Buffer.byteLength(value, "utf8") > STRICT_LIMITS.maxStringBytes) {
        errors.push(
          canonErr("C_STRING_TOO_LONG", `String exceeds ${STRICT_LIMITS.maxStringBytes} UTF-8 bytes`, path),
        );
        return;
      }
      out.push(serializeString(value));
      return;
    case "number":
      out.push(serializeNumber(value, path, errors));
      return;
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "object": {
      if (value === null) {
        out.push("null");
        return;
      }
      if (depth >= STRICT_LIMITS.maxDepth) {
        errors.push(
          canonErr("C_DEPTH_EXCEEDED", `Nesting exceeds maximum depth ${STRICT_LIMITS.maxDepth}`, path),
        );
        return;
      }
      if (Array.isArray(value)) {
        if (value.length > STRICT_LIMITS.maxContainerMembers) {
          errors.push(
            canonErr("C_CONTAINER_TOO_LARGE", `Array exceeds ${STRICT_LIMITS.maxContainerMembers} items`, path),
          );
          return;
        }
        const inner: string[] = [];
        for (let i = 0; i < value.length; i++) {
          walk(value[i] as JsonValue, `${path}[${i}]`, depth + 1, inner, errors);
        }
        out.push(`[${inner.join(",")}]`);
        return;
      }
      const keys = Object.keys(value).sort();
      if (keys.length > STRICT_LIMITS.maxContainerMembers) {
        errors.push(
          canonErr("C_CONTAINER_TOO_LARGE", `Object exceeds ${STRICT_LIMITS.maxContainerMembers} members`, path),
        );
        return;
      }
      const members: string[] = [];
      for (const k of keys) {
        const member: string[] = [];
        const memberValue = (value as { readonly [key: string]: JsonValue })[k] as JsonValue;
        walk(memberValue, `${path}.${k}`, depth + 1, member, errors);
        members.push(`${serializeString(k)}:${member.join("")}`);
      }
      out.push(`{${members.join(",")}}`);
      return;
    }
    default: {
      // `undefined` and functions cannot appear in parsed JSON; defensive.
      errors.push(canonErr("C_NOT_FINITE", "Unsupported value type in document", path));
      return;
    }
  }
}

/**
 * Canonicalize an in-memory JSON value under AB-JCS-1.
 *
 * The result depends only on the logical value: same value ⇒ identical UTF-8
 * bytes, independent of key insertion order or platform. Errors (if any) do
 * not truncate work — all violations in one document are collected.
 */
export function canonicalize(value: JsonValue): CanonResult {
  const errors: CanonError[] = [];
  const out: string[] = [];
  walk(value, "$", 0, out, errors);
  if (errors.length > 0) {
    return { ok: false, stage: "canon", errors };
  }
  return { ok: true, profile: CANON_PROFILE_ID, canonicalText: out.join("") };
}
