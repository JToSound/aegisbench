/**
 * AegisBench — restricted ASCII identifier syntax (M0 Slice 1).
 *
 * Contract reference: MASTER_PROMPT.md §7 — "restricted ASCII syntax for
 * security-sensitive IDs". Binding pattern pinned in
 * docs/implementation-plan.md: ^[A-Za-z][A-Za-z0-9_-]{0,127}$ .
 *
 * Pure functions only; no dependencies.
 */

export const RESTRICTED_ID_DESCRIPTION =
  "restricted identifier: 1-128 chars, starting with an ASCII letter, then ASCII letters, digits, '_' or '-'";

const RESTRICTED_ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,127}$/;

export type RestrictedIdResult =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Validate a security-sensitive identifier against the AB-JCS-1 restricted
 * ASCII syntax. Reasons are stable lowercase tokens suitable for reports.
 */
export function checkRestrictedId(raw: unknown): RestrictedIdResult {
  if (typeof raw !== "string") {
    return { ok: false, reason: "id_not_a_string" };
  }
  if (raw.length === 0) {
    return { ok: false, reason: "id_empty" };
  }
  if (!RESTRICTED_ID_RE.test(raw)) {
    return { ok: false, reason: `id_pattern_violation (${RESTRICTED_ID_DESCRIPTION})` };
  }
  return { ok: true, value: raw };
}
