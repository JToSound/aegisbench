/**
 * Tests: AB-JCS-1 strict JSON parser (M0 Slice 1).
 * Required coverage: valid input, malformed JSON, duplicate keys,
 * plus limit/edge behavior pinned in docs/implementation-plan.md.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseStrict, STRICT_LIMITS } from "../src/json.ts";

function firstCode(text: string): string {
  const r = parseStrict(text);
  assert.equal(r.ok, false, `expected failure, got ok for: ${JSON.stringify(text.slice(0, 60))}`);
  if (r.ok) throw new Error("unreachable");
  assert.equal(r.errors.length, 1, "exactly one primary error expected");
  return (r.errors[0] as { code: string }).code;
}

test("valid input parses with correct structure and values", () => {
  const text = `{
    "$schema": "ab.evidence-envelope/1",
    "bundle_id": "bundle-2026-08-24-a",
    "created_utc": "2026-08-24T07:00:00Z",
    "note": "\\u20ac euro \\n newline \\u0041",
    "nested": { "arr": [1, 2.5, -1e3, true, false, null], "empty": {}, "list": [] }
  }`;
  const r = parseStrict(text);
  assert.ok(r.ok);
  if (!r.ok) return;
  const v = r.value as Record<string, unknown>;
  assert.equal(v["$schema"], "ab.evidence-envelope/1");
  const nested = v["nested"] as Record<string, unknown>;
  const arr = nested["arr"] as unknown[];
  assert.deepEqual(arr, [1, 2.5, -1000, true, false, null]);
  assert.equal(v["note"], "€ euro \n newline A");
});

test("malformed JSON is rejected with E_MALFORMED", () => {
  assert.equal(firstCode("{not json"), "E_MALFORMED");
  assert.equal(firstCode('{"a":}'), "E_MALFORMED");
  assert.equal(firstCode("[1,2"), "E_MALFORMED");
  assert.equal(firstCode('"unterminated'), "E_MALFORMED");
});

test("duplicate keys rejected before materialization, with path", () => {
  const r = parseStrict('{"id":"x","other":1,"id":"y"}');
  assert.ok(!r.ok);
  if (r.ok) return;
  const e = r.errors[0] as { code: string; path?: string };
  assert.equal(e.code, "E_DUPLICATE_KEY");
  assert.equal(e.path, "$.id");

  const deep = parseStrict('{"o":{"p":{"k":1,"k":2}}}');
  assert.ok(!deep.ok);
  if (deep.ok) return;
  const de = deep.errors[0] as { code: string; path?: string };
  assert.equal(de.code, "E_DUPLICATE_KEY");
  assert.equal(de.path, "$.o.p.k");
});

test("trailing content rejected", () => {
  assert.equal(firstCode("{} {}"), "E_TRAILING_CONTENT");
  assert.equal(firstCode("1 2"), "E_TRAILING_CONTENT");
});

test("empty input and BOM are rejected", () => {
  assert.equal(firstCode(""), "E_EMPTY_INPUT");
  assert.equal(firstCode("\uFEFF{}"), "E_BOM");
});

test("-0 and non-finite results are rejected", () => {
  assert.equal(firstCode("-0"), "E_NEGATIVE_ZERO");
  assert.equal(firstCode("-0.0"), "E_NEGATIVE_ZERO");
  assert.equal(firstCode("1e999"), "E_NONFINITE_NUMBER");
  assert.equal(firstCode("-1e999"), "E_NONFINITE_NUMBER");
});

test("lone surrogates rejected (escaped and raw)", () => {
  assert.equal(firstCode('"\\ud800"'), "E_LONE_SURROGATE");
  assert.equal(firstCode('"\\udc00"'), "E_LONE_SURROGATE");
  assert.equal(firstCode('"\\ud800x"'), "E_LONE_SURROGATE");
  // Raw unpaired surrogate embedded in the source text.
  assert.equal(firstCode(JSON.stringify("\uD800")), "E_LONE_SURROGATE");
});

test("paired surrogate escapes decode to the astral character", () => {
  const r = parseStrict('"\\ud83d\\ude00"');
  assert.ok(r.ok);
  if (r.ok) assert.equal(r.value, "😀");
});

test("depth limit: 64 containers ok, 65 rejected", () => {
  const ok64 = "[".repeat(STRICT_LIMITS.maxDepth) + "1" + "]".repeat(STRICT_LIMITS.maxDepth);
  const r64 = parseStrict(ok64);
  assert.ok(r64.ok);
  const bad65 = "[".repeat(STRICT_LIMITS.maxDepth + 1) + "1" + "]".repeat(STRICT_LIMITS.maxDepth + 1);
  assert.equal(firstCode(bad65), "E_DEPTH_EXCEEDED");
});

test("container member limit enforced", () => {
  const bigArray = "[" + "1,".repeat(STRICT_LIMITS.maxContainerMembers) + "1]";
  assert.equal(firstCode(bigArray), "E_CONTAINER_TOO_LARGE");
});

test("oversized string rejected", () => {
  const s = '"' + "a".repeat(STRICT_LIMITS.maxStringBytes + 1) + '"';
  assert.equal(firstCode(s), "E_STRING_TOO_LONG");
});

test("error position: line and column computed over CRLF input", () => {
  const text = '{\r\n  "a": tru}';
  const r = parseStrict(text);
  assert.ok(!r.ok);
  if (r.ok) return;
  const e = r.errors[0] as { code: string; line: number; column: number };
  assert.equal(e.code, "E_MALFORMED");
  assert.equal(e.line, 2);
  assert.equal(e.column, 8);
});

test("unescaped control characters in strings rejected", () => {
  assert.equal(firstCode('"a\u0007b"'), "E_CONTROL_CHAR_IN_STRING");
});

test("bad escapes rejected", () => {
  assert.equal(firstCode('"\\x41"'), "E_BAD_ESCAPE");
  assert.equal(firstCode('"\\u12g4"'), "E_BAD_ESCAPE");
});
