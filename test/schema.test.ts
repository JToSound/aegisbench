/**
 * Tests: restricted-ID syntax, versioned schema validation, semantic
 * invariants (M0 Slice 1). Required coverage: valid input, unknown schema
 * version, missing mandatory fields, duplicate IDs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkRestrictedId } from "../src/ids.ts";
import {
  SUPPORTED_SCHEMA_VERSION,
  validateEnvelope,
} from "../src/schema.ts";
import { parseStrict } from "../src/json.ts";
import type { JsonValue } from "../src/json.ts";

// ---------------------------------------------------------------------------
// Restricted identifier syntax
// ---------------------------------------------------------------------------

test("restricted ID: accepted forms", () => {
  for (const good of ["a", "Z", "bundle-2026-08-24-a", "ab_x9", "A".repeat(128)]) {
    const r = checkRestrictedId(good);
    assert.ok(r.ok, `expected ok: ${good}`);
  }
});

test("restricted ID: rejected forms", () => {
  for (const bad of ["", "9lead-digit", "_underscore-first", "-dash-first", "has space", "hás-accent", "tab\tinside"]) {
    const r = checkRestrictedId(bad);
    assert.ok(!r.ok, `expected rejection: ${JSON.stringify(bad)}`);
  }
  const tooLong = "A".repeat(129);
  assert.ok(!checkRestrictedId(tooLong).ok);
  assert.equal(checkRestrictedId(42).ok, false);
});

// ---------------------------------------------------------------------------
// Envelope validation helpers
// ---------------------------------------------------------------------------

function validEnvelopeText(): string {
  return `{
    "$schema": "${SUPPORTED_SCHEMA_VERSION}",
    "bundle_id": "bundle-ref-0001",
    "created_utc": "2026-08-24T07:00:00Z",
    "scenarios": [
      { "id": "scenario-benign-001", "title": "Benign completion", "requirement_ids": ["REQ-HOST-010"] },
      { "id": "scenario-export-002", "title": "Export denial", "requirement_ids": ["REQ-BND-020", "REQ-OBS-011"] }
    ]
  }`;
}

function validateText(text: string) {
  const p = parseStrict(text);
  assert.ok(p.ok, `fixture must parse: ${text.slice(0, 80)}`);
  if (!p.ok) throw new Error("unreachable");
  return validateEnvelope(p.value as JsonValue);
}

function codesOf(result: ReturnType<typeof validateEnvelope>): string[] {
  if (result.ok) return [];
  return result.issues.map((i) => i.code);
}

test("valid envelope passes schema + semantic validation", () => {
  const r = validateText(validEnvelopeText());
  assert.deepEqual(r, { ok: true });
});

test("unknown schema version is rejected and gates further checks", () => {
  const text = validEnvelopeText().replace(SUPPORTED_SCHEMA_VERSION, "ab.evidence-envelope/99");
  const r = validateText(text);
  assert.ok(!r.ok);
  if (r.ok) return;
  assert.deepEqual(codesOf(r), ["V_UNKNOWN_SCHEMA_VERSION"]);
  assert.equal(r.issues[0]?.path, "$.$schema");
});

test("$schema version must be a string", () => {
  const r = validateText(validEnvelopeText().replace(`"${SUPPORTED_SCHEMA_VERSION}"`, "1"));
  assert.ok(!r.ok);
  if (r.ok) return;
  assert.ok(codesOf(r).includes("V_SCHEMA_VERSION_NOT_STRING"));
});

test("missing mandatory fields are each reported", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    scenarios: [{ id: "s-1", title: "t", requirement_ids: ["R1"] }],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  const issues = r.issues.filter((i) => i.code === "V_MISSING_MANDATORY_FIELD");
  const paths = issues.map((i) => i.path).sort();
  assert.deepEqual(paths, ["$.bundle_id", "$.created_utc"]);
});

test("missing mandatory scenario fields are reported", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    bundle_id: "b-1",
    created_utc: "2026-08-24T07:00:00Z",
    scenarios: [{ id: "s-1", requirement_ids: ["R1"] }, { title: "no id here", requirement_ids: ["R1"] }, { id: "s-3", title: "t" }],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  const missing = r.issues.filter((i) => i.code === "V_MISSING_MANDATORY_FIELD").map((i) => i.path);
  assert.ok(missing.includes("$.scenarios[0].title"));
  assert.ok(missing.includes("$.scenarios[1].id"));
  assert.ok(missing.includes("$.scenarios[2].requirement_ids"));
});

test("duplicate scenario IDs are reported at later occurrences", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    bundle_id: "b-1",
    created_utc: "2026-08-24T07:00:00Z",
    scenarios: [
      { id: "dup-1", title: "a", requirement_ids: ["R1"] },
      { id: "dup-1", title: "b", requirement_ids: ["R1"] },
      { id: "dup-1", title: "c", requirement_ids: ["R1"] },
    ],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  const dups = r.issues.filter((i) => i.code === "V_DUPLICATE_ID");
  assert.equal(dups.length, 2); // occurrences 2 and 3
  assert.deepEqual(dups.map((d) => d.path), ["$.scenarios[1].id", "$.scenarios[2].id"]);
});

test("IDs violating restricted ASCII syntax are reported", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    bundle_id: "9bad-start",
    created_utc: "2026-08-24T07:00:00Z",
    scenarios: [{ id: "has space", title: "t", requirement_ids: ["R1"] }],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  const badIds = r.issues.filter((i) => i.code === "V_INVALID_ID");
  assert.equal(badIds.length, 2);
});

test("undeclared (extra) fields are rejected", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    bundle_id: "b-1",
    created_utc: "2026-08-24T07:00:00Z",
    sneaky_field: true,
    scenarios: [{ id: "s-1", title: "t", requirement_ids: ["R1"], bonus: 1 }],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  const extras = r.issues.filter((i) => i.code === "V_EXTRA_FIELD").map((i) => i.path);
  assert.deepEqual(extras.sort(), ["$.scenarios[0].bonus", "$.sneaky_field"]);
});

test("empty arrays are rejected", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    bundle_id: "b-1",
    created_utc: "2026-08-24T07:00:00Z",
    scenarios: [],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  assert.ok(codesOf(r).includes("V_EMPTY_ARRAY"));

  const doc2 = JSON.parse(validEnvelopeText()) as { scenarios: Array<{ requirement_ids: string[] }> };
  doc2.scenarios[0]!.requirement_ids = [];
  const r2 = validateEnvelope(doc2 as unknown as JsonValue);
  assert.ok(!r2.ok);
  if (!r2.ok) assert.ok(codesOf(r2).includes("V_EMPTY_ARRAY"));
});

test("depends_on entries must satisfy restricted-ID syntax", () => {
  const doc = {
    $schema: SUPPORTED_SCHEMA_VERSION,
    bundle_id: "b-1",
    created_utc: "2026-08-24T07:00:00Z",
    scenarios: [{ id: "s-1", title: "t", requirement_ids: ["R1"] }],
    depends_on: ["ok-bundle", "BAD REF"],
  };
  const r = validateEnvelope(doc as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  const badIds = r.issues.filter((i) => i.code === "V_INVALID_ID");
  assert.equal(badIds.length, 1);
  assert.equal(badIds[0]?.path, "$.depends_on[1]");
});

test("non-object root is rejected", () => {
  const r = validateEnvelope([1, 2] as unknown as JsonValue);
  assert.ok(!r.ok);
  if (r.ok) return;
  assert.deepEqual(codesOf(r), ["V_NOT_AN_OBJECT"]);
});
