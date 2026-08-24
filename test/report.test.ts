/**
 * Tests: report model with AB-NOTICE-001 binding (M0 Slice 5a).
 * Covers: builder always embeds the notice; independent validator rejects
 * missing/wrong id, tampered text, wrong digests, coupling violations;
 * human text carries the notice verbatim; redaction gate blocks canary
 * leaks with no partial artifact; determinism.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { JsonValue } from "../src/json.ts";
import {
  ASSURANCE_NOTICE_ID,
  ASSURANCE_NOTICE_TEXT,
  SUPPORTED_REPORT_SCHEMA,
  buildReportArtifact,
  finalizeReportArtifact,
  produceReport,
  validateReportArtifact,
} from "../src/report.ts";

const CANARY = "AB_CANARY_0123456789abcdef0123456789abcdef";

function validInput(): Parameters<typeof buildReportArtifact>[0] {
  return {
    reportId: "report-ref-0001",
    scenarioId: "scenario-benign-001",
    verdict: "pass",
    runValidity: "valid",
    aggregationRule: "ab.verdict-aggregation/1",
    reasons: ["step6:all_properties_pass_all_gates_open"],
    createdUtc: "2026-08-24T08:00:00Z",
    notes: "synthetic reference run",
  };
}

test("builder always embeds AB-NOTICE-001 and the full manifest", () => {
  const r = buildReportArtifact(validInput());
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.artifact.assurance_notice_id, ASSURANCE_NOTICE_ID);
  assert.equal(r.artifact.notice_manifest.notice_text, ASSURANCE_NOTICE_TEXT);
  assert.equal(
    r.artifact.notice_manifest.utf8_sha256_hex,
    createHash("sha256").update(Buffer.from(ASSURANCE_NOTICE_TEXT, "utf8")).digest("hex"),
  );
});

test("validator accepts a correctly built artifact (both verdict shapes)", () => {
  const pass = buildReportArtifact(validInput());
  assert.ok(pass.ok && validateReportArtifact(pass.artifact as unknown as JsonValue).ok);

  const { runValidity: _omit, ...rest } = validInput();
  const notRun = buildReportArtifact({
    ...rest,
    verdict: "not_run",
  });
  assert.ok(notRun.ok);
  if (!notRun.ok) return;
  assert.deepEqual(validateReportArtifact(notRun.artifact as unknown as JsonValue), { ok: true });
  assert.equal(notRun.artifact.run_validity, undefined);
});

test("coupling: not_run with run_validity rejected; non-not_run without it rejected", () => {
  const { runValidity: _drop, ...noValidity } = validInput();
  const r1 = buildReportArtifact({ ...validInput(), verdict: "not_run" as const });
  assert.ok(!r1.ok);
  const r2 = buildReportArtifact({ ...noValidity, verdict: "fail" });
  assert.ok(!r2.ok);
});

test("validator rejects missing or wrong assurance_notice_id", () => {
  const built = buildReportArtifact(validInput());
  assert.ok(built.ok);
  if (!built.ok) return;

  const stripped = JSON.parse(JSON.stringify(built.artifact)) as Record<string, unknown>;
  delete stripped["assurance_notice_id"];
  const v1 = validateReportArtifact(stripped as unknown as JsonValue);
  assert.ok(!v1.ok);
  if (!v1.ok) assert.ok(v1.issues.some((i) => i.path === "$.assurance_notice_id"));

  const wrong = { ...built.artifact, assurance_notice_id: "AB-NOTICE-002" };
  const v2 = validateReportArtifact(wrong as unknown as JsonValue);
  assert.ok(!v2.ok);
});

test("validator rejects tampered notice text and wrong digests", () => {
  const built = buildReportArtifact(validInput());
  assert.ok(built.ok);
  if (!built.ok) return;

  const tamperedText = {
    ...built.artifact,
    notice_manifest: { ...built.artifact.notice_manifest, notice_text: "everything is fine, trust us" },
  };
  const v1 = validateReportArtifact(tamperedText as unknown as JsonValue);
  assert.ok(!v1.ok);
  if (!v1.ok) assert.ok(v1.issues.some((i) => i.path === "$.notice_manifest.notice_text"));

  const wrongDigest = {
    ...built.artifact,
    notice_manifest: {
      ...built.artifact.notice_manifest,
      ab_jcs1_digest_hex: "0".repeat(64),
    },
  };
  const v2 = validateReportArtifact(wrongDigest as unknown as JsonValue);
  assert.ok(!v2.ok);
  if (!v2.ok) assert.ok(v2.issues.some((i) => i.code === "V_DIGEST_MISMATCH"));
});

test("human text renders the notice verbatim", () => {
  const produced = produceReport(validInput());
  assert.ok(produced.ok);
  if (!produced.ok) return;
  assert.ok(produced.finalized.humanText.includes(ASSURANCE_NOTICE_TEXT));
  assert.ok(produced.finalized.canonicalJson.includes(ASSURANCE_NOTICE_ID));
  // Canonical JSON round-trips to exactly the artifact object.
  const reparsed = JSON.parse(produced.finalized.canonicalJson) as JsonValue;
  assert.deepEqual(reparsed, produced.finalized.artifact as unknown as JsonValue);
});

test("redaction gate: canary in notes fails finalization with record only", () => {
  const produced = produceReport({ ...validInput(), notes: `leak ${CANARY}` });
  assert.ok(!produced.ok);
  if (produced.ok) return;
  const failure = produced as unknown as { stage: string; record?: { findings: Array<{ rule_id: string }>; clean: boolean } };
  assert.equal(failure.stage, "redaction");
  const rec = failure.record;
  assert.ok(rec !== undefined, "redaction failure must carry the scan record");
  if (rec === undefined) return;
  assert.equal(rec.clean, false);
  assert.ok(rec.findings.some((f) => f.rule_id === "canary_token"));
  // Finding metadata (rule id/offsets) may appear; raw matched value and any
  // artifact content must NOT escape through the failure result.
  const serialized = JSON.stringify(produced);
  assert.ok(!serialized.includes(CANARY));
  assert.ok(serialized.includes("canary_token")); // finding metadata allowed
  assert.ok(!serialized.includes('"artifact"')); // NO artifact object present
  assert.ok(!serialized.includes('"canonicalJson"'));
  assert.ok(!serialized.includes('"humanText"'));
  assert.ok(!serialized.includes("leak")); // the note text itself never escapes
});

test("finalize is deterministic: identical inputs give byte-identical outputs", () => {
  const a = produceReport(validInput());
  const b = produceReport(JSON.parse(JSON.stringify(validInput())) as Parameters<typeof buildReportArtifact>[0]);
  assert.ok(a.ok && b.ok);
  if (!(a.ok && b.ok)) return;
  assert.equal(a.finalized.canonicalJson, b.finalized.canonicalJson);
  assert.equal(a.finalized.humanText, b.finalized.humanText);
  assert.equal(JSON.stringify(a.finalized.redaction_scan), JSON.stringify(b.finalized.redaction_scan));
});

test("invalid IDs and malformed timestamps are refused at build time", () => {
  assert.ok(!buildReportArtifact({ ...validInput(), reportId: "9bad" }).ok);
  assert.ok(!buildReportArtifact({ ...validInput(), scenarioId: "has space" }).ok);
  assert.ok(!buildReportArtifact({ ...validInput(), createdUtc: "yesterday" }).ok);
});

test("extra fields make an otherwise-valid document fail validation", () => {
  const built = buildReportArtifact(validInput());
  assert.ok(built.ok);
  if (!built.ok) return;
  const padded = { ...built.artifact, bonus_claim: "we promise total safety" };
  const v = validateReportArtifact(padded as unknown as JsonValue);
  assert.ok(!v.ok);
  if (!v.ok) assert.ok(v.issues.some((i) => i.code === "V_EXTRA_FIELD"));
});
