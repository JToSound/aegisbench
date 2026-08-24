/**
 * AegisBench — report model with AB-NOTICE-001 binding (M0 Slice 5a).
 *
 * Contract references: MASTER_PROMPT.md §0 — every verdict-bearing artifact
 * SHALL contain `"assurance_notice_id": "AB-NOTICE-001"`; the root manifest
 * SHALL bind the ID to the exact notice text and its declared UTF-8 SHA-256;
 * human-facing reports render the full notice verbatim. §7 — before accepting
 * an artifact, run the deterministic redaction scan.
 *
 * Binding decisions pinned in docs/implementation-plan.md (Slice 5a):
 *  - the manifest declares BOTH a raw UTF-8 SHA-256 and an AB-JCS-1 domain
 *    digest (label `assurance_notice`);
 *  - the builder has NO code path that omits the notice block; an
 *    independent validator re-checks id/text/digests and the
 *    run_validity⇔verdict coupling (absent exactly for not_run);
 *  - finalize renders canonical JSON + human text, redaction-scans both,
 *    and on any finding returns ONLY the scan record — no partial artifact.
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { createHash } from "node:crypto";
import { checkRestrictedId } from "./ids.ts";
import type { JsonValue } from "./json.ts";
import { canonicalize } from "./canon.ts";
import { DIGEST_LABELS, domainDigestHex, verifyDigestHex } from "./digest.ts";
import { scanForSecrets } from "./redact.ts";
import type { ScanRecord } from "./redact.ts";

/** The exact required notice text — verbatim from MASTER_PROMPT.md §0. */
export const ASSURANCE_NOTICE_ID = "AB-NOTICE-001" as const;

export const ASSURANCE_NOTICE_TEXT =
  "AegisBench evaluates observable behavior in synthetic, versioned test environments. A passing result is not a security guarantee, certification, or proof of production safety.";

export const SUPPORTED_REPORT_SCHEMA = "ab.report/1";

/** Raw SHA-256 over the UTF-8 notice bytes (universally recomputable). */
let cachedUtf8Sha256: string | undefined;
export function assuranceNoticeUtf8Sha256Hex(): string {
  if (cachedUtf8Sha256 === undefined) {
    cachedUtf8Sha256 = createHash("sha256").update(Buffer.from(ASSURANCE_NOTICE_TEXT, "utf8")).digest("hex");
  }
  return cachedUtf8Sha256;
}

/** AB-JCS-1 domain digest over the UTF-8 notice bytes. */
let cachedDomainDigest: string | undefined;
export function assuranceNoticeDomainDigestHex(): string {
  if (cachedDomainDigest === undefined) {
    const d = domainDigestHex(DIGEST_LABELS.assuranceNotice, Buffer.from(ASSURANCE_NOTICE_TEXT, "utf8"));
    if (!d.ok) throw new Error("notice digest computation failed");
    cachedDomainDigest = d.hex;
  }
  return cachedDomainDigest;
}

export const SCENARIO_VERDICT_VALUES = [
  "pass",
  "fail",
  "inconclusive",
  "invalid_run",
  "not_supported",
  "not_run",
] as const;
export type ScenarioVerdict = (typeof SCENARIO_VERDICT_VALUES)[number];

const RUN_VALIDITY_VALUES = ["valid", "invalid"] as const;
type RunValidity = (typeof RUN_VALIDITY_VALUES)[number];

export interface NoticeManifest {
  readonly notice_id: typeof ASSURANCE_NOTICE_ID;
  readonly notice_text: string;
  readonly utf8_sha256_hex: string;
  readonly ab_jcs1_digest_hex: string;
}

export interface ReportArtifactInput {
  readonly reportId: string;
  readonly scenarioId: string;
  readonly verdict: ScenarioVerdict;
  /** Required unless verdict === "not_run"; forbidden when it is. */
  readonly runValidity?: RunValidity;
  readonly aggregationRule: string;
  readonly reasons: readonly string[];
  readonly bundleId?: string;
  /** RFC 3339 UTC shape when present. */
  readonly createdUtc?: string;
  readonly notes?: string;
}

export interface ReportArtifact {
  readonly $schema: "ab.report/1";
  readonly report_id: string;
  readonly scenario_id: string;
  readonly verdict: ScenarioVerdict;
  readonly run_validity?: RunValidity;
  readonly aggregation_rule: string;
  readonly reasons: readonly string[];
  readonly assurance_notice_id: typeof ASSURANCE_NOTICE_ID;
  readonly notice_manifest: NoticeManifest;
  readonly bundle_id?: string;
  readonly created_utc?: string;
  readonly notes?: string;
}

export interface FinalizedReport {
  readonly artifact: ReportArtifact;
  /** AB-JCS-1 canonical JSON text of the artifact. */
  readonly canonicalJson: string;
  /** Human-facing text; includes the notice verbatim. */
  readonly humanText: string;
  /** Redaction ScanRecord over both rendered texts (always clean here). */
  readonly redaction_scan: ScanRecord;
}

// ---------------------------------------------------------------------------
// Builder — no code path omits the notice block
// ---------------------------------------------------------------------------

function buildNoticeManifest(): NoticeManifest {
  return {
    notice_id: ASSURANCE_NOTICE_ID,
    notice_text: ASSURANCE_NOTICE_TEXT,
    utf8_sha256_hex: assuranceNoticeUtf8Sha256Hex(),
    ab_jcs1_digest_hex: assuranceNoticeDomainDigestHex(),
  };
}

/**
 * Construct a verdict-bearing report artifact. The assurance-notice block is
 * always embedded; callers cannot omit it through this API.
 */
export function buildReportArtifact(input: ReportArtifactInput): { readonly ok: true; readonly artifact: ReportArtifact } | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly { readonly code: string; readonly path: string; readonly message: string }[] } {
  const issues: { code: string; path: string; message: string }[] = [];

  const rid = checkRestrictedId(input.reportId);
  if (!rid.ok) issues.push({ code: "V_INVALID_ID", path: "$.report_id", message: rid.reason });
  const sid = checkRestrictedId(input.scenarioId);
  if (!sid.ok) issues.push({ code: "V_INVALID_ID", path: "$.scenario_id", message: sid.reason });

  if (input.verdict === "not_run") {
    if (input.runValidity !== undefined) {
      issues.push({
        code: "V_INCONSISTENT_INPUT",
        path: "$.run_validity",
        message: 'run_validity must be absent when verdict is "not_run"',
      });
    }
  } else if (input.runValidity === undefined) {
    issues.push({
      code: "V_MISSING_MANDATORY_FIELD",
      path: "$.run_validity",
      message: `run_validity is required unless verdict is "not_run"`,
    });
  }

  if (input.createdUtc !== undefined && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(input.createdUtc)) {
    issues.push({ code: "V_INVALID_FIELD_TYPE", path: "$.created_utc", message: "must match RFC 3339 UTC shape (…Z)" });
  }
  if (input.bundleId !== undefined) {
    const b = checkRestrictedId(input.bundleId);
    if (!b.ok) issues.push({ code: "V_INVALID_ID", path: "$.bundle_id", message: b.reason });
  }

  if (issues.length > 0) {
    return { ok: false, stage: "validate", issues };
  }

  // Notice block is unconditional from here on.
  const artifact: ReportArtifact = {
    $schema: SUPPORTED_REPORT_SCHEMA,
    report_id: input.reportId,
    scenario_id: input.scenarioId,
    verdict: input.verdict,
    aggregation_rule: input.aggregationRule,
    reasons: [...input.reasons],
    assurance_notice_id: ASSURANCE_NOTICE_ID,
    notice_manifest: buildNoticeManifest(),
    ...(input.runValidity !== undefined ? { run_validity: input.runValidity } : {}),
    ...(input.bundleId !== undefined ? { bundle_id: input.bundleId } : {}),
    ...(input.createdUtc !== undefined ? { created_utc: input.createdUtc } : {}),
    ...(input.notes !== undefined ? { notes: input.notes } : {}),
  };
  return { ok: true, artifact };
}

// ---------------------------------------------------------------------------
// Independent validator — re-checks everything, including the notice binding
// ---------------------------------------------------------------------------

export type ReportValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly { readonly code: string; readonly path: string; readonly message: string }[] };

const REPORT_ALLOWED_FIELDS: readonly string[] = [
  "$schema",
  "report_id",
  "scenario_id",
  "verdict",
  "run_validity",
  "aggregation_rule",
  "reasons",
  "assurance_notice_id",
  "notice_manifest",
  "bundle_id",
  "created_utc",
  "notes",
];

const MANIFEST_ALLOWED_FIELDS: readonly string[] = ["notice_id", "notice_text", "utf8_sha256_hex", "ab_jcs1_digest_hex"];

function issue(code: string, path: string, message: string): { code: string; path: string; message: string } {
  return { code, path, message };
}

/**
 * Validate an arbitrary parsed document as an `ab.report/1` artifact with an
 * intact AB-NOTICE-001 binding. Independent of the builder.
 */
export function validateReportArtifact(doc: JsonValue): ReportValidationResult {
  const issues: ReturnType<typeof issue>[] = [];
  const isObj = (v: JsonValue): v is { readonly [key: string]: JsonValue } =>
    typeof v === "object" && v !== null && !Array.isArray(v);

  if (!isObj(doc)) {
    return { ok: false, stage: "validate", issues: [issue("V_NOT_AN_OBJECT", "$", "report must be a JSON object")] };
  }
  for (const k of Object.keys(doc)) {
    if (!REPORT_ALLOWED_FIELDS.includes(k)) {
      issues.push(issue("V_EXTRA_FIELD", `$.${k}`, `field "${k}" is not declared by ${SUPPORTED_REPORT_SCHEMA}`));
    }
  }

  const sv = doc["$schema"];
  if (sv !== SUPPORTED_REPORT_SCHEMA) {
    issues.push(
      sv === undefined
        ? issue("V_MISSING_MANDATORY_FIELD", "$.$schema", 'missing mandatory field "$schema"')
        : issue("V_UNKNOWN_SCHEMA_VERSION", "$.$schema", `expected ${SUPPORTED_REPORT_SCHEMA}`),
    );
  }

  const str = (v: JsonValue | undefined): v is string => typeof v === "string";

  const reportId = doc["report_id"];
  if (reportId === undefined || !str(reportId) || !checkRestrictedId(reportId).ok) {
    issues.push(issue("V_INVALID_ID", "$.report_id", "must be a restricted ID"));
  }
  const scenarioId = doc["scenario_id"];
  if (scenarioId === undefined || !str(scenarioId) || !checkRestrictedId(scenarioId).ok) {
    issues.push(issue("V_INVALID_ID", "$.scenario_id", "must be a restricted ID"));
  }

  const verdict = doc["verdict"];
  if (!str(verdict) || !(SCENARIO_VERDICT_VALUES as readonly string[]).includes(verdict)) {
    issues.push(issue("V_INVALID_FIELD_TYPE", "$.verdict", `must be one of ${SCENARIO_VERDICT_VALUES.join(" | ")}`));
  }

  const runValidity = doc["run_validity"];
  if (verdict === "not_run") {
    if (runValidity !== undefined) {
      issues.push(issue("V_INCONSISTENT_INPUT", "$.run_validity", 'run_validity must be absent for verdict "not_run"'));
    }
  } else if (runValidity === undefined) {
    issues.push(issue("V_MISSING_MANDATORY_FIELD", "$.run_validity", "required unless verdict is not_run"));
  } else if (!(RUN_VALIDITY_VALUES as readonly string[]).includes(String(runValidity))) {
    issues.push(issue("V_INVALID_FIELD_TYPE", "$.run_validity", "must be valid | invalid"));
  }

  const agg = doc["aggregation_rule"];
  if (agg === undefined) {
    issues.push(issue("V_MISSING_MANDATORY_FIELD", "$.aggregation_rule", "missing mandatory field"));
  } else if (!str(agg) || agg.length === 0) {
    issues.push(issue("V_INVALID_FIELD_TYPE", "$.aggregation_rule", "must be a non-empty string"));
  }

  const reasons = doc["reasons"];
  if (!Array.isArray(reasons)) {
    issues.push(issue("V_INVALID_FIELD_TYPE", "$.reasons", "must be an array of strings"));
  } else if (reasons.some((r) => !str(r))) {
    issues.push(issue("V_INVALID_FIELD_TYPE", "$.reasons[i]", "all reasons must be strings"));
  }

  // --- Notice binding -----------------------------------------------------
  const nid = doc["assurance_notice_id"];
  if (nid !== ASSURANCE_NOTICE_ID) {
    issues.push(
      nid === undefined
        ? issue("V_MISSING_MANDATORY_FIELD", "$.assurance_notice_id", "every verdict-bearing artifact SHALL carry AB-NOTICE-001")
        : issue("V_INVALID_FIELD_TYPE", "$.assurance_notice_id", `must be exactly "${ASSURANCE_NOTICE_ID}"`),
    );
  }

  const manifestRaw: JsonValue = doc["notice_manifest"] ?? null;
  if (!isObj(manifestRaw)) {
    issues.push(issue("V_MISSING_MANDATORY_FIELD", "$.notice_manifest", "the root manifest binds the notice ID to its text and digests"));
  } else {
    for (const k of Object.keys(manifestRaw)) {
      if (!MANIFEST_ALLOWED_FIELDS.includes(k)) {
        issues.push(issue("V_EXTRA_FIELD", `$.notice_manifest.${k}`, "undeclared manifest field"));
      }
    }
    const mid = manifestRaw["notice_id"];
    if (mid !== ASSURANCE_NOTICE_ID) {
      issues.push(issue("V_INVALID_FIELD_TYPE", "$.notice_manifest.notice_id", `must be "${ASSURANCE_NOTICE_ID}"`));
    }
    const mtext = manifestRaw["notice_text"];
    if (mtext !== ASSURANCE_NOTICE_TEXT) {
      issues.push(
        mtext === undefined
          ? issue("V_MISSING_MANDATORY_FIELD", "$.notice_manifest.notice_text", "manifest must carry the exact notice text")
          : issue("V_INVALID_FIELD_TYPE", "$.notice_manifest.notice_text", "notice text does not match the pinned required text"),
      );
    }
    const uSha = manifestRaw["utf8_sha256_hex"];
    if (!str(uSha) || !verifyDigestHex(assuranceNoticeUtf8Sha256Hex(), String(uSha))) {
      issues.push(issue("V_DIGEST_MISMATCH", "$.notice_manifest.utf8_sha256_hex", "declared digest does not match the pinned notice bytes"));
    }
    const dSha = manifestRaw["ab_jcs1_digest_hex"];
    if (!str(dSha) || !verifyDigestHex(assuranceNoticeDomainDigestHex(), String(dSha))) {
      issues.push(issue("V_DIGEST_MISMATCH", "$.notice_manifest.ab_jcs1_digest_hex", "declared digest does not match the pinned notice bytes"));
    }
  }

  if (issues.length > 0) {
    return { ok: false, stage: "validate", issues };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Finalization — canonical + human rendering behind the redaction gate
// ---------------------------------------------------------------------------

const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function renderHumanText(a: ReportArtifact): string {
  const lines: string[] = [];
  lines.push(`AegisBench report ${a.report_id}`);
  lines.push(`scenario: ${a.scenario_id}`);
  lines.push(`verdict: ${a.verdict}`);
  if (a.run_validity !== undefined) lines.push(`run_validity: ${a.run_validity}`);
  lines.push(`aggregation_rule: ${a.aggregation_rule}`);
  if (a.reasons.length > 0) lines.push(`reasons: ${a.reasons.join("; ")}`);
  if (a.notes !== undefined && a.notes.length > 0) lines.push(`notes: ${a.notes}`);
  lines.push("");
  lines.push(`Assurance notice (${a.assurance_notice_id}):`);
  lines.push(a.notice_manifest.notice_text);
  return lines.join("\n");
}

export type FinalizeResult =
  | { readonly ok: true; readonly finalized: FinalizedReport }
  | {
      readonly ok: false;
      readonly stage: "redaction";
      readonly record: ScanRecord;
    };

/**
 * Render the artifact deterministically and accept it ONLY after the
 * Slice 4a redaction scanner reports zero findings on both rendered texts.
 * On any finding nothing but the scan record escapes this function.
 */
export function finalizeReportArtifact(artifact: ReportArtifact): FinalizeResult {
  const canon = canonicalize(artifact as unknown as JsonValue);
  if (!canon.ok) throw new Error("artifact failed canonicalization");
  const human = renderHumanText(artifact);

  // NOTE: CanonResult exposes `canonicalText`; guard the exact field.
  const canonicalText = canon.canonicalText;
  const record = scanForSecrets([canonicalText, human], ["artifact_text"]);
  if (!record.clean) {
    return { ok: false, stage: "redaction", record };
  }
  return {
    ok: true,
    finalized: {
      artifact,
      canonicalJson: canonicalText,
      humanText: human,
      redaction_scan: record,
    },
  };
}

/** Convenience: validate → build → finalize in one deterministic step. */
export function produceReport(input: ReportArtifactInput): FinalizeResult | { readonly ok: false; readonly stage: "validate"; readonly issues: readonly ReturnType<typeof issue>[] } {
  const built = buildReportArtifact(input);
  if (!built.ok) return built;
  const validated = validateReportArtifact(built.artifact as unknown as JsonValue);
  if (!validated.ok) return validated;
  return finalizeReportArtifact(built.artifact);
}
