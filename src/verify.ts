/**
 * AegisBench — offline verifier pipeline (M0 Slice 5b).
 *
 * Contract reference: MASTER_PROMPT.md §0 primary success condition and §3
 * M0 ("stable stdout, stderr, and exit-code contract").
 *
 * Pipeline: strict parse → policy/oracle → report build → independent
 * validation → render → redaction gate. Every stage short-circuits with a
 * single structured diagnostic; no partial artifact escapes on failure.
 *
 * Identity derivation (pinned in docs/implementation-plan.md):
 *   report_id = "report-" + first 16 hex of the AB-JCS-1 domain digest
 *   (label canonical_payload) over the canonical text of the parsed input;
 *   scenario_id = "scenario-under-test" (constant in M0).
 *
 * Zero dependencies. Erasable TS syntax only. ESM: static fs import only.
 */

import { readFileSync } from "node:fs";
import { parseStrict, type JsonValue } from "./json.ts";
import { canonicalize } from "./canon.ts";
import { canonicalPayloadDigest } from "./digest.ts";
import { scanForSecrets } from "./redact.ts";
import {
  decideScenarioVerdict,
  VERDICT_AGGREGATION_RULE,
  type PolicyOutcome,
} from "./policy.ts";
import { produceReport } from "./report.ts";

export type VerifyStage = "parse" | "validate" | "redaction";

export interface VerifyRejection {
  readonly ok: false;
  readonly stage: VerifyStage;
  /** Fixed field order for deterministic single-line diagnostics. */
  readonly code: string;
  readonly path: string;
  readonly message: string;
}

export interface VerifySuccess {
  readonly ok: true;
  readonly verdict: string;
  readonly exitCode: number;
  readonly finalized: {
    readonly artifact: Record<string, unknown>;
    readonly canonicalJson: string;
    readonly humanText: string;
  };
}

export type VerifyResult = VerifySuccess | VerifyRejection;

/** Verdict→exit-code mapping per docs/implementation-plan.md Slice 5b. */
export const VERDICT_EXIT_CODES: Readonly<Record<string, number>> = {
  pass: 0,
  fail: 1,
  inconclusive: 2,
  not_supported: 3,
  not_run: 4,
  invalid_run: 5,
};

/** Reserved codes documented in the plan; never returned by this pipeline. */
export const RESERVED_EXIT_CODES: Readonly<Record<string, string>> = {
  "12": "redaction-gate rejection on report content (no M0 producer)",
};

function reject(stage: VerifyStage, code: string, path: string, message: string): VerifyRejection {
  return { ok: false, stage, code, path, message };
}

/**
 * Run the full offline verification over raw input text.
 */
export function verifyText(text: string): VerifyResult {
  // Stage 1 — strict JSON parse (duplicate keys, limits, I-JSON).
  const parsed = parseStrict(text);
  if (!parsed.ok) {
    const e = parsed.errors[0];
    if (e === undefined) {
      return reject("parse", "E_UNKNOWN", "$", "parser returned no diagnostic");
    }
    return reject("parse", e.code, e.path ?? "$", e.message);
  }

  // Stage 2 — policy/oracle decision (structural + consistency + verdict).
  const decision = decideScenarioVerdict(parsed.value);
  if (!decision.ok) {
    const issue = decision.issues[0];
    if (issue === undefined) {
      return reject("validate", "V_UNKNOWN", "$", "validator returned no diagnostic");
    }
    return reject("validate", issue.code, issue.path, issue.message);
  }
  const outcome: PolicyOutcome = decision.outcome;

  // Deterministic identity derivation from the input's canonical text.
  const canonInput = canonicalize(parsed.value);
  if (!canonInput.ok) {
    const ce = canonInput.errors[0];
    return reject(
      "validate",
      ce?.code ?? "C_UNKNOWN",
      ce?.path ?? "$",
      ce?.message ?? "input failed canonicalization",
    );
  }
  const digest = canonicalPayloadDigest(canonInput.canonicalText);
  if (!digest.ok) {
    return reject("validate", digest.errors[0]?.code ?? "D_UNKNOWN", "$", "identity digest failed");
  }
  const reportId = `report-${digest.hex.slice(0, 16)}`;
  const scenarioId = "scenario-under-test";

  // Stage 3 — report build + independent validation + render + redaction gate.
  const produced = produceReport({
    reportId,
    scenarioId,
    verdict: outcome.scenario_verdict,
    ...(outcome.run_validity === undefined ? {} : { runValidity: outcome.run_validity }),
    aggregationRule: VERDICT_AGGREGATION_RULE,
    reasons: outcome.reasons,
  });
  if (!produced.ok) {
    if (produced.stage === "redaction") {
      return reject("redaction", "R_REDACTION_GATE", "$", "report text rejected by redaction scanner");
    }
    const issue = produced.issues[0];
    return reject(
      "validate",
      typeof issue?.code === "string" ? issue.code : "V_UNKNOWN",
      typeof issue?.path === "string" ? issue.path : "$",
      typeof issue?.message === "string" ? issue.message : "report validation failed",
    );
  }

  const exitCode = VERDICT_EXIT_CODES[outcome.scenario_verdict] ?? 2;
  return {
    ok: true,
    verdict: outcome.scenario_verdict,
    exitCode,
    finalized: {
      artifact: produced.finalized.artifact as unknown as Record<string, unknown>,
      canonicalJson: produced.finalized.canonicalJson,
      humanText: produced.finalized.humanText,
    },
  };
}

// ---------------------------------------------------------------------------
// CLI plumbing (injectable I/O so tests need no process spawn)
// ---------------------------------------------------------------------------

export interface CliIo {
  readonly stdout: (s: string) => void;
  readonly stderr: (s: string) => void;
}

export interface CliInvocationResult {
  readonly exitCode: number;
}

/**
 * Formats the single-line diagnostic with FIXED field order. Raw secret
 * material must never reach the terminal verbatim: EVERY field value is
 * scanned independently and suppressed when it matches a redaction rule
 * (a duplicate-key error can echo a canary-shaped key into `path` too).
 */
export function formatDiagnostic(r: Exclude<VerifyResult, VerifySuccess>): string {
  const redact = (value: string): string => {
    const scan = scanForSecrets([value], ["log_line"]);
    return scan.clean ? value : "[suppressed by redaction scanner]";
  };
  const stage = r.stage;
  const code = r.code; // codes are our own fixed vocabulary; never user data
  const path = redact(r.path);
  const message = redact(r.message);
  return `aegisbench error stage=${stage} code=${code} path=${path} message=${message}`;
}

function rejectionExitCode(r: Exclude<VerifyResult, VerifySuccess>): number {
  switch (r.stage) {
    case "parse":
      return 10;
    case "validate":
      return 11;
    case "redaction":
      return 12;
    default:
      return 11;
  }
}

/**
 * In-process CLI entrypoint. Reads the named file (or stdin for "-"),
 * prints exactly one stream per contract, returns the exit code.
 */
export function runCli(argv: readonly string[], io: CliIo): CliInvocationResult {
  // Usage: node src/cli.ts <file|-> [--format=json|human]
  const args = [...argv];
  let format: "json" | "human" = "json";
  const fmtIdx = args.indexOf("--format");
  if (fmtIdx >= 0) {
    const v = args[fmtIdx + 1];
    args.splice(fmtIdx, 2);
    if (v !== "json" && v !== "human") {
      io.stderr("aegisbench error stage=usage code=U_BAD_FORMAT path=- message=--format must be json|human\n");
      return { exitCode: 13 };
    }
    format = v;
  }

  const positional = args.filter((a) => !a.startsWith("-"));
  const leftoverFlags = args.filter((a) => a.startsWith("-"));
  if (leftoverFlags.length > 0 || positional.length !== 1) {
    io.stderr("aegisbench error stage=usage code=U_USAGE path=- message=usage: node src/cli.ts <file|-> [--format=json|human]\n");
    return { exitCode: 13 };
  }
  const fileArg = positional[0] as string;

  let text: string;
  try {
    text = fileArg === "-" ? readFileSync(0, "utf8") : readFileSync(fileArg, "utf8");
  } catch {
    io.stderr(`aegisbench error stage=usage code=U_READ path=${fileArg} message=input could not be read\n`);
    return { exitCode: 13 };
  }

  const result = verifyText(text);
  if (!result.ok) {
    io.stderr(formatDiagnostic(result) + "\n");
    return { exitCode: rejectionExitCode(result) };
  }

  const body = format === "json" ? result.finalized.canonicalJson : result.finalized.humanText;
  io.stdout(body + "\n");
  return { exitCode: result.exitCode };
}
