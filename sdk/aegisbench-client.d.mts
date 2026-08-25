/**
 * Type declarations for sdk/aegisbench-client.mjs (zero-dep consumer SDK).
 */

export interface AbSession {
  now_utc: string;
  approval: Record<string, unknown>;
  parameters: Record<string, unknown>;
}

export interface AbRunResult {
  status: number | null;
  events: Array<Record<string, unknown>>;
  artifactExists: boolean;
  workspaceRemoved: boolean;
  workspaceLeftovers: readonly string[];
  /** Present only when keepWorkspace:true — caller owns cleanup then. */
  workspacePath?: string;
}

/** JSON Lines → event array; throws Error("line N: …") on malformed output. */
export declare function parseEventStream(stdoutText: string): Array<Record<string, unknown>>;

/**
 * Run one scenario against a pinned host. shell:false always; effects stay
 * inside the disposable workspace; cleanup verified unless keepWorkspace.
 */
export declare function runScenario(options: {
  hostPath: string;
  scenario: "s1" | "s2" | "s3";
  session: AbSession;
  misbehave?: string;
  keepWorkspace?: boolean;
  timeoutMs?: number;
}): AbRunResult;

// --- Re-validated decision helpers (structural mirrors of src/) ---

export interface AbControlsIssue {
  code: string;
  path: string;
  message: string;
}

export declare function validateMeasurementPlan(
  doc: unknown,
): { ok: true } | { ok: false; stage: "validate"; issues: readonly AbControlsIssue[] };

export interface AbControlResultEntry {
  control_id: string;
  outcome: "passed" | "failed" | "not_run";
}

export interface AbAppliedControlResults {
  complete: boolean;
  allPassed: boolean;
  passedCount: number;
  failedIds: readonly string[];
  notRunIds: readonly string[];
  missingIds: readonly string[];
  unknownIds: readonly string[];
}

export declare function applyControlResults(planDoc: unknown, results: readonly AbControlResultEntry[]): AbAppliedControlResults;

export type AbScenarioVerdict = "pass" | "fail" | "inconclusive" | "not_supported" | "not_run" | "invalid_run";
export type AbClaimAdmissibility = "admissible" | "downgraded" | "inadmissible";

export declare function decideScenarioVerdict(
  input: unknown,
):
  | {
      ok: true;
      outcome: {
        scenario_verdict: AbScenarioVerdict;
        run_validity?: "valid" | "invalid";
        aggregation_rule: string;
        reasons: readonly string[];
      };
    }
  | { ok: false; stage: "validate"; issues: readonly AbControlsIssue[] };

export declare function claimAdmissibilityCeiling(
  verdict: AbScenarioVerdict,
  observerIndependenceComplete: boolean,
): AbClaimAdmissibility;
