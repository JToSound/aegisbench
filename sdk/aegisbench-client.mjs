/**
 * aegisbench-client — zero-dependency ESM SDK exposing the M1-H pilot's
 * harness primitives to consumers (docs/m1h-pilot-plan.md Addendum 3 §A3.3).
 *
 * Not published to any registry; import directly from this repository.
 *
 * Exposes:
 *   runScenario({ hostPath, scenario, session, misbehave?, keepWorkspace? })
 *     — shell:false spawn into a fresh disposable workspace, JSON Lines
 *       parsing, artifact inspection, verified cleanup (unless kept).
 *   parseEventStream(stdoutText) — JSON Lines → event array (throws with the
 *       line number on malformed output).
 *   re-validated decision helpers: validateMeasurementPlan,
 *       applyControlResults, decideScenarioVerdict, claimAdmissibilityCeiling.
 *
 * Safety model identical to the pilot: no shell interpolation ever; all
 * host effects stay inside the disposable workspace; cleanup is verified.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export { validateMeasurementPlan, applyControlResults } from "../src/controls.ts";
export { decideScenarioVerdict, claimAdmissibilityCeiling } from "../src/policy.ts";

/** Parse a JSON Lines stream; throws Error(`line N: …`) on bad output. */
export function parseEventStream(stdoutText) {
  const events = [];
  const lines = stdoutText.split("\n").filter((l) => l.trim().length > 0);
  for (let i = 0; i < lines.length; i++) {
    try {
      events.push(JSON.parse(lines[i]));
    } catch (e) {
      throw new Error(`line ${i + 1}: not valid JSON`);
    }
  }
  return events;
}

/**
 * Run one scenario against a host. Returns:
 *   { status, events, artifactExists, workspaceRemoved, workspaceLeftovers }
 */
export function runScenario({
  hostPath,
  scenario,
  session,
  misbehave,
  keepWorkspace = false,
  timeoutMs = 10_000,
}) {
  if (!hostPath || !scenario || !session) {
    throw new Error("hostPath, scenario and session are required");
  }
  if (!["s1", "s2", "s3"].includes(scenario)) {
    throw new Error('scenario must be "s1" | "s2" | "s3"');
  }
  const ws = mkdtempSync(join(tmpdir(), "ab-sdk-"));
  try {
    const sessionPath = join(ws, "session.json");
    writeFileSync(sessionPath, JSON.stringify(session), "utf8");

    const args = ["--scenario", scenario, "--workspace", ws, "--session", sessionPath];
    if (misbehave !== undefined) args.push("--misbehave", String(misbehave));

    // shell:false ALWAYS — no shell interpolation anywhere in this SDK.
    const proc = spawnSync(process.execPath, [hostPath, ...args], {
      encoding: "utf8",
      timeout: timeoutMs,
      shell: false,
    });
    const events = parseEventStream(proc.stdout ?? "");
    const fileName = typeof session.parameters?.filename === "string" ? session.parameters.filename : "report.txt";
    const artifactExists = existsSync(join(ws, "outbox", fileName));

    if (!keepWorkspace) {
      rmSync(ws, { recursive: true, force: true });
      return {
        status: proc.status,
        events,
        artifactExists,
        workspaceRemoved: !existsSync(ws),
        workspaceLeftovers: [],
      };
    }
    return {
      status: proc.status,
      events,
      artifactExists,
      workspaceRemoved: false,
      workspaceLeftovers: existsSync(ws) ? readdirSync(ws) : [],
      workspacePath: ws,
    };
  } catch (e) {
    // Never leak a live temp dir on our own errors.
    if (!keepWorkspace) {
      rmSync(ws, { recursive: true, force: true });
    }
    throw e;
  }
}
