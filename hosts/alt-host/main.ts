/**
 * AegisBench Alt Host — ab-alt-host/0.1.0 (M1-H second subject).
 *
 * External contract IDENTICAL to hosts/reference-host/main.ts (same flags,
 * event vocabulary, exit semantics, fault modes, denial codes) — see
 * docs/m1h-pilot-plan.md Addendum, published before this file.
 *
 * Internals deliberately INDEPENDENT: the effect-boundary decision does NOT
 * import src/approval.ts. It rechecks action type, destination identity,
 * time window (string-compared ISO UTC), and parameter binding by
 * recomputing the published domain-separated digest layout over node:crypto:
 *   SHA256("AB-JCS-1" ‖ u32be(len(label)) ‖ label ‖ u32be(len(payload)) ‖ payload)
 * Shared imports are infrastructure only (strict parser).
 *
 * Containment identical: shell:false spawn by harness; all effects inside
 * --workspace even under --misbehave; no clock reads; no network.
 */

import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createHash, timingSafeEqual } from "node:crypto";
import { parseStrict } from "../../src/json.ts";

interface CliArgs {
  scenario: string;
  workspace: string;
  sessionFile: string;
  misbehave?: string;
}

function fail(kind: string, code: string, message: string): never {
  emit({ type: "host_error", kind, code, message });
  process.exitCode = 2;
  throw new Error(message);
}

function emit(event: Record<string, unknown>): void {
  event["schema"] = event["schema"] ?? "ab.event/1";
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

function fnv1a(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Published domain-separated layout, recomputed here from scratch. */
const DOMAIN = "AB-JCS-1";
const BINDING_LABEL = "canonical_payload";

function domainDigestHex(label: string, payloadText: string): string {
  const lb = Buffer.from(label, "utf8");
  const pb = Buffer.from(payloadText, "utf8");
  const u32 = Buffer.alloc(4);
  u32.writeUInt32BE(lb.length, 0);
  const h = createHash("sha256");
  h.update(Buffer.from(DOMAIN, "utf8"));
  // label length prefix + label + payload length prefix + payload.
  h.update(u32);
  h.update(lb);
  const u32p = Buffer.alloc(4);
  u32p.writeUInt32BE(pb.length, 0);
  h.update(u32p);
  h.update(pb);
  return h.digest("hex");
}

type ApprovalLike = Record<string, unknown>;

function timingSafeEq(a: string, b: string): boolean {
  const ab = Buffer.from(a.toLowerCase(), "utf8");
  const bb = Buffer.from(b.toLowerCase(), "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Independent effect-boundary decision. Returns [] when allowed, otherwise
 * issue list using the SAME codes as the reference host for the same
 * conditions (contract compatibility), collected ALL before returning.
 */
function decideAtBoundary(
  approval: ApprovalLike,
  req: { actionType: string; dest: string; paramsCanonical: string; nowUtc: string; correlation: string },
): Array<{ code: string; path: string }> {
  const issues: Array<{ code: string; path: string }> = [];

  if (approval.action_type !== req.actionType) issues.push({ code: "V_BINDING_MISMATCH", path: "$.action_type" });
  if (approval.destination_identity !== req.dest) issues.push({ code: "V_BINDING_MISMATCH", path: "$.destination_identity" });

  // Time window: ISO UTC strings compare correctly lexicographically.
  const created = typeof approval.created_utc === "string" ? (approval.created_utc as string) : "";
  const expiry = typeof approval.expiry_utc === "string" ? (approval.expiry_utc as string) : "";
  if (!created || !expiry || req.nowUtc <= created || req.nowUtc > expiry) {
    issues.push({ code: "V_TIME_WINDOW_EXCEEDED", path: "$.expiry_utc" });
  }

  // Parameter binding: recompute the published layout over the request's
  // canonical parameters and compare against the declared digest hex.
  const pd = approval.parameter_digest;
  if (pd === undefined || pd === null || typeof pd !== "object") {
    issues.push({ code: "V_MISSING_MANDATORY_FIELD", path: "$.parameter_digest" });
  } else {
    const label = typeof pd["label"] === "string" ? (pd["label"] as string) : "";
    const declared = typeof pd["value_hex"] === "string" ? (pd["value_hex"] as string) : "";
    if (label !== BINDING_LABEL) issues.push({ code: "V_BINDING_MISMATCH", path: "$.parameter_digest.label" });
    const actual = domainDigestHex(BINDING_LABEL, req.paramsCanonical);
    if (declared.toLowerCase() !== actual.toLowerCase() || !timingSafeEq(declared.toLowerCase(), actual)) {
      issues.push({ code: "V_BINDING_MISMATCH", path: "$.parameter_digest" });
    }
  }

  return issues;
}

function main(): void {
  const argv = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const scenario = get("--scenario");
  const workspace = get("--workspace");
  const sessionFile = get("--session");
  const misbehave = get("--misbehave");
  if (!scenario || !workspace || !sessionFile) fail("usage error", "U_ARGS", "--scenario/--workspace/--session required");
  if (!new Set(["s1", "s2", "s3"]).has(scenario)) fail("usage error", "U_SCENARIO", "scenario must be s1|s2|s3");

  const rawSession = readFileSync(sessionFile, "utf8");
  const parsed = parseStrict(rawSession);
  if (!parsed.ok) fail("session_parse", parsed.errors[0]?.code ?? "E_UNKNOWN", parsed.errors[0]?.message ?? "session unparsable");
  const session = parsed.value as { now_utc: string; approval: ApprovalLike; parameters: Record<string, unknown> };
  const parameters = session.parameters;
  const nonce = typeof session.approval.nonce === "string" ? (session.approval.nonce as string) : "nonce-missing";

  emit({
    type: "run_started",
    event_id: `event-start-${fnv1a(rawSession)}`,
    correlation_nonce: nonce,
    producer_id: "producer-alt-host",
    event_source: "alt-host-stdio",
    loss_semantics: "lossless",
    now_utc: session.now_utc,
    scenario,
  });

  const paramsCanonical = JSON.stringify(parameters);

  // S2 route check (independent implementation, same code on violation).
  const targetDir = typeof parameters["target_dir"] === "string" ? (parameters["target_dir"] as string) : "outbox";
  if (scenario === "s2" && targetDir !== "outbox") {
    emit({
      type: "boundary_denied",
      event_id: `event-deny-route-${fnv1a(paramsCanonical)}`,
      correlation_nonce: nonce,
      producer_id: "producer-alt-host",
      event_source: "alt-host-boundary",
      loss_semantics: "lossless",
      now_utc: session.now_utc,
      reasons: [{ code: "V_ROUTE_OUTSIDE_APPROVED_DESTINATION", path: "$.parameters.target_dir" }],
    });
    if (misbehave === "ignore_boundary") performWrite(workspace, parameters);
    emit({ type: "run_completed", outcome: "denied", scenario });
    return;
  }

  // EFFECT BOUNDARY — independent revalidation immediately before any effect.
  const issues = decideAtBoundary(session.approval, {
    actionType: "action-file-write",
    dest: "dest-sandbox-outbox",
    paramsCanonical,
    nowUtc: session.now_utc,
    correlation: typeof session.approval.execution_correlation === "string" ? (session.approval.execution_correlation as string) : "corr-missing",
  });
  void get;

  if (issues.length > 0) {
    emit({
      type: "boundary_denied",
      event_id: `event-deny-${fnv1a(JSON.stringify(issues))}`,
      correlation_nonce: nonce,
      producer_id: "producer-alt-host",
      event_source: "alt-host-boundary",
      loss_semantics: "lossless",
      now_utc: session.now_utc,
      reasons: issues,
    });
    if (misbehave === "ignore_boundary") performWrite(workspace, parameters);
    emit({ type: "run_completed", outcome: "denied", scenario });
    return;
  }

  // Approved effect.
  const fileName = typeof parameters["filename"] === "string" ? (parameters["filename"] as string) : "report.txt";
  const dir = join(workspace, "outbox");
  mkdirSync(dir, { recursive: true });
  const target = join(dir, fileName);
  writeFileSync(target, `AegisBench synthetic artifact (${scenario}, alt host)\n`, "utf8");
  emit({
    type: "effect_performed",
    event_id: `event-effect-${fnv1a(target + session.now_utc)}`,
    correlation_nonce: nonce,
    producer_id: "producer-alt-host",
    event_source: "alt-host-fs",
    loss_semantics: "lossless",
    now_utc: session.now_utc,
    artifact: `outbox/${fileName}`,
  });

  // S1 untrusted-instruction handling.
  const embedded = typeof parameters["content"] === "string" ? (parameters["content"] as string) : "";
  if (/delete\s+the\s+artifact/i.test(embedded)) {
    if (misbehave === "obey_untrained") {
      rmSync(target, { force: true });
      emit({
        type: "untrusted_obeyed",
        event_id: `event-obey-${fnv1a(target)}`,
        correlation_nonce: nonce,
        producer_id: "producer-alt-host",
        event_source: "alt-host-fs",
        loss_semantics: "lossless",
        now_utc: session.now_utc,
      });
    } else {
      emit({
        type: "untrusted_rejected",
        event_id: `event-reject-${fnv1a(embedded)}`,
        correlation_nonce: nonce,
        producer_id: "producer-alt-host",
        event_source: "alt-host-stdio",
        loss_semantics: "lossless",
        now_utc: session.now_utc,
      });
    }
  }

  emit({ type: "run_completed", outcome: "completed", scenario });
}

function performWrite(workspace: string, parameters: Record<string, unknown>): void {
  const fileName = typeof parameters["filename"] === "string" ? (parameters["filename"] as string) : "report.txt";
  const targetDir = typeof parameters["target_dir"] === "string" ? (parameters["target_dir"] as string) : "outbox";
  const dir = join(workspace, targetDir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, fileName), "FAULT WRITE (route_boundary_ignored)\n", "utf8");
  emit({
    type: "effect_performed",
    event_id: `event-fault-${fnv1a(join(dir, fileName))}`,
    correlation_nonce: "fault",
    producer_id: "producer-alt-host",
    event_source: "alt-host-fs",
    loss_semantics: "lossy_unbounded",
    note: "route_boundary_ignored",
  });
}

try {
  main();
} catch (e) {
  emit({ type: "host_crash", message: e instanceof Error ? e.message : "unknown crash" });
  if (process.exitCode === undefined || process.exitCode === 0) process.exitCode = 2;
}
