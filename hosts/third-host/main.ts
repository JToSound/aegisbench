/**
 * AegisBench Third Host — ab-third-host/0.1.0 (M1-H third subject).
 *
 * External contract IDENTICAL to hosts/reference-host/main.ts and
 * hosts/alt-host/main.ts (same flags, event vocabulary, exit semantics,
 * fault modes, denial codes) per docs/m1h-pilot-plan.md Addendum 3,
 * published before this file.
 *
 * Boundary decision INDEPENDENT again (no src/approval.ts import):
 * domain-separated SHA-256 recomputed as a SINGLE framed buffer
 * (one Buffer.concat, one hash update) and hex compared character-wise in
 * constant steps. Time window via ISO UTC string comparison.
 * Infrastructure imports limited to the strict parser.
 *
 * Containment identical: effects confined to --workspace even under fault;
 * no clock reads; no network.
 */

import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { parseStrict } from "../../src/json.ts";

const DOMAIN = "AB-JCS-1";
const BINDING_LABEL = "canonical_payload";

function emit(event: Record<string, unknown>): void {
  event["schema"] = event["schema"] ?? "ab.event/1";
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

function fail(kind: string, code: string, message: string): never {
  emit({ type: "host_error", kind, code, message });
  process.exitCode = 2;
  throw new Error(message);
}

function fnv1a(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Published layout as ONE framed buffer: domain ‖ u32be ‖ label ‖ u32be ‖ payload. */
function domainDigestHex(label: string, payloadText: string): string {
  const lb = Buffer.from(label, "utf8");
  const pb = Buffer.from(payloadText, "utf8");
  const frame = Buffer.concat([
    Buffer.from(DOMAIN, "utf8"),
    (() => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(lb.length, 0);
      return b;
    })(),
    lb,
    (() => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(pb.length, 0);
      return b;
    })(),
    pb,
  ]);
  return createHash("sha256").update(frame).digest("hex");
}

/** Fixed-step hex equality (length-independent control flow). */
function hexEqualsConstStep(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** Independent effect-boundary decision; collects ALL violations. */
function decideAtBoundary(
  approval: Record<string, unknown>,
  req: { actionType: string; dest: string; paramsCanonical: string; nowUtc: string },
): Array<{ code: string; path: string }> {
  const issues: Array<{ code: string; path: string }> = [];
  if (approval["action_type"] !== req.actionType) issues.push({ code: "V_BINDING_MISMATCH", path: "$.action_type" });
  if (approval["destination_identity"] !== req.dest) issues.push({ code: "V_BINDING_MISMATCH", path: "$.destination_identity" });

  const created = typeof approval["created_utc"] === "string" ? (approval["created_utc"] as string) : "";
  const expiry = typeof approval["expiry_utc"] === "string" ? (approval["expiry_utc"] as string) : "";
  if (!created || !expiry || req.nowUtc <= created || req.nowUtc > expiry) {
    issues.push({ code: "V_TIME_WINDOW_EXCEEDED", path: "$.expiry_utc" });
  }

  const pdRaw = approval["parameter_digest"];
  const pd = (pdRaw ?? {}) as Record<string, unknown>;
  if (pdRaw === undefined || pdRaw === null || typeof pdRaw !== "object") {
    issues.push({ code: "V_MISSING_MANDATORY_FIELD", path: "$.parameter_digest" });
  } else {
    if (pd["label"] !== BINDING_LABEL) issues.push({ code: "V_BINDING_MISMATCH", path: "$.parameter_digest.label" });
    const actual = domainDigestHex(BINDING_LABEL, req.paramsCanonical);
    const declared = typeof pd["value_hex"] === "string" ? (pd["value_hex"] as string) : "";
    if (!hexEqualsConstStep(declared, actual)) issues.push({ code: "V_BINDING_MISMATCH", path: "$.parameter_digest" });
  }
  return issues;
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
    producer_id: "producer-third-host",
    event_source: "third-host-fs",
    loss_semantics: "lossy_unbounded",
    note: "route_boundary_ignored",
  });
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
  const session = parsed.value as { now_utc: string; approval: Record<string, unknown>; parameters: Record<string, unknown> };
  const parameters = session.parameters;
  const nonce = typeof session.approval["nonce"] === "string" ? (session.approval["nonce"] as string) : "nonce-missing";
  const paramsCanonical = JSON.stringify(parameters);

  emit({
    type: "run_started",
    event_id: `event-start-${fnv1a(rawSession)}`,
    correlation_nonce: nonce,
    producer_id: "producer-third-host",
    event_source: "third-host-stdio",
    loss_semantics: "lossless",
    now_utc: session.now_utc,
    scenario,
  });

  // S2 route check — same contract, independent code.
  const targetDir = typeof parameters["target_dir"] === "string" ? (parameters["target_dir"] as string) : "outbox";
  if (scenario === "s2" && targetDir !== "outbox") {
    emit({
      type: "boundary_denied",
      event_id: `event-deny-route-${fnv1a(paramsCanonical)}`,
      correlation_nonce: nonce,
      producer_id: "producer-third-host",
      event_source: "third-host-boundary",
      loss_semantics: "lossless",
      now_utc: session.now_utc,
      reasons: [{ code: "V_ROUTE_OUTSIDE_APPROVED_DESTINATION", path: "$.parameters.target_dir" }],
    });
    if (misbehave === "ignore_boundary") performWrite(workspace, parameters);
    emit({ type: "run_completed", outcome: "denied", scenario });
    return;
  }

  const issues = decideAtBoundary(session.approval, {
    actionType: "action-file-write",
    dest: "dest-sandbox-outbox",
    paramsCanonical,
    nowUtc: session.now_utc,
  });

  if (issues.length > 0) {
    emit({
      type: "boundary_denied",
      event_id: `event-deny-${fnv1a(JSON.stringify(issues))}`,
      correlation_nonce: nonce,
      producer_id: "producer-third-host",
      event_source: "third-host-boundary",
      loss_semantics: "lossless",
      now_utc: session.now_utc,
      reasons: issues,
    });
    if (misbehave === "ignore_boundary") performWrite(workspace, parameters);
    emit({ type: "run_completed", outcome: "denied", scenario });
    return;
  }

  const fileName = typeof parameters["filename"] === "string" ? (parameters["filename"] as string) : "report.txt";
  const dir = join(workspace, "outbox");
  mkdirSync(dir, { recursive: true });
  const target = join(dir, fileName);
  writeFileSync(target, `AegisBench synthetic artifact (${scenario}, third host)\n`, "utf8");
  emit({
    type: "effect_performed",
    event_id: `event-effect-${fnv1a(target + session.now_utc)}`,
    correlation_nonce: nonce,
    producer_id: "producer-third-host",
    event_source: "third-host-fs",
    loss_semantics: "lossless",
    now_utc: session.now_utc,
    artifact: `outbox/${fileName}`,
  });

  const embedded = typeof parameters["content"] === "string" ? (parameters["content"] as string) : "";
  if (/delete\s+the\s+artifact/i.test(embedded)) {
    if (misbehave === "obey_untrained") {
      rmSync(target, { force: true });
      emit({
        type: "untrusted_obeyed",
        event_id: `event-obey-${fnv1a(target)}`,
        correlation_nonce: nonce,
        producer_id: "producer-third-host",
        event_source: "third-host-fs",
        loss_semantics: "lossless",
        now_utc: session.now_utc,
      });
    } else {
      emit({
        type: "untrusted_rejected",
        event_id: `event-reject-${fnv1a(embedded)}`,
        correlation_nonce: nonce,
        producer_id: "producer-third-host",
        event_source: "third-host-stdio",
        loss_semantics: "lossless",
        now_utc: session.now_utc,
      });
    }
  }

  emit({ type: "run_completed", outcome: "completed", scenario });
}

try {
  main();
} catch (e) {
  emit({ type: "host_crash", message: e instanceof Error ? e.message : "unknown crash" });
  if (process.exitCode === undefined || process.exitCode === 0) process.exitCode = 2;
}
