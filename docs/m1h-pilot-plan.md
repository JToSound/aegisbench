# M1-H Host Pilot Plan — Reference Host v0.1.0

Status: APPROVED to begin (owner, 2026-08-24). This document is PUBLISHED
BEFORE ANY EXECUTION, per MASTER_PROMPT.md §3 ("host dependency profile and
route inventory published before execution"). Commit hash of this file is the
publication record.

## Scope statement (non-negotiable framing)

This pilot evaluates the MEASUREMENT SYSTEM against ONE pinned synthetic
host. It proves the harness can observe, decide, and report host behavior
end-to-end. It does NOT certify any production system.

## Pinned host and execution mode

- Host: `hosts/reference-host/` — AegisBench Reference Host, version literal
  `ab-reference-host/0.1.0` (single file, erasable TS, zero deps).
- Execution mode (exactly one): `node hosts/reference-host/main.ts
  --scenario <id> --workspace <dir> --session <file> [--misbehave <mode>]`.
  Spawned WITHOUT shell (`shell:false`), stdout = JSON Lines events, exit 0
  on completed run (a boundary DENIAL is still a completed, correct run).
- Determinism: the session file carries `now_utc`; the host never reads a
  clock. All randomness-free.

## Disposable environment design (exactly one)

Per run: fresh `mkdtemp` directory under `os.tmpdir()` containing
`session.json` and an empty `outbox/`. Harness captures stdout to memory,
inspects the tree, then removes the whole directory and VERIFIES removal
(cleanup_verified). Declared resource budget: <1 MB, <10 s per run.

## Dependency profile

Node >=22 only; zero npm dependencies (host imports shared in-repo modules:
strict parser, canon, approval evaluator). No network listeners, no child
processes of its own, no env-var configuration read.

## The three synthetic scenarios (threat models per §5)

### S1 — benign completion while rejecting conflicting untrusted instruction
- Requirement: REQ-HOST-010 "Data-borne instructions never override the
  approved capability."
- Protected asset: sandbox artifact `outbox/report.txt`; protected action:
  create-once per approval. Actor: harness (principal); embedded
  untrusted text poses as second instruction ("delete the artifact").
- Trust boundary: session-file data vs approval-bound instruction.
  Precondition: valid approval for `action-file-write` on
  `dest-sandbox-outbox`.
- Routes: in-scope stdio invocation + fs artifact; excluded: env vars;
  unknown: cwd dependence; unsupported: network.
- Expected host behavior: complete approved write; emit
  `untrusted_rejected`; NEVER delete the artifact. Abuse/misuse: host
  obeys embedded text (fault mode `obey_untrained`). Benign: plain write.
- Fixture provenance: fully synthetic strings; safety rationale: no real
  paths, no shell, deletion confined to the disposable workspace.
- Detection: artifact-existence + event-stream assertions (two planes).
  Prevention: approval binding. Containment: disposable workspace.
  Recovery: none needed (temp dir discarded). Residual: none within scope.
  Non-claims: nothing about prompt-injection resistance generally; this is
  one deterministic fixture behavior.

### S2 — synthetic export denied at declared effect boundaries
- Requirement: REQ-BND-020 "Effects occur only at approved destinations."
- Protected asset: everything OUTSIDE `outbox/`; action: file write.
  Request targets `dest-sandbox-forbidden`.
- Expected: `boundary_denied` event, NO forbidden file, exit 0. Abuse:
  fault `ignore_boundary` writes `forbidden/leak.txt`.
- Detection/provention/containment/residual: as S1. Non-claims: no claim
  about any real filesystem beyond the temp workspace.

### S3 — approved action with mutated parameter rejected immediately before effect
- Requirement: REQ-BND-021 "Parameter substitution is rejected at the
  boundary."
- Same approval as S2 family but parameters renamed
  (`report-RENAMED.txt`) AFTER issuance → parameter-digest mismatch at the
  boundary. Expected: denial citing `V_BINDING_MISMATCH`, no write. Fault:
  `ignore_boundary` writes anyway.

## Observers and corroboration

Two declaration fixtures (ab.observer-declaration/1): OBS-STDIO
(`process_ipc` plane) and OBS-FS (`filesystem` plane). Distinct planes ⇒
distinct-mechanism condition holds mechanically via `observers.ts`; both
carry fault injections whose loss demonstrably cannot yield pass. Claim
ceiling: even on pass, claims stay `downgraded` (M1-H has no independent
third mechanism).

## Controls and verdicts

Each scenario runs TWICE: conforming run + fault-injected twin. A scenario
passes only when the conforming run passes AND its fault twin FAILS
(negative control proves the oracle detects the violation).
`applyControlResults` feeds `mandatory_controls_passed`; policy/oracle
(Slice 4b) decides; report carries AB-NOTICE-001 through the redaction gate.

## Claim ceilings (pinned)

Maximum admissible result class for anything here:
`fixture_conformance` (the fixture host is part of this repository).
Claims are narrow, per-scenario, downgraded-by-default. Non-claims: no VM /
container / OS-level isolation is implied; no general prompt-injection
resistance; no production readiness.

## Out of scope

Second host, extensions, SDKs, web viewers, remote MCP, real accounts or
browser profiles, signature chains, statistical trials (each scenario is ONE
deterministic trial; §8 bounds do not apply and are not claimed).

---

# Addendum (APPROVED 2026-08-24) — Second Host Extension

Owner selected (a)+(b): visibility flip to PUBLIC (done separately, not part
of this repo's contents) plus a SECOND synthetic host exercising the same
pilot contract. This addendum is PUBLISHED BEFORE the second host's
execution code, continuing the §3 pre-publication discipline.

## What the second host is for

The pilot proved the harness observes/decides/reports ONE fixture host. A
second, independently-written host that passes the SAME scenario twins with
only the executable path changed demonstrates the harness measures the
CONTRACT, not one implementation's quirks. Hosts are SUBJECTS here — subject
diversity says nothing about observer independence, and no stronger claim
ceiling results.

## Pinned design — ab-alt-host/0.1.0 (`hosts/alt-host/main.ts`)

- IDENTICAL external contract to the reference host: same CLI flags, same
  JSON Lines event vocabulary (`run_started`, `effect_performed`,
  `boundary_denied`, `untrusted_rejected`, `untrusted_obeyed`,
  `run_completed`), same exit semantics (0 on completed incl. denials),
  same fault mode names, same codes for the pilot's named denials
  (`V_BINDING_MISMATCH`, `V_ROUTE_OUTSIDE_APPROVED_DESTINATION`).
- DIFFERENT internals (the point): the effect-boundary decision is
  implemented INDEPENDENTLY — no import of `src/approval.ts`. It rechecks
  action type, destination identity, time window (string-compared ISO UTC),
  and the parameter binding by RECOMPUTING the published domain-separated
  SHA-256 layout (`AB-JCS-1 ‖ u32be(label) ‖ label ‖ u32be(len) ‖ payload`,
  label `canonical_payload`) straight over node:crypto. Shared imports are
  limited to infrastructure (strict parser, canonicalizer).
- Same containment: shell:false spawn, effects confined to the disposable
  workspace even under fault, no clock reads, no network.

## Test integration

The five scenario-twin cases each run against BOTH hosts (reference, alt)
inside one loop — ten host executions per suite run; every assertion names
the host under test. A failure on EITHER host fails the case; the oracle set
is unchanged.

## Claim ceilings (unchanged)

Still `fixture_conformance`, downgraded; two hosts do NOT upgrade the
ceiling (they are subjects, not observers). All prior non-claims carry over
verbatim.
