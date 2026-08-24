# AegisBench Implementation Plan — M0 Slice 1

Governing contract: `MASTER_PROMPT.md` v7.0. This document is created before any
code change, per §1 rule 3, and covers only the approved M0 Slice 1 scope.

## Objective

Establish the smallest deterministic foundation of the AegisBench offline core:

1. strict JSON input handling with duplicate-key rejection **before** normal
   object materialization;
2. versioned schema validation for the evidence-bundle envelope;
3. semantic validation for required identifiers and duplicate IDs;
4. a deterministic canonicalization interface (AB-JCS-1 profile skeleton);
5. deterministic tests covering: valid input, malformed JSON, duplicate keys,
   unknown schema version, missing mandatory fields.

## Bounded acceptance criteria

- `node --test test/` exits 0 with all listed cases passing on Node ≥22.
- Duplicate-key JSON input fails in the parse stage with no object produced from
  the duplicated text; failure message identifies the duplicate key path.
- Unknown `schema` version and missing mandatory fields fail in the validate
  stage with stable machine-readable error codes; neither can ever yield pass.
- Canonicalization is pure: same logical value ⇒ identical UTF-8 byte output,
  verified across two separate processes.
- Runtime dependencies: **zero** (Node built-ins only). No lockfile change.
- No file outside this slice's declared set is created or modified.

## Affected requirement IDs

- §7 AB-JCS-1 definition subset: UTF-8, I-JSON constraints, duplicate-key
  rejection before materialization, finite numbers, max depth/document/string/
  array size, canonical field ordering, restricted ASCII ID syntax, SHA-256
  domain-separation labels (labels defined; digest use lands in Slice 2).
- §3 M0 "strict JSON input parser", "schema and semantic invariant validation",
  "canonicalization profile AB-JCS-1" (interface + reference implementation
  skeleton only).
- §4 verdict vocabulary constants are declared but no oracle logic yet.

Explicitly out of scope for Slice 1 (deferred): digests module, event envelopes,
policy/oracle decision order, report generation, redaction scanner, CLI/verifier,
fixtures as files, exit-code contract.

## Assumptions and unknowns

- Node 22.23.2 type stripping (`node file.ts`) supports erasable-only TS syntax;
  **verified by probe 2026-08-24** (`strip-ok`, exit 0; `enum` correctly rejected
  as ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX). Sources use erasable syntax only;
  zero-dependency approach adopted, no fallback needed.
- AB-JCS-1 numeric parameters not pinned by the contract are proposed here and
  become binding when first committed:
  - maximum depth 64, maximum document size 1 MiB, maximum string 65536 bytes,
    maximum array/object member count 10000;
  - numbers: I-JSON finite IEEE-754 doubles, serialized shortest round-trip
    (ECMAScript `Number::toString` semantics, RFC 8785-compatible for values in
    its data model); `-0` rejected at parse time;
  - restricted ASCII ID syntax: `^[A-Za-z][A-Za-z0-9_-]{0,127}$`.
- Bundle envelope schema id: `ab-evidence-envelope`, supported version literal
  `ab.evidence-envelope/1`. Unknown versions must fail validation.
- `prompts/` empty directory has no expected content; left untouched.

## Threat / safety impact

Positive: earlier rejection of malformed/hostile JSON reduces parser attack
surface; duplicate-key rejection removes an ambiguity class that could later be
exploited to smuggle contradictory evidence past downstream validators.
No new network, credential, filesystem-outside-workspace, or process surface is
introduced. Nothing here can produce a pass verdict — the slice contains no
oracle.

## Intended commands

- `node --test test/` — run the deterministic test suite after each meaningful
  change (smallest relevant test per §1 rule 5).
- `node --input-type=module -e …` one-off probes (type-stripping smoke;
  cross-process determinism check). Probes write nothing to disk.

## Commands intentionally not run and why

- `pnpm install` / any dependency install: zero-dependency slice; also gated on
  explicit approval by operator instruction.
- `git add/commit/init`: operator forbade staging/committing in Slice 1.
- Any formatter (`prettier` etc.): no broad reformat permitted; formatting is
  authored directly.
- `pnpm typecheck` via a global tsc: none installed locally without approval;
  Node's own load-time type stripping exercises the sources, and full `tsc`
  gating is deferred to the tooling slice.

## Rollback path

Slice 1 touches only new files (`docs/implementation-plan.md`, `package.json`,
`tsconfig.json`, `src/*.ts`, `test/*.ts`). Rollback = delete those files; no
shared state exists yet. `MASTER_PROMPT.md` and `prompts/` remain untouched.

## Explicit non-goals for this change

M1 items, M1-H host pilot, host adapters, GitHub Actions, VS Code integration,
web viewer, remote MCP, signatures/trust roots, report rendering, redaction
scanner, policy/oracle, CLI, fixtures-as-artifacts, CI, publishing anything.

## Outcome log (2026-08-24)

Final state: 33/33 tests pass (`node --test`, exit 0); three independent
processes produced byte-identical AB-JCS-1 canonical text and SHA-256
`d5a20dc21245ab548aa5953ce457599f408fa4c63cec52fc7a8cb83a38a2f845`.

Failures encountered during the slice and their resolutions (preserved, none
weakened):

1. Node strip-only mode rejects TypeScript **enum** (probe) — sources restricted
   to erasable syntax.
2. Node strip-only mode rejects **parameter properties** (`constructor(readonly
   x: T)`) — `StrictParseFailure` rewritten with explicit field declaration.
   Found by first real test run; all three suites failed to load.
3. Real parser bug found by tests: surrogate-pair lookahead consumed one
   character too many after the first `\uXXXX` escape, rejecting every valid
   astral character (`😀`) as E_LONE_SURROGATE. Fixed in src/json.ts; paired-
   escape test now passes alongside the lone-surrogate rejections.
4. Test-authoring errors (not product bugs): wrong expected key ordering
   (`\n` U+000A sorts before `\r` U+000D in UTF-16 order — implementation was
   correct), and passing a URL object where `execFileSync` needed a string URL.
   Assertions corrected to the verified-correct values; no test weakened.

---

# M0 Slice 2 — Domain-Separated Integrity Digests

## Objective

Implement `src/digest.ts`: SHA-256 digests with AB-JCS-1 domain separation
(MASTER_PROMPT.md §7 "SHA-256 domain separation labels"), the integrity
primitive consumed by every later surface. Plus deterministic tests:
known-answer, tamper detection, boundary-ambiguity resistance, cross-process
determinism, label validation.

## Binding byte layout (pinned here; normative)

```
digest = SHA-256(
  UTF8("AB-JCS-1")                      ||
  uint32bigendian(byteLength(label))    ||
  UTF8(label)                           ||
  uint32bigendian(byteLength(payload))  ||
  payload
)
```

Length prefixes make `(label, payload)` splitting unambiguous: no payload can
masquerade as part of a label or vice versa. Digest-label grammar:
`^[a-z][a-z0-9_.-]{0,63}$`. Registered labels start with `canonical_payload`
(over AB-JCS-1 canonical text bytes); registry extends by appending only.
Verification uses `crypto.timingSafeEqual`. Hex form: lowercase, 64 chars.

## Bounded acceptance criteria

- Known-answer test pins a fixed input's digest to a literal hex value.
- Flipping any single payload byte changes the digest (tamper detection).
- Ambiguous splits (`("a","bc…")` vs `("ab","c…")`) never collide.
- Invalid labels are rejected with stable error codes, never silently hashed.
- Same input ⇒ identical hex across separate processes.
- Still zero runtime dependencies.

## Affected requirement IDs

§3 M0 "SHA-256 domain-separated integrity digests"; §7 domain-separation
labels. Out of scope: signatures/trust roots (§7 defers these), event
envelopes, redaction scanning, keyed commitments/HMAC.

## Threat / safety impact

Positive: unambiguous construction prevents boundary-confusion forgery of
evidence identifiers; constant-time comparison avoids leaking match-prefix
lengths. No new I/O or network surface.

## Commands / rollback / non-goals

Same policy as Slice 1: only `node --test`; no installs, no git, no network.
Rollback = delete `src/digest.ts` + `test/digest.test.ts` + this section.

### Outcome log (2026-08-24)

41/41 tests pass (`node --test`, exit 0) — 33 carried from Slice 1 plus 8 new.
Known-answer vectors were computed independently from the pinned layout with
raw `node:crypto` (not via src/digest.ts) and then pinned as literals:
`{"a":1}`→`e49056da…fda05d`, `abc`→`18a9ed14…587299`, split-resistance
vectors `abe4aa93…d8f6a5` / `af94b233…f6a3a72`. Cross-process digest equality
verified in fresh child processes. No failures occurred in this slice's test
runs; no tests were weakened. Pending owner approvals (unchanged): git
baseline commit; one-time devDependency install for the tsc gate.

---

# M0 Slice 3 — Normalized Event Envelope and Trace Invariants

## Objective

Implement `src/events.ts`: the versioned event envelope (`ab.event/1`) with
the §6 mandatory fields, plus trace-level semantic invariants when events are
evaluated as a set ("event trace"). This is the first slice that CONSUMES
Slices 1–2: each event carries an inline `payload` whose AB-JCS-1 canonical
digest is recomputed and compared, making tampering detectable end-to-end.

## Binding decisions (pinned here; normative proposals)

- Envelope `$schema` literal: `"ab.event/1"`.
- Mandatory fields: `event_id`, `correlation_nonce`, `producer_id`,
  `event_source`, `loss_semantics`, `payload`, `payload_digest`.
- Restricted-ID syntax (Slice 1) applies to `event_id`, `correlation_nonce`,
  `producer_id`, `event_source`, and every `causal_predecessors` entry.
- Optional fields: `sequence` (integer 0..2^53-1), `timestamp_utc`,
  `timestamp_uncertainty_ms`, `causal_predecessors`.
  - `timestamp_uncertainty_ms` requires `timestamp_utc` (orphan = violation);
    uncertainty must be finite > 0.
  - `timestamp_utc` minimal shape gate: RFC 3339 UTC (`…Z`) regex; full
    calendar validation deferred.
- `loss_semantics` closed set: `lossless | lossy_bounded | lossy_unbounded`.
- `payload_digest` shape: `{ algorithm: "sha256", label: "canonical_payload",
  value_hex: <64 lowercase hex> }`; the verifier RECANONICALIZES `payload`
  and recomputes the Slice 2 digest; mismatch ⇒ `V_DIGEST_MISMATCH`.

## Trace-level invariants (list of events, order given)

- `event_id` unique across the trace (`V_DUPLICATE_ID`).
- Every `causal_predecessors` entry resolves to an event in the same trace
  (`V_UNRESOLVED_REFERENCE` — first consumer of the code reserved in Slice 1);
  self-reference rejected (`V_CAUSAL_SELF_REFERENCE`).
- Causal relation must be acyclic (`V_CAUSAL_CYCLE`, deterministic DFS order).
- Where present, `sequence` is strictly increasing per `producer_id` in trace
  order (`V_SEQUENCE_NOT_MONOTONIC`).

## Bounded acceptance criteria

- Valid single event and valid multi-event chain pass; tampered payload or
  forged digest both yield `V_DIGEST_MISMATCH`.
- Missing mandatory fields, unknown schema version, invalid IDs, extra fields,
  orphan uncertainty, malformed timestamp each yield their stable code.
- Duplicate IDs, unresolved/self/cyclic predecessors, non-monotonic sequences
  detected at trace level.
- Zero dependencies maintained; `node --test` green.

## Affected requirement IDs

§3 M0 "normalized event envelope and decision trace" (envelope half; decision
trace lands with the policy/oracle slice); §6 event field list; §7 semantic
invariants (unique IDs, no unresolved evidence references, acyclic relations).

## Threat / safety impact

Positive: inline digest binding makes silent evidence mutation detectable at
validation time; uniqueness/reference/cycle rules prevent contradictory or
forged causal narratives from entering later verdict logic. No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/events.ts` + `test/events.test.ts` + this section. Non-goals: observer
declarations/FCZ graphs, approval capabilities, ordering-model proofs,
decision-trace generation (oracle slice).

### Outcome log (2026-08-24)

63/63 tests pass (`node --test`, exit 0) — 41 carried from Slices 1–2 plus 22
new. One test-authoring error found and fixed: an "independent expectation"
was built as the RAW sha256 of canonical text instead of the pinned
domain-separated layout; corrected by reconstructing the layout manually in
the test from docs/implementation-plan.md (still not via src/digest.ts) and
adding a negative control asserting the digest differs from the raw hash.
Implementation needed no changes in this slice. Pending owner approvals
(unchanged): git baseline commit; one-time devDependency install for tsc gate.

---

# M0 Slice 4a — Deterministic Redaction Scanner

## Objective

Implement `src/redact.ts`: deterministic pre-acceptance redaction scan per
MASTER_PROMPT.md §7 ("Before accepting an artifact: run deterministic redaction
scan; reject raw canary pattern matches; reject raw ephemeral secret pattern
matches; record scanner version, ruleset digest, scope, result, and
limitations") and §2 (ephemeral secrets never appear raw in any artifact).

## Binding decisions (pinned here; normative proposals)

- Ruleset identity: `ab.redact-rules`, version literal `ab.redact-rules/1`.
- Rules are declarative data `{id, description, source}` (ECMAScript regex
  source); compiled once at module load. Ruleset v1 (narrow, deliberate):
  - `canary_token`: `AB_CANARY_[0-9a-f]{32}` (this project's declared canary
    format; fixtures adopt it in a later slice);
  - `private_key_pem`: `-----BEGIN[A-Z ]*PRIVATE KEY-----`;
  - `aws_access_key_id`: `AKIA[0-9A-Z]{16}`;
  - `bearer_token`: `Bearer [A-Za-z0-9_-]{20,}`;
  - `secret_assignment`: `(password|secret|api[_-]?key|token)["']?\s*[:=]\s*("[^"]*"|'[^']*'|[^"',;\s)]+)`
    (case-insensitive; covers bare, double-quoted, and single-quoted values —
    revised pre-commit after the original class missed `token='x'`).
- Deliberate NON-rules (documented limitation): bare high-entropy hex/base64
  strings are NOT flagged — 64-hex payload digests are legitimate evidence and
  must survive scanning. Entropy analysis deferred.
- Self-description: the ruleset canonicalizes via Slice 1 `canonicalize` and
  digests via Slice 2 under new registry label `redaction_ruleset` (appended,
  per registry append-only policy). The scan RECORD embeds this digest so any
  artifact's acceptance is auditable against the exact ruleset bytes.
- Finding contents: `{rule_id, scope_index, start, end, length}` ONLY — UTF-16
  code-unit offsets. The matched raw value MUST NEVER appear in the record
  (§2); a test enforces this by serializing the whole record and asserting no
  canary byte leaks.
- Record: `{scanner_version, ruleset_id, ruleset_version, ruleset_digest,
  scope[], scanned_items, findings[], clean, limitations[]}`; deterministic
  ordering (scope_index, start, end, rule_id); identical inputs ⇒ identical
  record bytes.
- Limitations declared in every record: single-pass regex; no entropy scoring;
  UTF-16 offsets; ruleset covers only declared patterns; encoding-normalizing
  evasion (e.g. base64-wrapped secrets) out of scope for v1.

## Bounded acceptance criteria

- Each v1 rule detects its synthetic fixture; clean input yields zero findings.
- Whole serialized record never contains any matched raw value.
- Ruleset digest equals an independently reconstructed domain digest.
- Two scans of the same inputs produce byte-identical records.
- Legit 64-hex digest text is NOT flagged (negative control).
- Zero dependencies maintained; `node --test` green.

## Affected requirement IDs

§7 redaction-scan clause; §2 ephemeral-secret handling. Out of scope:
keyed-commitment comparison helpers, artifact storage, quarantine flows.

## Threat / safety impact

Positive: prevents raw canaries/ephemeral secrets from entering accepted
artifacts; embedded ruleset digest makes future audits reproducible. Risk
noted: false negatives (pattern gap) and false positives (noise) — mitigated
by pinned ruleset + declared limitations, not by silent tolerance.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/redact.ts` + `test/redact.test.ts` + revert this section and the
DIGEST_LABELS appendix. Non-goals: entropy heuristics, ML classifiers,
encoding-transform sweeps, filesystem crawling.

### Outcome log (2026-08-24)

72/72 tests pass (`node --test`, exit 0) — 63 carried from Slices 1–3 plus 9
new. One REAL ruleset gap found by tests before any commit: the pinned
`secret_assignment` value class excluded quote characters, so
`token='abc123'` went undetected. Fixed by revising the rule to three value
alternatives (double-quoted | single-quoted | bare); plan section, source,
independent test reconstruction, and the pinned ruleset digest were updated
together (new digest `d5dac764…b1a1e2`). A shell-probe transcription error was
also caught pre-pinning (backslash mangling produced a wrong candidate
digest) — the pinned KAT was taken from the live module instead, then
cross-checked against the in-test independent rebuild. Pending owner
approvals (unchanged): git baseline commit; one-time devDependency install
for tsc gate.

---

# M0 Slice 4b Outcome Log (2026-08-24)

94/94 tests pass (`node --test`, exit 0) — 72 carried from Slices 1–4a plus
22 new covering decision steps 1–6, precedence, consistency gate, structural
validation, determinism, and the admissibility ceiling. Implementation was
self-reviewed before first test run (dead code and a wrong-reason attribution
in step-2 citations removed pre-emptively). One TEST-fixture semantic error
found and fixed: the not_run fixture reused passing-template gate values
(true) instead of honest not-run facts (false) — the implementation's
consistency gate correctly rejected it; fixture corrected, no implementation
or assertion weakened. Pending owner approvals (unchanged): git baseline
commit; one-time devDependency install for tsc gate.

---

# M0 Slice 5a — Report Model with AB-NOTICE-001 Binding

## Objective

Implement `src/report.ts`: the versioned report artifact (`ab.report/1`) in
which EVERY verdict-bearing artifact carries `"assurance_notice_id":
"AB-NOTICE-001"` by construction; the root notice manifest binds the ID to
the exact required notice text and its declared digests; human-facing
rendering includes the notice verbatim; finalization runs the Slice 4a
redaction scan over all rendered texts BEFORE anything is accepted.

## Binding decisions (pinned here; normative proposals)

- Notice text (verbatim from MASTER_PROMPT.md §0):
  `AegisBench evaluates observable behavior in synthetic, versioned test environments. A passing result is not a security guarantee, certification, or proof of production safety.`
- Root manifest declares BOTH digests: `utf8_sha256_hex` (raw SHA-256 over
  the UTF-8 notice bytes — universally recomputable) and `ab_jcs1_digest_hex`
  (Slice 2 domain digest under new registry label `assurance_notice`,
  appended append-only).
- Artifact schema `ab.report/1` mandatory fields: `$schema`, `report_id`
  (restricted ID), `scenario_id`, `verdict` (six-value set), `run_validity`
  (optional; absent exactly when verdict=`not_run`, mirroring Slice 4b),
  `aggregation_rule`, `reasons[]`, `assurance_notice_id`, `notice_manifest`.
  Optional: `bundle_id`, `created_utc` (RFC 3339 UTC shape), `notes`.
- The builder refuses to construct a verdict-bearing artifact without the
  notice block (no code path omits it); the independent validator
  `validateReportArtifact` re-checks: notice id equality, manifest text/
  digest equality against the pinned constants, run_validity⇔verdict
  coupling (`not_run` ⇔ absent; otherwise required).
- `finalizeReportArtifact`: renders canonical JSON text + human text,
  scans BOTH with Slice 4a scanner (scope `artifact_text`), embeds the ScanRecord,
  returns `{ok:false, stage:"redaction", record}` on ANY finding — no partial
  artifact escapes. Clean records make the finalized artifact deterministic.
- Out of scope: file writing, exit codes, CLI wiring, statistical sections.

## Bounded acceptance criteria

- Every built artifact contains the notice id + manifest; validator rejects
  missing/wrong id, tampered text, wrong digests, and verdict/run_validity
  mismatches.
- Manifest digest values match independently reconstructed computations.
- Human text contains the notice verbatim (exact substring).
- An input note containing a synthetic canary makes finalize fail with a
  redaction record and NO artifact output.
- Byte-identical outputs for identical inputs; zero dependencies; suite green.

## Threat / safety impact

Positive: claim language cannot exceed evidence because reports carry only
the oracle's verdict/reasons plus the mandatory limiting notice; redaction
gate prevents leaking fixture secrets into accepted reports. No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/report.ts` + `test/report.test.ts` + this section + the
`assurance_notice` label appendix.

### Outcome log (2026-08-24)

104/104 tests pass (`node --test`, exit 0) — 94 carried from Slices 1–4b plus
10 new. One REAL implementation bug caught by tests: finalizeReportArtifact
read a nonexistent `canon.canonicalJson` field (actual: `canonicalText`),
which would have made the finalized canonical text `undefined` AND silently
reduced the redaction gate to scanning empty strings. Fixed by binding the
exact field; the redaction gate now demonstrably scans both rendered texts
(the canary-note test fails without the fix). Two test-authoring slips were
also corrected pre-run (a meaningless assertion and over-narrow type
guarding). Pending owner approvals (unchanged): git baseline commit;
one-time devDependency install for tsc gate.

---

# M0 Slice 5b Outcome Log (2026-08-24) — M0 CLOSED

121/121 tests pass (`node --test`, exit 0) — 104 carried from Slices 1–5a
plus 17 new golden-contract tests over all 11 fixtures and one real
subprocess smoke.

Live demonstration of the M0 primary success condition (documented command):
- `node src/cli.ts fixtures/scenarios/pass.json` → canonical report JSON on
  stdout carrying `assurance_notice_id: "AB-NOTICE-001"`, the verbatim notice
  text, both manifest digests (`utf8_sha256_hex` 2982210a…, `ab_jcs1_digest_hex`
  7364b0e5…), exit 0; stderr empty; byte-stable across runs.
- `node src/cli.ts fixtures/rejected/canary-dup-key.json` → empty stdout,
  ONE stderr line `stage=parse code=E_DUPLICATE_KEY` with BOTH path and
  message suppressed by the redaction scanner, exit 10.

Failures encountered in this slice (all fixed, none weakened):

1. REAL semantic gap: policy outcomes for steps 3–5 lacked run_validity,
   which the report builder requires for non-not_run verdicts. Fixed per §4
   decision-order semantics — any run reaching step 3+ has already passed
   step-2 validity, so its honest run_validity is "valid" (fail,
   not_supported, and all three inconclusive branches updated).
2. Test-authoring slips: a broken regex expecting no spaces in suppressed
   fields, and a corrupted patch line (`const const`) caught immediately by
   readback before running tests.

Pending owner approvals (unchanged): git baseline commit; one-time
devDependency install to enable the tsc type gate. M0 remaining per contract
§3 is now limited to items deliberately deferred with justification:
property-based/mutation tests and the CI workflow (M1 scope), plus
signature/trust roots (explicitly post-M0).

---

# M1 Slice 2 Outcome Log (2026-08-24)

149/149 tests pass (`node --test`, exit 0) — 137 carried from M1 Slice 1
plus 12 new covering issuance integrity (independent digest reconstruction;
six-field tamper matrix), effect-boundary revalidation (four binding-mismatch
classes with fixed-message evidence; inclusive time-window edges; replay;
multi-violation collection), disclosure-bounded denials (canary-checked), and
immutability of consumption.

No implementation failures this slice; one pre-test self-review cleanup
(a meaningless defensive expression in consumeApproval). Pending owner
approvals (unchanged): git baseline commit; one-time devDependency install
for tsc gate.

---

# M1 Slice 3 — Observer Declarations and Independence Vectors

## Objective

Implement `src/observers.ts`: the §6 observer declaration schema
(`ab.observer-declaration/1`) and the MECHANICAL judgment of
"independently corroborating" evidence between two observers — explicitly
WITHOUT any ordinal independence score (§6 forbids one).

## Binding decisions (pinned here; normative proposals)

- Declaration fields: `$schema`, `observer_id`, `version` (restricted IDs);
  `implementation_digest {algorithm:"sha256", label, value_hex}` (declared;
  recomputation needs the implementation bytes, which are out of scope);
  `bootstrap_provenance`, `source` (non-empty ≤256);
  `observation_plane` ∈ `process_ipc | filesystem | api_boundary |
  admin_plane | network_loopback | clock_service`;
  `enforcement_capability` (bool); `loss_semantics` (events.ts closed set).
- `owners{}`: all nine §6 custodies mandatory, each a non-empty principal
  string: process, runtime, admin_plane, configuration, artifact_writer,
  clock, policy_source, fixture_source, keys.
- `host_privileges{}`: write/read/signal/debug/lifecycle/configuration/
  sockets/mounts, all mandatory booleans (inventory of what the HOST has).
- `independence_vector{}`: code/configuration/lifecycle/data_path/
  artifact_path/clock/policy/administration/key_custody, all mandatory
  booleans (observer independent of host per dimension).
- Graph structures: `fcz_nodes[{fcz_id,description}]` (≥1),
  `fcz_edges[{from_fcz_id,to_fcz_id}]` (must resolve),
  `blind_spots[{fcz_id?,description}]` (fcz_id must resolve when present),
  `unmitigated_forge_suppress_fcz_ids[]` (must resolve),
  `liveness_checks[]`, `health_checks[]`
  (`{check_id,description}`; may be empty),
  `fault_injections[{fault_id,description,demonstrates_loss_cannot_yield_pass}]`,
  `host_control_paths_declared[]` (honest inventory; strings).
- Corroboration judgment `isIndependentlyCorroborating(a,b)` evaluates the
  FIVE §6 conditions mechanically and names every failure:
  1. distinct mechanisms: planes differ OR FCZ id sets are disjoint;
  2. intersection of `unmitigated_forge_suppress_fcz_ids` is empty;
  3. host cannot control either observer:
     `host_control_paths_declared` empty AND
     !(host_privileges.debug ∨ host_privileges.lifecycle) for BOTH;
  4. trust paths declared: `bootstrap_provenance` + `implementation_digest`
     + every independence_vector dimension true for BOTH;
  5. loss/corruption cannot yield pass: at least one fault injection with
     `demonstrates_loss_cannot_yield_pass:true` for BOTH.
- Output shape carries NO numeric score anywhere (test-enforced).

## Bounded acceptance criteria

- Valid pair corroborates; breaking EACH condition alone flips the verdict
  with that condition named.
- Structural classes (closed sets, nine-field completeness, graph reference
  resolution, digest shape) each have a dedicated rejection test.
- Zero dependencies maintained; full suite green.

## Threat / safety impact

Positive: replaces prose claims of "independent observers" with a checkable
five-condition gate; ordinal-score gaming becomes impossible by construction.
No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/observers.ts` + `test/observers.test.ts` + this section. Non-goals:
runtime observer implementation, FCZ analysis tooling, quorum math.

---

# M1 Slice 1 Outcome Log (2026-08-24)

137/137 tests pass (`node --test`, exit 0) — 121 carried from M0 plus 16 new
covering the closed route vocabulary, mechanical derivation, exact-list
validation, cross-reference integrity, narrative-field enforcement, and the
bounded-negative-claim gate.

One REAL implementation issue found by tests and fixed: coverage-closure
validation short-circuited on narrative-field issues BEFORE comparing id
lists, hiding list mismatches from `missing[]` — violating this project's
collect-all-violations pattern. Early return now fires only when a document
view is unusable (version gates). One test-authoring slip corrected
afterwards: an over-guessing count assertion replaced with the exact count
(2) for that fixture.

Pending owner approvals (unchanged): git baseline commit; one-time
devDependency install for tsc gate.

---

# M1 Slice 2 — Single-Use Integrity-Bound Approval Capabilities

## Objective

Implement `src/approval.ts`: the approval capability model of MASTER_PROMPT.md
§6 — "An approval is a single-use integrity-bound capability, not a UI
acknowledgement" — including issuance-time binding, integrity self-description,
immutable consumption, and the pure revalidation decision taken immediately
before the effect boundary.

## Binding decisions (pinned here; normative proposals)

- Schema literal `ab.approval/1`. Bound fields (ALL mandatory):
  `approval_id`, `issuer_id`, `subject_id`, `session_id`, `scenario_id`,
  `policy_version`, `action_type`, `canonicalization_profile`,
  `parameter_digest {algorithm,label,value_hex}`, `destination_identity`,
  `nonce`, `execution_correlation`, `created_utc`, `expiry_utc`;
  plus `approval_digest` (self-integrity) and `consumption_state`
  (mutable tail). Restricted-ID syntax applies to the five *_id fields,
  `policy_version`, `action_type`, `canonicalization_profile`, `nonce`,
  `execution_correlation`. `destination_identity`: non-empty string ≤256,
  no ASCII control chars. Timestamps: RFC 3339 UTC shape.
- Integrity: `approval_digest` = AB-JCS-1 domain digest (new registry label
  `approval_binding`, appended append-only) over the canonical text of the
  binding-field set EXCLUDING `approval_digest` and `consumption_state`
  (so single-use consumption never breaks binding integrity).
- Ordering uses `Date.parse` (fractional-second-safe); shape stays gated by
  the RFC 3339 regex.
- Effect-boundary decision `evaluateApprovalAtEffectBoundary(doc, req)` with
  `req = {action_type, parameters_canonical_text, destination_identity,
  now_utc, execution_correlation}` collects ALL violations: structural +
  digest integrity + every binding equality + time window (`created_utc ≤
  now ≤ expiry_utc`) + replay (`consumption_state.consumed ⇒
  V_ALREADY_CONSUMED`). Allow ⇔ zero issues. The denial record carries
  issue codes/paths/fixed messages ONLY — raw parameter material cannot
  appear (no message interpolates request values); enforced by test.
- `consumeApproval(doc, consumed_at_utc)` returns a NEW document with
  `{consumed:true, consumed_at_utc}`; the input object is never mutated
  (immutability by construction, pinned). Consuming requires structural
  validity + not-yet-consumed.

## Bounded acceptance criteria

- Builder output validates; digest matches an independent reconstruction.
- Tampering ANY bound field flips the digest (V_DIGEST_MISMATCH).
- Each binding mismatch, both time-window edges, and replay have dedicated
  denial tests; allow requires exact agreement everywhere.
- Denial records contain no raw parameter text even when parameters embed
  canary-shaped material (scanner-checked).
- Immutability: consumption does not mutate its input.
- Zero dependencies maintained; full suite green.

## Threat / safety impact

Positive: approvals stop being UI acknowledgements — replayed, expired,
retargeted, or parameter-substituted capabilities are mechanically denied
with evidence whose disclosure is bounded by construction. No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/approval.ts` + `test/approval.test.ts` + this section + the
`approval_binding` label appendix. Non-goals: issuance ceremony/UI, key
custody, signature chains, revocation lists, policy engines.

---

# M1 Slice 1 — Route Inventory and Coverage-Closure Model

## Objective

Implement `src/routes.ts`: the closed route vocabulary, route-inventory
schema (`ab.route-inventory/1`), coverage-closure schema
(`ab.coverage-closure/1`), mechanical closure derivation, and the bounded-
negative-claim support gate — MASTER_PROMPT.md §5 ("Routes use exactly …";
"Only coverage_closed_for_route_set may support a bounded negative claim").
First M1 slice; consumes only Slice 1 primitives (restricted IDs).

## Binding decisions (pinned here; normative proposals)

- Route classifications (closed, exact): `mediated_tested |
  mediated_untested | observed_only | excluded_declared | unknown_possible |
  unsupported_by_subject`.
- Inventory document: `$schema`, `inventory_id` (restricted ID), `routes[]`
  (each `{route_id, classification, description?}`; no other fields; ≥1
  entry; unique route_ids).
- Closure derivation (mechanical, therefore auditable):
  - `included_routes`   ≡ ids classified `mediated_tested` ∪ `observed_only`
    (inventory order);
  - `excluded_routes`   ≡ `excluded_declared`;
  - `unknown_possible_routes` ≡ `unknown_possible`;
  - `mediated_untested` and `unsupported_by_subject` ids appear in NO list —
    they are visibly uncovered by construction.
- Closure document adds the mandatory narrative fields of §5:
  `closure_id`, `based_on_inventory_id`,
  `process_identity_assumption`, `enforcement_point`,
  `observer_liveness_evidence[]` (≥1 non-empty string),
  `interval_start_utc` ≤ `interval_end_utc` (RFC 3339 UTC shape),
  `clock_uncertainty_ms` (finite > 0), `residual_uncertainty` (non-empty).
- Validation = structure + exact equality of each id list against the
  derivation over the paired inventory + disjointness implied thereby +
  interval ordering. Any mismatch ⇒ `V_ROUTE_LIST_MISMATCH` /
  `V_UNRESOLVED_REFERENCE` / `V_INCONSISTENT_INPUT`.
- `supportsBoundedNegativeClaim(closure, inventory)` ⇒
  `{supported:true}` only when the closure validates completely; otherwise
  `{supported:false, missing:[…]}` naming every failed requirement.

## Bounded acceptance criteria

- Round trip: derive skeleton from a valid inventory, fill narratives,
  validate ⇒ ok; tampering any id list ⇒ precise mismatch code.
- Each closed-set violation, duplicate id, unresolved reference, unordered
  interval, and missing narrative field has a dedicated test.
- Claim gate refuses incomplete closures with actionable `missing[]`.
- Zero dependencies maintained; full suite green.

## Threat / safety impact

Positive: bounded negative claims become mechanically checkable instead of
prose assertions; untested mediated routes stay visibly outside every closure
list, preventing silent coverage inflation. No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/routes.ts` + `test/routes.test.ts` + this section. Non-goals: FCZ
graphs, observer declarations, control-result model, claim wording engine.

---

# M0 Slice 5b — Offline Verifier CLI, Fixtures, Exit-Code Contract (M0 close)

## Objective

Implement `src/verify.ts` (pure pipeline) and `src/cli.ts` (thin entrypoint),
plus fixture files and golden tests, delivering the M0 primary success
condition: a clean operator can run the reference bundle through the offline
verifier and get deterministic, explainable results.

## Binding decisions (pinned here; normative proposals)

- M0 input document = `ab.policy-input/1` (the full evidence-bundle container
  grows in M1 with events/observers; pinned explicitly to avoid pretending
  more structure exists than does).
- Pipeline: strict parse → policy/oracle decision → report build (notice
  binding) → independent validation → render → redaction gate. No step may
  be skipped; failures short-circuit with exactly one diagnostic line.
- Identity derivation (deterministic): `report_id = "report-" + first 16 hex
  of the AB-JCS-1 domain digest (label canonical_payload) over the canonical
  text of the parsed input`; `scenario_id = "scenario-under-test"` (constant;
  real scenario IDs arrive with the bundle schema in M1).
- CLI: `node src/cli.ts <file|-> [--format=json|human]`. Default json.
  - Success (verdict computed): stdout = finalized canonical JSON + `\n`
    (human: rendered human text + `\n`); stderr EMPTY.
  - Any rejection: stdout EMPTY; stderr = ONE line
    `aegisbench error stage=<s> code=<c> path=<p> message=<m>` (fixed order);
    no partial artifacts ever printed.
- Exit-code contract (stable, documented; automation reads the JSON):
  - 0 pass · 1 fail · 2 inconclusive · 3 not_supported · 4 not_run ·
    5 invalid_run   (verified-run verdict classes)
  - 10 parse-stage rejection · 11 validate-stage rejection ·
    12 redaction-gate rejection · 13 usage error.
- Fixtures: `fixtures/scenarios/{pass,fail,inconclusive,not-supported,
  not-run,invalid-run}.json` and `fixtures/rejected/{duplicate-key,
  unknown-schema,inconsistent-gates,missing-mandatory,canary-dup-key}.json`.
  Honesty note (amended pre-implementation): the M0 report contains NO
  input-derived free text (reasons are step citations; scenario_id is
  constant), so no input can drive the report-side redaction gate; exit 12 is
  therefore RESERVED and documented as such. Instead `canary-dup-key.json`
  carries a duplicated object key whose name matches the canary rule,
  proving the CLI suppresses raw secret material from stderr diagnostics
  (the echoed key text must never reach the terminal verbatim).
- Golden tests run `runCli` in-process against every fixture (exact exit +
  stdout/stderr shape + stability), plus ONE real subprocess smoke of the
  documented command line.

## Bounded acceptance criteria

- All 11 fixtures produce their pinned exit code; pass fixture stdout is
  byte-stable across invocations and carries AB-NOTICE-001.
- Every rejection prints exactly one stderr line and empty stdout.
- The canary-dup-key stderr line contains NO raw canary text (suppressed),
  while ordinary diagnostics keep their message field intact.
- Zero dependencies maintained; full suite green; subprocess smoke green.

## Threat / safety impact

Positive: deterministic exit codes and single-line diagnostics make the tool
scriptable without scraping prose; the redaction gate demonstrably blocks a
legal-looking canary ID before any artifact is emitted. No new I/O beyond
reading the named input file.

## Commands / rollback / non-goals

Only `node --test` and one subprocess invocation of the documented CLI
command; no installs/git/network. Rollback = delete `src/verify.ts`,
`src/cli.ts`, `test/verify.test.ts`, `fixtures/`, this section. Non-goals:
stdin streaming modes, config files, globbing, parallel runs, colored output.

---

# M0 Slice 4b — Deterministic Policy/Oracle (§4 Decision Order)

## Objective

Implement `src/policy.ts`: the versioned deterministic oracle that maps a
structured scenario-evaluation input to `run_validity` + `scenario_verdict`,
implementing MASTER_PROMPT.md §4 decision order 1–6 exactly, plus the pass
gates and the claim-admissibility ceiling helper.

## Binding decisions (pinned here; normative proposals)

- Input schema literal: `"ab.policy-input/1"`; aggregation rule id:
  `"ab.verdict-aggregation/1"`.
- Input fields: `$schema`, `intentionally_unexecuted`, `execution_status`
  (closed 6-value set), `failure_classes` (closed set: `setup |
  containment | mandatory_observer | integrity | correlation | control |
  teardown`), `capability_present`, `violation_detected`, `evidence_state`
  (`present | absent | contradictory | ambiguous | cannot_discriminate`),
  `property_outcomes` (≥1; `property_id` restricted-ID, unique; `predicate ∈
  pass | violation | insufficient_evidence`), `cleanup_verified`,
  `artifacts_reference_closed`, `observers_healthy`,
  `mandatory_controls_passed`, `unresolved_critical_contradiction`.
- Consistency validation BEFORE deciding (stable code `V_INCONSISTENT_INPUT`):
  `teardown ⇔ !cleanup_verified`; `mandatory_observer ⇔ !observers_healthy`;
  `control ⇔ !mandatory_controls_passed`; `integrity ⇔
  !artifacts_reference_closed`; `violation_detected ⇔ ≥1 outcome with
  predicate "violation"`.
- Decision order (verbatim semantics):
  1. intentionally unexecuted → `not_run` (run_validity left unset — validity
     of a non-run is meaningless; pinned).
  2. any failure class, or `execution_status ∈ {blocked, aborted}` →
     run_validity=`invalid`, verdict=`invalid_run`.
  3. capability absent → `not_supported`.
  4. violation detected → `fail`.
  5. evidence_state ≠ `present`, or unresolved critical contradiction →
     `inconclusive`.
  6. all pass gates (execution_status=`completed`, cleanup verified,
     reference-closed artifacts, healthy observers, mandatory controls passed,
     no unresolved critical contradiction) AND every required property outcome
     `pass` → `pass`; any outcome `insufficient_evidence` at this point →
     `inconclusive`.
  Each outcome carries machine-readable `reasons[]` citing the step fired.
- Claim-admissibility ceiling (pure helper, §4 "a pass never automatically
  makes a claim admissible"): non-pass ⇒ `inadmissible`; pass without
  complete observer-independence evidence ⇒ `downgraded`; pass with complete
  independence evidence ⇒ `admissible`. M0 has NO legitimate producer of
  `complete=true` (observer validation is M1 scope); the flag is an explicit
  input so the ceiling logic is testable now and honest later.
- Out of scope: result_class assignment (requires observer declarations),
  approval capabilities, statistical bounds (§8).

## Bounded acceptance criteria

- Each decision step fires on its dedicated fixture and in correct precedence
  (e.g. failure class beats missing capability beats violation).
- Inconsistent inputs are rejected before any verdict is computed.
- Same input ⇒ byte-identical outcome JSON (determinism test).
- Zero dependencies maintained; `node --test` green.

## Threat / safety impact

Positive: encodes the contract's conservative decision order so weak or
contradictory evidence can never yield pass; consistency checks prevent
forged gate combinations. No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/policy.ts` + `test/policy.test.ts` + this section.

---

# M1 Slice 3 Outcome Log (2026-08-24)

165/165 tests pass (`node --test`, exit 0) — 149 carried from M1 Slice 2
plus 16 new covering the §6 declaration schema (closed planes/loss sets,
nine custodies, eight host privileges, nine independence dimensions, FCZ
graph reference resolution) and the five-condition corroboration judgment
with per-condition isolation tests plus a no-numeric-score shape check.

Two test-fixture errors found by tests and fixed: overriding `fcz_nodes`
without updating `blind_spots` produced structurally invalid fixtures, which
the implementation correctly refuses to judge (invalid input ⇒ named
valid_declaration failure, not a silent verdict). Fixtures made
self-consistent; no implementation or assertion weakened. Implementation ran
green on the first full pass otherwise. Pending owner approvals (unchanged):
git baseline commit; one-time devDependency install for tsc gate.

---

# M1 Slice 4 Outcome Log (2026-08-24)

179/179 tests pass (`node --test`, exit 0) — 165 carried from M1 Slice 3
plus 14 new covering six-kind control completeness (each kind removed in
turn yields its named issue), per-defect-class control-result application
(failed/not_run/missing/unknown surfaced by id, never averaged), and the
requirement matrix (dangling requirement/plan refs, unmapped requirements,
V_UNMAPPED_PLAN, structurally invalid referenced plans — each named).

Implementation ran green on the first full pass; no failures to preserve.
Pending owner approvals (unchanged): git baseline commit; one-time
devDependency install for tsc gate.

---

# M1 Slice 5 Outcome Log (2026-08-24) — M1 CLOSED

188/188 tests pass (`node --test`, exit 0) — 179 carried from Slices 1–4 plus
9 new: four seeded property tests (300 iterations each; round-trip, key-
shuffle invariance, digest stability+sensitivity, generated-envelope
validity) and five mutation/guard tests.

Failures encountered and fixed in this slice:
1. Authoring slip: pinned seed literal `0xAEG15B` was INVALID hex (parser
   rejected it); amended to `0xAE915B` with the plan section updated to match.
2. Real test bug: the P3 mutation helper walked values but NEVER CHANGED
   them, so "mutation undetected" assertions failed — correctly exposing a
   no-op mutator. Replaced with `mutateValue`, a pure always-changes
   transformation with float-safe number handling (avoids -0 and large-
   double addition no-ops).

CI workflow created at `.github/workflows/ci.yml` (node 22 × ubuntu/windows,
smoke import of all 12 modules + `node --test`; no install step, no secrets).
Semantic spot-check passes after stripping comments. Pushing remains
owner-gated. M1 items from contract §3 are now all delivered or explicitly
deferred with justification (host pilot = M1-H, owner-gated).

Pending owner approvals (unchanged): git baseline commit; one-time
devDependency install for tsc gate.

---

# M1 Slice 5 (close) — Property/Mutation Tests and CI Synthetic Workflow

## Objective

Deliver the last two M1 items: property-based tests over the deterministic
core, mutation tests demonstrating that contract oracles kill each pinned
defect class, and the CI synthetic-test workflow (§3 M1 "package smoke import
and CI synthetic test workflow").

## Binding decisions (pinned here; normative proposals)

- Property runner: self-written, seeded PRNG (mulberry32, FIXED seed
  0xAE915B — original "0xAEG15B" was invalid hex and rejected by the parser;
  amended to the nearest valid literal), N=300 iterations per property —
  fully deterministic, no external property library (zero-dep policy).
  Properties:
  P1 round-trip `parseStrict(JSON.stringify(v)) ≟ v`;
  P2 key-shuffle invariance `canon(v) = canon(shuffledKeys(deepCopy(v)))`;
  P3 digest stability + leaf-mutation sensitivity;
  P4 generated-valid envelope passes validateEnvelope.
- Mutation methodology (honest boundary): mutants are DELIBERATELY DEFECTIVE
  REIMPLEMENTATIONS of production algorithm fragments, embedded in the test
  file and exercised against the SAME contract oracles the suite uses. No
  production source file is ever overwritten mid-run. Each mutant documents
  the defect class it represents and the oracle that must reject it:
  M1 unsorted object keys (canon) → killed by key-shuffle invariance;
  M2 digest without length prefixes (digest) → killed by boundary-split
     resistance vectors;
  M3 duplicate keys accepted last-wins (json) → killed by E_DUPLICATE_KEY
     contract;
  M4 `-0` silently normalized (canon/json) → killed by C_NEGATIVE_ZERO /
     E_NEGATIVE_ZERO contract.
  Each test asserts BOTH: oracle rejects mutant output AND real
  implementation satisfies oracle.
- CI: `.github/workflows/ci.yml`, matrix node 22 × [ubuntu-latest,
  windows-latest], steps = checkout + setup-node + `node --test`. No
  install step (zero dependencies), no secrets, no network beyond the
  runner itself. File creation is M1 scope; pushing to any remote remains
  owner-gated.

## Bounded acceptance criteria

- All properties green under their fixed seed; a seed mismatch fails loudly
  (seed asserted in-test).
- All four mutants killed by their named oracles.
- Workflow YAML parses (spot-checked structurally); suite still green.
- Zero dependencies maintained.

## Commands / rollback / non-goals

Only `node --test`; creating `.github/workflows/ci.yml`; NO git/push/install/
network. Rollback = delete both new test files + the workflow file + this
section. Non-goals: fuzzing beyond the bounded generator, coverage tooling,
cross-OS local verification (CI will do that), release automation.

---

# M1 Slice 4 — Measurement Plans, Control Results, Requirement Matrix

## Objective

Implement `src/controls.ts`: the §5 measurement-plan schema
(`ab.measurement-plan/1`) with its mandatory six-kind control set, the
control-result application model that feeds Slice 4b's `control` failure
class, and the requirement-to-test coverage matrix (`ab.requirement-matrix/1`)
validated mechanically against a collection of plans.

## Binding decisions (pinned here; normative proposals)

- Control kinds (§5 exact enumeration): `positive | negative | ambiguity |
  metamorphic | mutation | fault`. A measurement plan MUST declare ≥1 control
  of EACH kind (unique control_ids).
- Plan fields: `$schema`, `plan_id`, `property_id` (restricted IDs);
  `subject_version_binding`, `action_boundary`, `ordering_model`,
  `clock_source` (non-empty ≤256); `temporal_interval{start_utc,end_utc}`
  RFC 3339 UTC shape, start≤end; `clock_uncertainty_ms` finite >0;
  `loss_semantics` (events.ts closed set); `route_inventory_ref` (restricted
  ID — resolved by callers holding inventories); `observation_planes[]` ≥1
  from observers.ts closed planes; `required_controls[{control_id,kind}]`;
  `predicates{pass,fail,inconclusive}` all non-empty;
  `permitted_result_classes[]` ≥1 subset of §4's five classes.
- Control outcomes closed set: `passed | failed | not_run`.
  `applyControlResults(plan, results)` requires exactly one result per
  declared control_id (unknown or missing ids named); returns
  `{complete, allPassed, failedIds, notRunIds, missingIds, unknownIds}`;
  `!allPassed` is the honest producer of Slice 4b's `control` failure input.
- Matrix: `$schema`, `matrix_id`, `requirements[{requirement_id,statement}]`
  (unique ids), `mappings[{requirement_id,plan_id}]`. Validation against a
  plan map names EVERY defect: dangling requirement refs, dangling plan refs,
  requirements with zero mappings, plans never mapped (`V_UNMAPPED_PLAN`),
  and any plan failing its own structural/control-completeness validation.
- Result-class vocabulary reused verbatim from §4: `harness_integrity |
  fixture_conformance | adapter_observed_conformance |
  host_validated_conformance | research_observation`.

## Bounded acceptance criteria

- Valid plan/matrix pass; removing each of the six control kinds yields a
  named missing-kind issue; every dangling/unmapped/failed case has a test.
- applyControlResults handles all four defect classes distinctly.
- Zero dependencies maintained; full suite green.

## Threat / safety impact

Positive: makes "every critical property carries the full §5 control set"
mechanically checkable; untested or failed controls cannot silently support a
measurement claim. No new I/O.

## Commands / rollback / non-goals

Only `node --test`; no installs/git/network. Rollback = delete
`src/controls.ts` + `test/controls.test.ts` + this section. Non-goals:
executing controls, metamorphic relation libraries, statistical bounds (§8),
test-runner integration.

---

# Slice 6 — Baseline Freeze (APPROVED 2026-08-24)

## Objective

Owner approved option (a): initialize version control, commit the complete
M0+M1 state as the immutable baseline, install dev-only dependencies
(typescript + @types/node), and enable the `tsc -p tsconfig.json` type gate.

## Intended commands (approved)

1. Write `.gitattributes` (LF enforcement — byte-determinism requirement)
   and `.gitignore` (node_modules, logs).
2. Add devDependencies to package.json: `typescript ^5`, `@types/node ^22`
   (types only; runtime stays zero-dependency); add `typecheck` script.
3. `pnpm install` — ONE-TIME registry access, explicitly approved; produces
   pnpm-lock.yaml (committed) and node_modules (ignored).
4. `pnpm exec tsc -p tsconfig.json` — fix any real type errors WITHOUT
   weakening strictness.
5. Full `node --test`.
6. `git init -b main` → stage ALL files → single baseline commit.

## Commit identity note

If git has no configured identity, the commit will use `user.name=JToSound`,
`user.email=JToSound@users.noreply.github.com` (owner identity used across
this workspace's projects; GitHub noreply form). Easily amended before any
push; flagged in the delivery report.

## Rollback path

Pre-commit: delete .git directory. Post-install: delete node_modules +
pnpm-lock.yaml to restore the zero-dep state; package.json devDeps revert is
a one-line edit.

## Non-goals

No remote creation, no push, no tags, no branch strategy beyond main; no
release automation. M1-H remains separately gated.
