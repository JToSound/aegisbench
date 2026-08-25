# AegisBench

Evidence-bounded compliance assurance for synthetic agent-host scenarios.
Built strictly to the governing contract in [`MASTER_PROMPT.md`](MASTER_PROMPT.md)
(v7.0) — deterministic, offline-first, **zero runtime dependencies**,
erasable-TypeScript-only on Node ≥ 22.

> ## What this project claims — and does not claim
>
> Every verdict-bearing artifact carries the machine-bound
> [`AB-NOTICE-001`](src/report.ts) assurance notice. Claims produced here are
> **narrow, per-scenario, and fixture-scoped**:
>
> - Maximum evidence class: `fixture_conformance` (the hosts under test are
>   fixtures inside this repository).
> - Claim admissibility can reach `admissible` only via the pinned mechanical
>   path (pass verdict + all-pairs observer independence); even then it is an
>   admissible claim **about the fixtures**, worded exactly as each
>   measurement plan's predicates state.
> - **No claims** are made about VM/container/OS isolation, general
>   prompt-injection resistance, or production readiness. Each scenario is
>   one deterministic trial; no statistical bounds (§8) are claimed.
>
> Details: [`docs/m1h-pilot-plan.md`](docs/m1h-pilot-plan.md) (threat models,
> controls, ceilings) and [`docs/implementation-plan.md`](docs/implementation-plan.md)
> (per-slice binding decisions + outcome logs).

## What is here

| Layer | Path | Notes |
|---|---|---|
| Strict JSON parser | `src/json.ts` | Duplicate-key rejection before materialization, I-JSON limits, stable error codes |
| Canonicalization | `src/canon.ts` | AB-JCS-1 (RFC 8785-compatible domain), rejects `-0`/non-finite |
| Domain-separated digests | `src/digest.ts` | Length-prefixed SHA-256 layout, label registry |
| Evidence envelopes / events | `src/schema.ts`, `src/events.ts` | Integrity-bound payloads, trace invariants |
| Redaction scanner | `src/redact.ts` | Findings carry offsets only — never raw matches |
| Policy oracle | `src/policy.ts` | §4 decision order 1–6, consistency gates, claim-admissibility ceiling |
| Reports | `src/report.ts`, `src/verify.ts`, `src/cli.ts` | Builder cannot omit AB-NOTICE-001; redaction gate scans finalized text |
| Route inventory / approvals / observers / measurement plans | `src/routes.ts`, `src/approval.ts`, `src/observers.ts`, `src/controls.ts` | Mechanical derivation and judgment; no ordinal scores anywhere |
| Subject hosts ×3 | `hosts/*/main.ts` | Independently written effect-boundary decisions; identical external contract |
| Pilot tests | `test/` | Conforming+fault twins across ALL hosts; seeded property tests; mutation tests |
| Consumer SDK | `sdk/aegisbench-client.mjs` | Zero-dep harness primitives (not published to any registry) |
| Offline report viewer | `tools/report-viewer.html` | Standalone HTML; nothing leaves the window |

## Quick start

```bash
node --test          # 205 deterministic tests; no install step
pnpm run typecheck   # tsc strict gate (devDeps: typescript + @types/node)

# Verdict pipeline over a scenario fixture:
node src/cli.ts fixtures/scenarios/pass.json            # exit 0 = pass
node src/cli.ts fixtures/rejected/canary-dup-key.json   # single-line stderr error, exit 10
```

Exit-code contract: `0` pass · `1` fail · `2` inconclusive · `3`
not_supported · `4` not_run · `5` invalid_run · `10` parse · `11` validate ·
`12` reserved · `13` usage.

## Design invariants

- **Zero runtime dependencies** — Node built-ins only; devDeps exist solely
  for the type gate.
- **Byte-determinism** — LF everywhere (`.gitattributes`), canonical bytes
  independent of key insertion order, session-declared time (hosts never
  read a clock).
- **Collect-all-violations** — validators name every defect, never just the
  first.
- **Disclosure-bounded failures** — denial messages are fixed strings;
  findings carry offsets, never matched secrets.
- **Honest negative results** — fault twins must fail for a scenario to
  pass; failed controls are surfaced by id, never averaged away.

## Status

M0 (deterministic core), M1 (assurance integrity), M1-H (three-subject host
pilot with three-plane observers) — complete; CI green on Node 22 ×
ubuntu/windows. See the implementation plan for the full commit-by-commit
audit trail.

## License

[MIT](LICENSE) — © 2026 JToSound. The governing technical contract
([`MASTER_PROMPT.md`](MASTER_PROMPT.md)) and the assurance notices embedded
in artifacts remain authoritative for any claims made with this system;
the license grants no rights to present fixture-scoped results as
real-world guarantees.
