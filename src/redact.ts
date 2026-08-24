/**
 * AegisBench — deterministic redaction scanner (M0 Slice 4a).
 *
 * Contract references: MASTER_PROMPT.md §7 (pre-acceptance scan; reject raw
 * canary / raw ephemeral secret matches; record scanner version, ruleset
 * digest, scope, result, limitations) and §2 (ephemeral secrets never appear
 * raw in source, logs, artifacts, bundles, snapshots).
 *
 * Binding decisions pinned in docs/implementation-plan.md (Slice 4a):
 *  - ruleset `ab.redact-rules/1`, declarative rules compiled once;
 *  - findings carry OFFSETS ONLY — the matched raw value never enters the
 *    record (enforced by tests);
 *  - the record embeds the AB-JCS-1 domain digest of the canonical ruleset
 *    text under label `redaction_ruleset` for reproducible audits;
 *  - records are deterministic: identical inputs ⇒ byte-identical output.
 *
 * Zero dependencies. Erasable TS syntax only.
 */

import { canonicalize, type JsonValue } from "./canon.ts";
import { DIGEST_LABELS, domainDigestHex } from "./digest.ts";

export const SCANNER_VERSION = "ab-redact-scanner/1";
export const RULESET_ID = "ab.redact-rules";
export const RULESET_VERSION = "ab.redact-rules/1";

interface RuleDecl {
  readonly id: string;
  readonly description: string;
  /** ECMAScript regex source; compiled with NO flags unless declared. */
  readonly source: string;
  readonly flags?: string;
}

/**
 * Ruleset v1 — deliberately narrow; see plan limitations. Extending requires
 * a new version literal and a new pinned section in docs/implementation-plan.md.
 */
const RULESET_V1: readonly RuleDecl[] = [
  {
    id: "canary_token",
    description: "AegisBench synthetic canary token",
    source: "AB_CANARY_[0-9a-f]{32}",
  },
  {
    id: "private_key_pem",
    description: "PEM private key header",
    source: "-----BEGIN[A-Z ]*PRIVATE KEY-----",
  },
  {
    id: "aws_access_key_id",
    description: "AWS access key ID shape",
    source: "AKIA[0-9A-Z]{16}",
  },
  {
    id: "bearer_token",
    description: "Bearer credential prefix",
    source: "Bearer [A-Za-z0-9_-]{20,}",
  },
  {
    id: "secret_assignment",
    description: "Assignment to password/secret/api-key/token names",
    // Value alternatives: double-quoted | single-quoted | bare (no quotes/
    // whitespace/terminators). Covers password=hunter2, API_KEY: sk-live,
    // token='abc', secret="multi part".
    source: `(password|secret|api[_-]?key|token)["']?\\s*[:=]\\s*("[^"]*"|'[^']*'|[^"',;\\s)]+)`,
    flags: "i",
  },
];

interface CompiledRule {
  readonly decl: RuleDecl;
  readonly re: RegExp;
}

const COMPILED_RULES: readonly CompiledRule[] = RULESET_V1.map((decl) => ({
  decl,
  re: new RegExp(decl.source, decl.flags === undefined ? "g" : `${decl.flags}g`),
}));

/** Canonical JSON document describing the ruleset (data only, no RegExp). */
function rulesetDocument(): JsonValue {
  return {
    ruleset_id: RULESET_ID,
    version: RULESET_VERSION,
    rules: RULESET_V1.map((r) =>
      r.flags === undefined
        ? { id: r.id, description: r.description, source: r.source }
        : { id: r.id, description: r.description, source: r.source, flags: r.flags },
    ),
  };
}

let cachedRulesetText: string | undefined;

function rulesetCanonicalText(): string {
  if (cachedRulesetText === undefined) {
    const c = canonicalize(rulesetDocument());
    if (!c.ok) {
      // A static document failing canonicalization is an implementation bug.
      throw new Error(`ruleset failed canonicalization: ${JSON.stringify(c.errors)}`);
    }
    cachedRulesetText = c.canonicalText;
  }
  return cachedRulesetText;
}

let cachedRulesetDigest: string | undefined;

/** AB-JCS-1 domain digest of the canonical ruleset text (label registry). */
export function redactionRulesetDigest(): string {
  if (cachedRulesetDigest === undefined) {
    const d = domainDigestHex(DIGEST_LABELS.redactionRuleset, Buffer.from(rulesetCanonicalText(), "utf8"));
    if (!d.ok) throw new Error("ruleset digest computation failed");
    cachedRulesetDigest = d.hex;
  }
  return cachedRulesetDigest;
}

export interface RedactionFinding {
  readonly rule_id: string;
  readonly scope_index: number;
  /** UTF-16 code-unit start offset within the scanned item. */
  readonly start: number;
  /** UTF-16 code-unit end offset (exclusive). */
  readonly end: number;
  readonly length: number;
}

export interface ScanRecord {
  readonly scanner_version: typeof SCANNER_VERSION;
  readonly ruleset_id: typeof RULESET_ID;
  readonly ruleset_version: typeof RULESET_VERSION;
  readonly ruleset_digest: string;
  readonly scope: readonly string[];
  readonly scanned_items: number;
  readonly findings: readonly RedactionFinding[];
  readonly clean: boolean;
  readonly limitations: readonly string[];
}

const LIMITATIONS: readonly string[] = [
  "single-pass regular expressions over UTF-16 code units",
  "no entropy scoring; bare high-entropy strings are not flagged by design",
  "offsets are UTF-16 code-unit positions, not byte or grapheme positions",
  "ruleset covers only the declared patterns of ab.redact-rules/1",
  "encoding-transform evasion (e.g. base64-wrapped secrets) is out of scope",
];

export type ScanScope = "artifact_text" | "report_text" | "log_line" | "fixture_text" | "string";

/**
 * Deterministically scan the given strings. Identical inputs produce
 * byte-identical ScanRecords (stable ordering; no clock, no randomness).
 */
export function scanForSecrets(items: readonly string[], scope: readonly ScanScope[]): ScanRecord {
  const findings: RedactionFinding[] = [];
  for (let i = 0; i < items.length; i++) {
    const text = items[i] ?? "";
    for (const { decl, re } of COMPILED_RULES) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        findings.push({
          rule_id: decl.id,
          scope_index: i,
          start: m.index,
          end: m.index + m[0].length,
          length: m[0].length,
        });
        if (m[0].length === 0) break; // zero-width safety; no v1 rule is zero-width
      }
    }
  }
  // Deterministic ordering independent of rule iteration order.
  findings.sort(
    (a, b) =>
      a.scope_index - b.scope_index ||
      a.start - b.start ||
      a.end - b.end ||
      (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0),
  );
  return {
    scanner_version: SCANNER_VERSION,
    ruleset_id: RULESET_ID,
    ruleset_version: RULESET_VERSION,
    ruleset_digest: redactionRulesetDigest(),
    scope,
    scanned_items: items.length,
    findings,
    clean: findings.length === 0,
    limitations: LIMITATIONS,
  };
}
