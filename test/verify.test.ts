/**
 * Golden contract tests: offline verifier CLI (M0 Slice 5b).
 * Pins exit codes, stream discipline (one line / one document), byte
 * stability, notice presence, and secret-suppression on diagnostics for all
 * 11 fixtures, plus one real subprocess smoke of the documented command.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { ASSURANCE_NOTICE_ID, ASSURANCE_NOTICE_TEXT } from "../src/report.ts";
import { RESERVED_EXIT_CODES, VERDICT_EXIT_CODES, runCli } from "../src/verify.ts";

const CANARY = "AB_CANARY_0123456789abcdef0123456789abcdef";

function capture(argv: readonly string[]): { exitCode: number; out: string; err: string } {
  const out: string[] = [];
  const err: string[] = [];
  const r = runCli(argv, {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
  });
  return { exitCode: r.exitCode, out: out.join(""), err: err.join("") };
}

// ---------------------------------------------------------------------------
// Verdict scenarios — pinned exit codes, stream discipline, stability
// ---------------------------------------------------------------------------

const SCENARIOS: ReadonlyArray<readonly [string, number]> = [
  ["fixtures/scenarios/pass.json", VERDICT_EXIT_CODES["pass"] ?? -1],
  ["fixtures/scenarios/fail.json", VERDICT_EXIT_CODES["fail"] ?? -1],
  ["fixtures/scenarios/inconclusive.json", VERDICT_EXIT_CODES["inconclusive"] ?? -1],
  ["fixtures/scenarios/not-supported.json", VERDICT_EXIT_CODES["not_supported"] ?? -1],
  ["fixtures/scenarios/not-run.json", VERDICT_EXIT_CODES["not_run"] ?? -1],
  ["fixtures/scenarios/invalid-run.json", VERDICT_EXIT_CODES["invalid_run"] ?? -1],
];

for (const [file, expectedExit] of SCENARIOS) {
  test(`scenario ${file} → exit ${expectedExit}, clean streams, stable bytes`, () => {
    const a = capture([file]);
    assert.equal(a.exitCode, expectedExit);
    assert.equal(a.err, "", "stderr must be empty on verdict success");
    assert.ok(a.out.endsWith("\n"));
    assert.equal(a.out.split("\n").length, 2, "exactly one output line");
    const doc = JSON.parse(a.out) as Record<string, unknown>;
    assert.equal(doc["assurance_notice_id"], ASSURANCE_NOTICE_ID);
    const manifest = doc["notice_manifest"] as Record<string, unknown>;
    assert.equal(manifest["notice_text"], ASSURANCE_NOTICE_TEXT);

    const b = capture([file]);
    assert.equal(b.out, a.out, "byte-identical across invocations");

    // Human format carries the notice verbatim and stays stable too.
    const h = capture(["--format", "human", file].length === 3 ? ["--format", "human", file] : [file]);
    assert.ok(h.out.includes(ASSURANCE_NOTICE_TEXT));
  });
}

test("verdict field matches the fixture's expected class", () => {
  const expectations: ReadonlyArray<readonly [string, string]> = [
    ["pass", "pass"],
    ["fail", "fail"],
    ["inconclusive", "inconclusive"],
    ["not-supported", "not_supported"],
    ["not-run", "not_run"],
    ["invalid-run", "invalid_run"],
  ];
  for (const [name, verdict] of expectations) {
    const r = capture([`fixtures/scenarios/${name}.json`]);
    assert.equal(r.exitCode, VERDICT_EXIT_CODES[verdict]);
    const doc = JSON.parse(r.out) as Record<string, unknown>;
    assert.equal(doc["verdict"], verdict, name);
  }
});

test("not_run report omits run_validity; others carry it", () => {
  const nr = JSON.parse(capture(["fixtures/scenarios/not-run.json"]).out) as Record<string, unknown>;
  assert.ok(!("run_validity" in nr));
  const ps = JSON.parse(capture(["fixtures/scenarios/pass.json"]).out) as Record<string, unknown>;
  assert.equal(ps["run_validity"], "valid");
});

// ---------------------------------------------------------------------------
// Rejections — pinned codes, single-line stderr, empty stdout
// ---------------------------------------------------------------------------

const REJECTIONS: ReadonlyArray<readonly [string, number, string, string]> = [
  ["fixtures/rejected/duplicate-key.json", 10, "parse", "E_DUPLICATE_KEY"],
  ["fixtures/rejected/canary-dup-key.json", 10, "parse", "E_DUPLICATE_KEY"],
  ["fixtures/rejected/unknown-schema.json", 11, "validate", "V_UNKNOWN_SCHEMA_VERSION"],
  ["fixtures/rejected/inconsistent-gates.json", 11, "validate", "V_INCONSISTENT_INPUT"],
  ["fixtures/rejected/missing-mandatory.json", 11, "validate", "V_MISSING_MANDATORY_FIELD"],
];

for (const [file, exit, stage, code] of REJECTIONS) {
  test(`rejection ${file} → exit ${exit}, one-line ${stage} diagnostic`, () => {
    const r = capture([file]);
    assert.equal(r.exitCode, exit);
    assert.equal(r.out, "", "stdout must be empty on rejection");
    const lines = r.err.split("\n");
    assert.equal(lines.length, 2, "exactly one stderr line + newline");
    assert.match(
      r.err,
      /^aegisbench error stage=(?:parse|validate|redaction) code=[A-Z_]+ path=(?:\[suppressed by redaction scanner\]|\S+)(?: \[suppressed by redaction scanner\])? message=.+\n$/,
    );
  });
}

test("canary duplicate key never reaches stderr verbatim", () => {
  const r = capture(["fixtures/rejected/canary-dup-key.json"]);
  assert.equal(r.exitCode, 10);
  assert.ok(!r.err.includes(CANARY), "raw canary leaked into stderr");
  assert.ok(r.err.includes("[suppressed by redaction scanner]"));
});

test("reserved exit code 12 is documented but never produced by M0 pipeline", () => {
  assert.ok(RESERVED_EXIT_CODES["12"] !== undefined);
  for (const [file] of SCENARIOS) {
    const r = capture([file]);
    assert.notEqual(r.exitCode, 12, file);
  }
});

test("usage errors: missing file, bad flag, unreadable file → exit 13", () => {
  assert.equal(capture([]).exitCode, 13);
  assert.equal(capture(["--format", "yaml", "x.json"]).exitCode, 13);
  const r = capture(["fixtures/does-not-exist.json"]);
  assert.equal(r.exitCode, 13);
  assert.match(r.err, /^aegisbench error stage=usage code=U_READ /);
});

// ---------------------------------------------------------------------------
// Real subprocess smoke of the documented command line
// ---------------------------------------------------------------------------

test("subprocess smoke: node src/cli.ts fixtures/scenarios/pass.json", () => {
  const stdout = execFileSync(process.execPath, ["src/cli.ts", "fixtures/scenarios/pass.json"], {
    encoding: "utf8",
  });
  const doc = JSON.parse(stdout) as Record<string, unknown>;
  assert.equal(doc["verdict"], "pass");
  assert.equal(doc["assurance_notice_id"], ASSURANCE_NOTICE_ID);

  const failRun = (() => {
    try {
      execFileSync(process.execPath, ["src/cli.ts", "fixtures/scenarios/fail.json"], {
        encoding: "utf8",
      });
      return null;
    } catch (e) {
      return e as { status: number };
    }
  })();
  assert.ok(failRun !== null);
  assert.equal(failRun?.status, VERDICT_EXIT_CODES["fail"]);
});
