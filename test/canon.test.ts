/**
 * Tests: AB-JCS-1 deterministic canonicalization interface (M0 Slice 1).
 * Includes RFC 8785 compatibility vectors (within its data model), key-order
 * independence, and SAME-BYTES-across-separate-processes determinism evidence.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { canonicalize } from "../src/canon.ts";
import { parseStrict } from "../src/json.ts";

test("key order independence: canonical bytes depend on value, not insertion order", () => {
  const a = canonicalize({ b: 1, a: 2 });
  const b = canonicalize({ a: 2, b: 1 });
  assert.ok(a.ok && b.ok);
  if (!(a.ok && b.ok)) return;
  assert.equal(a.canonicalText, '{"a":2,"b":1}');
  assert.equal(a.canonicalText, b.canonicalText);
});

test("parse -> canonicalize round trip normalizes formatting", () => {
  const r = parseStrict('{ "b" : 1 , "a" : [ true , null , "x" ] }');
  assert.ok(r.ok);
  if (!r.ok) return;
  const c = canonicalize(r.value);
  assert.ok(c.ok);
  if (!c.ok) return;
  assert.equal(c.canonicalText, '{"a":[true,null,"x"],"b":1}');
  assert.equal(c.profile, "AB-JCS-1");
});

test("RFC 8785 number serialization vectors (within its data model)", () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['{"v":4.50}', '{"v":4.5}'],
    ['{"v":1E30}', '{"v":1e+30}'],
    ['{"v":2e-3}', '{"v":0.002}'],
    ['{"v":0.000000000000000000000000001}', '{"v":1e-27}'],
    ['{"v":333333333.3}', '{"v":333333333.3}'],
    ['{"v":123456789012345678901234567890}', '{"v":1.2345678901234568e+29}'],
  ];
  for (const [input, expected] of cases) {
    const p = parseStrict(input);
    assert.ok(p.ok, `parse failed for ${input}`);
    if (!p.ok) continue;
    const c = canonicalize(p.value);
    assert.ok(c.ok, `canon failed for ${input}`);
    if (!c.ok) continue;
    assert.equal(c.canonicalText, expected, `mismatch for ${input}`);
  }
});

test("RFC 8785 string escaping vectors", () => {
  const p = parseStrict('{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\u000a":"Newline"}');
  assert.ok(p.ok);
  if (!p.ok) return;
  const c = canonicalize(p.value);
  assert.ok(c.ok);
  if (!c.ok) return;
  assert.equal(c.canonicalText, '{"\\n":"Newline","\\r":"Carriage Return","€":"Euro Sign"}');
});

test("non-finite and -0 inputs are rejected by the canonicalizer", () => {
  const c1 = canonicalize({ a: Number.NaN });
  assert.ok(!c1.ok);
  if (!c1.ok) assert.equal(c1.errors[0]?.code, "C_NOT_FINITE");
  const c2 = canonicalize({ a: Infinity });
  assert.ok(!c2.ok);
  const c3 = canonicalize({ a: -0 });
  assert.ok(!c3.ok);
  if (!c3.ok) assert.equal(c3.errors[0]?.code, "C_NEGATIVE_ZERO");
});

// ---------------------------------------------------------------------------
// Cross-process determinism: the same logical value canonicalized in TWO
// SEPARATE node processes must yield identical SHA-256 over the UTF-8 bytes.
// ---------------------------------------------------------------------------

const SAMPLE_JSON =
  '{"z":[1,0.5,-2e24,1e30,0.002],"a":{"€":"Euro Sign"},"m":{"kéy":true,"K":null,"k":[false,null]},"seq":"\\ud83d\\ude00"}';

function sha256OfCanonicalFromFreshProcess(): string {
  const moduleUrl = new URL("../src/canon.ts", import.meta.url).href;
  const probe = [
    `import { canonicalize } from ${JSON.stringify(moduleUrl)};`,
    `import { createHash } from "node:crypto";`,
    `const v = JSON.parse(${JSON.stringify(SAMPLE_JSON)});`,
    `const r = canonicalize(v);`,
    `if (!r.ok) throw new Error("canon failed: " + JSON.stringify(r.errors));`,
    `console.log(createHash("sha256").update(Buffer.from(r.canonicalText, "utf8")).digest("hex"));`,
  ].join("\n");
  const stdout = execFileSync(process.execPath, ["--input-type=module", "-e", probe], {
    encoding: "utf8",
  }).trim();
  assert.match(stdout, /^[0-9a-f]{64}$/);
  return stdout;
}

test("identical canonical SHA-256 across two independent processes", () => {
  const h1 = sha256OfCanonicalFromFreshProcess();
  const h2 = sha256OfCanonicalFromFreshProcess();
  assert.equal(h1, h2, "cross-process canonical bytes diverged");

  // And the local in-process computation must agree with the child processes.
  const p = parseStrict(SAMPLE_JSON);
  assert.ok(p.ok);
  if (!p.ok) return;
  const c = canonicalize(p.value);
  assert.ok(c.ok);
  if (!c.ok) return;
  const localHash = createHash("sha256").update(Buffer.from(c.canonicalText, "utf8")).digest("hex");
  assert.equal(localHash, h1);
});
