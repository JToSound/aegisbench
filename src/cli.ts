/**
 * AegisBench CLI entrypoint (M0 Slice 5b).
 *
 * Usage: node src/cli.ts <file|-> [--format=json|human]
 *
 * Exit codes (stable contract, docs/implementation-plan.md Slice 5b):
 *   0 pass · 1 fail · 2 inconclusive · 3 not_supported · 4 not_run ·
 *   5 invalid_run · 10 parse · 11 validate · 12 reserved · 13 usage.
 */
import { runCli } from "./verify.ts";

const out: string[] = [];
const err: string[] = [];
const result = runCli(process.argv.slice(2), {
  stdout: (s) => out.push(s),
  stderr: (s) => err.push(s),
});
if (out.length > 0) process.stdout.write(out.join(""));
if (err.length > 0) process.stderr.write(err.join(""));
process.exitCode = result.exitCode;
