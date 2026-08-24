/**
 * Tests: observer declarations + corroboration judgment (M1 Slice 3).
 * Each §6 condition broken in isolation flips the verdict with that
 * condition named; structural classes each rejected distinctly; no numeric
 * score anywhere.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { JsonValue } from "../src/json.ts";
import {
  SUPPORTED_OBSERVER_SCHEMA,
  isIndependentlyCorroborating,
  validateObserverDeclaration,
} from "../src/observers.ts";

type Mutable = Record<string, unknown>;

function declaration(observerId: string, plane: string): Mutable {
  return {
    $schema: SUPPORTED_OBSERVER_SCHEMA,
    observer_id: observerId,
    version: "observer-v1",
    implementation_digest: { algorithm: "sha256", label: "canonical_payload", value_hex: "a".repeat(64) },
    bootstrap_provenance: "built from pinned source in synthetic CI",
    source: "src/observers/synthetic",
    observation_plane: plane,
    enforcement_capability: false,
    loss_semantics: "lossless",
    owners: {
      process: "harness-owner", runtime: "runtime-owner", admin_plane: "admin-owner",
      configuration: "config-owner", artifact_writer: "artifact-owner", clock: "clock-owner",
      policy_source: "policy-owner", fixture_source: "fixture-owner", keys: "keys-owner",
    },
    host_privileges: {
      write: true, read: true, signal: false, debug: false,
      lifecycle: false, configuration: false, sockets: false, mounts: false,
    },
    independence_vector: {
      code: true, configuration: true, lifecycle: true, data_path: true,
      artifact_path: true, clock: true, policy: true, administration: true,
      key_custody: true,
    },
    fcz_nodes: [{ fcz_id: `fcz-${observerId}`, description: "capture path" }],
    fcz_edges: [],
    blind_spots: [{ fcz_id: `fcz-${observerId}`, description: "buffer truncation" }],
    unmitigated_forge_suppress_fcz_ids: [],
    liveness_checks: [{ check_id: `live-${observerId}`, description: "heartbeat seen" }],
    health_checks: [],
    fault_injections: [
      { fault_id: `fault-${observerId}`, description: "drop events", demonstrates_loss_cannot_yield_pass: true },
    ],
    host_control_paths_declared: [],
  };
}

function aDoc(): JsonValue {
  return declaration("obs-ipc-alpha", "process_ipc") as JsonValue;
}
function bDoc(): JsonValue {
  return declaration("obs-file-beta", "filesystem") as JsonValue;
}

test("valid pair of distinct-plane observers corroborates", () => {
  assert.deepEqual(validateObserverDeclaration(aDoc()), { ok: true });
  const j = isIndependentlyCorroborating(aDoc(), bDoc());
  assert.deepEqual(j, { independentlyCorroborating: true });
});

test("same-plane overlapping-FCZ pair fails distinct_mechanisms only", () => {
  const mk = (id: string): JsonValue => {
    const d = declaration(id, "process_ipc") as Mutable;
    // Keep the graph self-consistent while sharing one FCZ id.
    d["fcz_nodes"] = [{ fcz_id: "fcz-shared", description: "shared capture path" }];
    d["blind_spots"] = [{ fcz_id: "fcz-shared", description: "buffer truncation" }];
    return d as JsonValue;
  };
  const j = isIndependentlyCorroborating(mk("obs-gamma"), mk("obs-delta"));
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.equal(j.failures.length, 1);
    assert.equal(j.failures[0]?.condition, "distinct_mechanisms");
  }
});

test("shared unmitigated FCZ fails no_shared_unmitigated_fcz only", () => {
  const mk = (id: string, plane: string): JsonValue => {
    const d = declaration(id, plane) as Mutable;
    d["fcz_nodes"] = [{ fcz_id: "fcz-shared-risk", description: "forgeable path" }];
    d["blind_spots"] = [{ fcz_id: "fcz-shared-risk", description: "buffer truncation" }];
    d["unmitigated_forge_suppress_fcz_ids"] = ["fcz-shared-risk"];
    return d as JsonValue;
  };
  const j = isIndependentlyCorroborating(mk("obs-a", "process_ipc"), mk("obs-b", "filesystem"));
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.ok(j.failures.some((f) => f.condition === "no_shared_unmitigated_fcz"));
    // Planes differ and everything else holds — exactly this one failure.
    assert.equal(j.failures.length, 1);
  }
});

test("host debug privilege on either side fails host_cannot_control_observer", () => {
  const withDebug = {
    ...declaration("obs-dbg", "admin_plane"),
    host_privileges: {
      write: true, read: true, signal: false, debug: true,
      lifecycle: false, configuration: false, sockets: false, mounts: false,
    },
  } as Mutable;
  const j = isIndependentlyCorroborating(aDoc(), withDebug as JsonValue);
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.ok(j.failures.some((f) => f.condition === "host_cannot_control_observer"));
  }
});

test("declared host control path fails host_cannot_control_observer", () => {
  const controlled = {
    ...declaration("obs-ctl", "api_boundary"),
    host_control_paths_declared: ["host can rewrite config via env"],
  } as Mutable;
  const j = isIndependentlyCorroborating(aDoc(), controlled as JsonValue);
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.ok(j.failures.some((f) => f.condition === "host_cannot_control_observer"));
  }
});

test("incomplete independence vector fails trust_paths_declared", () => {
  const iv = { ...declaration("obs-partial", "network_loopback") };
  (iv["independence_vector"] as Mutable)["key_custody"] = false;
  const j = isIndependentlyCorroborating(iv as JsonValue, bDoc());
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.ok(j.failures.some((f) => f.condition === "trust_paths_declared"));
  }
});

test("no demonstrating fault injection fails loss_cannot_yield_pass", () => {
  const weak = {
    ...declaration("obs-weak", "clock_service"),
    fault_injections: [{ fault_id: "fault-x", description: "nudge clock", demonstrates_loss_cannot_yield_pass: false }],
  } as Mutable;
  const j = isIndependentlyCorroborating(weak as JsonValue, bDoc());
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.ok(j.failures.some((f) => f.condition === "loss_cannot_yield_pass"));
  }
});

test("structurally invalid observer names the valid_declaration failure", () => {
  const broken = { ...(aDoc() as Mutable) };
  delete broken["owners"];
  const j = isIndependentlyCorroborating(broken as JsonValue, bDoc());
  assert.ok(!j.independentlyCorroborating);
  if (!j.independentlyCorroborating) {
    assert.ok(j.failures.some((f) => f.condition === "valid_declaration_a"));
  }
});

// ---------------------------------------------------------------------------
// Structural validation classes
// ---------------------------------------------------------------------------

test("unknown schema version gates checks", () => {
  const r = validateObserverDeclaration({ ...(aDoc() as Mutable), $schema: "ab.observer-declaration/9" } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.deepEqual(r.issues.map((i) => i.code), ["V_UNKNOWN_SCHEMA_VERSION"]);
});

test("each missing owner custody reported individually", () => {
  const doc = aDoc() as Mutable;
  const owners = doc["owners"] as Mutable;
  delete owners["keys"];
  delete owners["policy_source"];
  const r = validateObserverDeclaration(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) {
    const missing = r.issues.filter((i) => i.code === "V_MISSING_MANDATORY_FIELD" && i.path.startsWith("$.owners."));
    assert.equal(missing.length, 2);
  }
});

test("undeclared ownership or privilege dimension rejected", () => {
  const doc = aDoc() as Mutable;
  (doc["owners"] as Mutable)["extra_custody"] = "someone";
  const r = validateObserverDeclaration(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_EXTRA_FIELD" && i.path === "$.owners.extra_custody"));
});

test("unresolvable FCZ edge reference rejected", () => {
  const doc = aDoc() as Mutable;
  doc["fcz_edges"] = [{ from_fcz_id: "fcz-ghost", to_fcz_id: "fcz-obs-ipc-alpha" }];
  const r = validateObserverDeclaration(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_UNRESOLVED_REFERENCE"));
});

test("empty FCZ node list rejected", () => {
  const r = validateObserverDeclaration({ ...(aDoc() as Mutable), fcz_nodes: [] } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_EMPTY_ARRAY"));
});

test("invalid observation plane and loss semantics rejected via closed sets", () => {
  const r1 = validateObserverDeclaration({ ...(aDoc() as Mutable), observation_plane: "telepathy" } as JsonValue);
  assert.ok(!r1.ok);
  const r2 = validateObserverDeclaration({ ...(aDoc() as Mutable), loss_semantics: "mostly_fine" } as JsonValue);
  assert.ok(!r2.ok);
});

test("malformed implementation digest shape rejected", () => {
  const doc = aDoc() as Mutable;
  doc["implementation_digest"] = { algorithm: "md5", label: "", value_hex: "zz" };
  const r = validateObserverDeclaration(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.filter((i) => i.path.startsWith("$.implementation_digest")).length >= 3);
});

test("corroboration judgment carries no numeric score anywhere", () => {
  const j = isIndependentlyCorroborating(aDoc(), bDoc());
  const serialized = JSON.stringify(j);
  assert.ok(!/"score"\s*:/.test(serialized));
  assert.ok(!/"level"\s*:/.test(serialized));
  assert.ok(!/\b[0-9]+\/10\b/.test(serialized));
});
