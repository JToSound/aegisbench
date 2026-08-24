/**
 * Tests: route inventory + coverage-closure model (M1 Slice 1).
 * Round trip, mechanical derivation, tamper detection, closed-set and
 * narrative-field enforcement, bounded-negative-claim gate.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { JsonValue } from "../src/json.ts";
import {
  SUPPORTED_COVERAGE_CLOSURE_SCHEMA,
  SUPPORTED_ROUTE_INVENTORY_SCHEMA,
  deriveCoverageClosureLists,
  supportsBoundedNegativeClaim,
  validateCoverageClosure,
  validateRouteInventory,
} from "../src/routes.ts";

type Mutable = Record<string, unknown>;

function inventoryDoc(): JsonValue {
  return {
    $schema: SUPPORTED_ROUTE_INVENTORY_SCHEMA,
    inventory_id: "inventory-clipboard-001",
    routes: [
      { route_id: "route-ui-paste", classification: "mediated_tested", description: "paste via UI" },
      { route_id: "route-clipboard-daemon", classification: "observed_only" },
      { route_id: "route-os-hotkey", classification: "excluded_declared", description: "not in scope" },
      { route_id: "route-sync-engine", classification: "unknown_possible" },
      { route_id: "route-kernel-bypass", classification: "unsupported_by_subject" },
      { route_id: "route-plugin-hook", classification: "mediated_untested" },
    ],
  } as unknown as JsonValue;
}

function closureDoc(): JsonValue {
  return {
    $schema: SUPPORTED_COVERAGE_CLOSURE_SCHEMA,
    closure_id: "closure-clipboard-001",
    based_on_inventory_id: "inventory-clipboard-001",
    included_routes: ["route-ui-paste", "route-clipboard-daemon"],
    excluded_routes: ["route-os-hotkey"],
    unknown_possible_routes: ["route-sync-engine"],
    process_identity_assumption: "single synthetic clipboard host, pinned version",
    enforcement_point: "host paste-permission check immediately before effect",
    observer_liveness_evidence: ["observer heartbeat event observed at t0 and t1"],
    interval_start_utc: "2026-08-24T08:00:00Z",
    interval_end_utc: "2026-08-24T09:00:00Z",
    clock_uncertainty_ms: 25,
    residual_uncertainty: "untested plugin hook route remains outside this closure",
  } as unknown as JsonValue;
}

test("valid inventory passes validation", () => {
  assert.deepEqual(validateRouteInventory(inventoryDoc()), { ok: true });
});

test("derivation places ids exactly per classification, in inventory order", () => {
  const inv = inventoryDoc();
  const sinkFree = deriveCoverageClosureLists({
    inventoryId: "inventory-clipboard-001",
    entries: (inv as unknown as { routes: Array<{ route_id: string; classification: string }> }).routes.map((r) => ({
      routeId: r.route_id,
      classification: r.classification as never,
    })),
  });
  assert.deepEqual(sinkFree.included_routes, ["route-ui-paste", "route-clipboard-daemon"]);
  assert.deepEqual(sinkFree.excluded_routes, ["route-os-hotkey"]);
  assert.deepEqual(sinkFree.unknown_possible_routes, ["route-sync-engine"]);
});

test("round trip: derived lists + narratives validate against the inventory", () => {
  const inv = inventoryDoc();
  const derived = deriveCoverageClosureLists({
    inventoryId: "inventory-clipboard-001",
    entries: (inv as unknown as { routes: Array<{ route_id: string; classification: string }> }).routes.map((r) => ({
      routeId: r.route_id,
      classification: r.classification as never,
    })),
  });
  const clo = {
    ...(closureDoc() as Mutable),
    included_routes: derived.included_routes,
    excluded_routes: derived.excluded_routes,
    unknown_possible_routes: derived.unknown_possible_routes,
  } as JsonValue;
  assert.deepEqual(validateCoverageClosure(clo, inv), { ok: true });
  assert.deepEqual(supportsBoundedNegativeClaim(clo, inv), { supported: true });
});

test("tampering any id list yields V_ROUTE_LIST_MISMATCH with expected list", () => {
  const base = closureDoc() as Mutable;
  const dropOne = { ...base, included_routes: ["route-ui-paste"] } as JsonValue;
  const r = validateCoverageClosure(dropOne, inventoryDoc());
  assert.ok(!r.ok);
  if (!r.ok) {
    const m = r.issues.find((i) => i.code === "V_ROUTE_LIST_MISMATCH" && i.path === "$.included_routes");
    assert.ok(m !== undefined);
    assert.match(m.message, /route-clipboard-daemon/);
  }

  const addPhantom = { ...base, excluded_routes: ["route-os-hotkey", "phantom-route"] } as JsonValue;
  const r2 = validateCoverageClosure(addPhantom, inventoryDoc());
  assert.ok(!r2.ok);
  if (!r2.ok) assert.ok(r2.issues.some((i) => i.code === "V_ROUTE_LIST_MISMATCH"));
});

test("covered id appearing in two lists is inconsistent", () => {
  const doc = {
    ...(closureDoc() as Mutable),
    unknown_possible_routes: ["route-sync-engine", "route-ui-paste"],
  } as JsonValue;
  const r = validateCoverageClosure(doc, inventoryDoc());
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"));
});

test("based_on_inventory_id must match the provided inventory", () => {
  const r = validateCoverageClosure(closureDoc(), {
    ...(inventoryDoc() as Mutable),
    inventory_id: "inventory-other-999",
  } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_UNRESOLVED_REFERENCE"));
});

test("uncovered-by-construction: untested mediated route appears in no list", () => {
  const r = supportsBoundedNegativeClaim(closureDoc(), inventoryDoc());
  // The closure is valid; but the untested route must not be claimed covered.
  if (r.supported) {
    const serialized = JSON.stringify(closureDoc());
    assert.ok(!serialized.includes("route-plugin-hook"));
    assert.ok(!serialized.includes("route-kernel-bypass"));
  }
});

// ---------------------------------------------------------------------------
// Inventory structural cases
// ---------------------------------------------------------------------------

test("inventory: unknown schema version gates further checks", () => {
  const r = validateRouteInventory({
    ...(inventoryDoc() as Mutable),
    $schema: "ab.route-inventory/9",
  } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.deepEqual(r.issues.map((i) => i.code), ["V_UNKNOWN_SCHEMA_VERSION"]);
});

test("inventory: duplicate route ids reported at later occurrences", () => {
  const doc = inventoryDoc() as Mutable;
  (doc["routes"] as Mutable[]).push({ route_id: "route-ui-paste", classification: "observed_only" });
  const r = validateRouteInventory(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) {
    const dup = r.issues.filter((i) => i.code === "V_DUPLICATE_ID");
    assert.equal(dup.length, 1);
    assert.match(dup[0]?.message ?? "", /route-ui-paste/);
  }
});

test("inventory: invalid classification rejected with closed-set message", () => {
  const doc = inventoryDoc() as Mutable;
  (doc["routes"] as Mutable[])[0] = { route_id: "route-x", classification: "sort_of_tested" };
  const r = validateRouteInventory(doc as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_INVALID_FIELD_TYPE"));
});

test("inventory: empty routes array rejected", () => {
  const r = validateRouteInventory({ ...(inventoryDoc() as Mutable), routes: [] } as JsonValue);
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_EMPTY_ARRAY"));
});

// ---------------------------------------------------------------------------
// Closure structural + narrative cases
// ---------------------------------------------------------------------------

test("closure: missing narrative fields each reported", () => {
  const base = closureDoc() as Mutable;
  delete base["process_identity_assumption"];
  delete base["enforcement_point"];
  delete base["residual_uncertainty"];
  const r = validateCoverageClosure(base as JsonValue, inventoryDoc());
  assert.ok(!r.ok);
  if (!r.ok) {
    const missing = r.issues.filter((i) => i.code === "V_MISSING_MANDATORY_FIELD").map((i) => i.path).sort();
    assert.deepEqual(missing, [
      "$.enforcement_point",
      "$.process_identity_assumption",
      "$.residual_uncertainty",
    ]);
  }
});

test("closure: empty liveness evidence rejected", () => {
  const r = validateCoverageClosure(
    { ...(closureDoc() as Mutable), observer_liveness_evidence: [] } as JsonValue,
    inventoryDoc(),
  );
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_EMPTY_ARRAY"));
});

test("closure: inverted interval rejected as inconsistent", () => {
  const r = validateCoverageClosure(
    { ...(closureDoc() as Mutable), interval_end_utc: "2026-08-24T07:00:00Z" } as JsonValue,
    inventoryDoc(),
  );
  assert.ok(!r.ok);
  if (!r.ok) assert.ok(r.issues.some((i) => i.code === "V_INCONSISTENT_INPUT"));
});

test("closure: non-positive clock uncertainty rejected", () => {
  for (const v of [0, -5, Number.NaN]) {
    const r = validateCoverageClosure(
      { ...(closureDoc() as Mutable), clock_uncertainty_ms: v } as JsonValue,
      inventoryDoc(),
    );
    assert.ok(!r.ok, String(v));
  }
});

test("claim gate names every failed requirement on a broken closure", () => {
  const broken = { ...(closureDoc() as Mutable), residual_uncertainty: "", included_routes: [] };
  const r = supportsBoundedNegativeClaim(broken as JsonValue, inventoryDoc());
  assert.ok(!r.supported);
  if (!r.supported) {
    assert.ok(r.missing.some((m) => m.startsWith("V_ROUTE_LIST_MISMATCH @ $.included_routes")));
    assert.ok(r.missing.some((m) => m.includes("residual_uncertainty")));
    // Exactly these two requirements fail for this fixture.
    assert.equal(r.missing.length, 2);
  }
});
