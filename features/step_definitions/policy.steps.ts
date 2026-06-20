import assert from "node:assert/strict";
import { DataTable, Then, When } from "@cucumber/cucumber";
import { inspect } from "../../packages/core/src/index.js";
import type { InspectOptions } from "../../packages/core/src/index.js";
import type { LinklintWorld } from "../support/world.js";

/** Option keys whose value is a string[] supplied as a comma-separated list. */
const ARRAY_KEYS = new Set(["denyTlds", "allowTlds", "denyHosts", "allowHosts", "allowSchemes", "denySchemes"]);
/** Option keys whose value is a number[] supplied as a comma-separated list. */
const NUMBER_ARRAY_KEYS = new Set(["denyPorts"]);
/** Option keys whose value is a boolean ("true"/"false"). */
const BOOLEAN_KEYS = new Set(["denyNonStandardPorts"]);

/**
 * Parse a DataTable of option-name → value into {@link InspectOptions}. Arrays
 * are comma-separated; ports parse to numbers; booleans are "true"/"false". The
 * DataTable form keeps the step extensible as new policy axes land.
 */
function parsePolicyOptions(table: DataTable): InspectOptions {
  const opts: Record<string, unknown> = {};
  // `raw()` returns every row including the first; our DataTables are
  // option-name → value pairs with no header row, so we must not use `rows()`
  // (which would drop the first pair as a header).
  for (const row of table.raw()) {
    const key = (row[0] ?? "").trim();
    const value = (row[1] ?? "").trim();
    if (ARRAY_KEYS.has(key)) {
      opts[key] = value.split(",").map((s) => s.trim());
    } else if (NUMBER_ARRAY_KEYS.has(key)) {
      opts[key] = value.split(",").map((s) => Number(s.trim()));
    } else if (BOOLEAN_KEYS.has(key)) {
      opts[key] = value === "true";
    } else {
      throw new Error(`unknown policy option: ${key}`);
    }
  }
  return opts as InspectOptions;
}

When(
  "I inspect {string} with policy:",
  function (this: LinklintWorld, input: string, table: DataTable) {
    this.input = input;
    this.baseline = inspect(input);
    this.result = inspect(input, parsePolicyOptions(table));
  },
);

Then("the reason {string} has layer {string}", function (this: LinklintWorld, code: string, layer: string) {
  const reason = this.result.reasons.find((r) => r.code === code);
  assert.ok(reason, `missing reason ${code}`);
  assert.equal(reason.layer, layer);
});

Then("the score is unchanged from the no-policy baseline", function (this: LinklintWorld) {
  assert.ok(this.baseline, "no baseline captured — use the 'with policy:' step first");
  assert.equal(this.result.score, this.baseline.score);
  assert.equal(this.result.severity, this.baseline.severity);
});
