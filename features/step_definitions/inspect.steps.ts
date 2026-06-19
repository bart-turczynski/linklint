import assert from "node:assert/strict";
import { Then, When } from "@cucumber/cucumber";
import { inspect } from "../../packages/core/src/index.js";
import type { LinklintWorld } from "../support/world.js";

When("I inspect {string}", function (this: LinklintWorld, input: string) {
  this.input = input;
  this.result = inspect(input);
});

Then("the status is {string}", function (this: LinklintWorld, status: string) {
  assert.equal(this.result.status, status);
});

Then("the status is one of {string}", function (this: LinklintWorld, csv: string) {
  assert.ok(csv.split(",").includes(this.result.status));
});

Then("the score is {int}", function (this: LinklintWorld, score: number) {
  assert.equal(this.result.score, score);
});

Then("the severity is {string}", function (this: LinklintWorld, severity: string) {
  assert.equal(this.result.severity, severity);
});

Then("parsed is null", function (this: LinklintWorld) {
  assert.equal(this.result.parsed, null);
});

Then("score is null", function (this: LinklintWorld) {
  assert.equal(this.result.score, null);
});

Then("severity is null", function (this: LinklintWorld) {
  assert.equal(this.result.severity, null);
});

Then("the reasons contain {string}", function (this: LinklintWorld, code: string) {
  assert.ok(this.result.reasons.some((r) => r.code === code), `expected reason ${code}`);
});

Then("the reasons do not contain {string}", function (this: LinklintWorld, code: string) {
  assert.ok(!this.result.reasons.some((r) => r.code === code), `unexpected reason ${code}`);
});

const SEVERITY_RANK = ["info", "low", "medium", "high", "critical"];
Then("the severity is at least {string}", function (this: LinklintWorld, min: string) {
  const actual = this.result.severity;
  assert.ok(actual, "severity is null");
  assert.ok(
    SEVERITY_RANK.indexOf(actual) >= SEVERITY_RANK.indexOf(min),
    `severity ${actual} is below ${min}`,
  );
});

Then("the reason {string} has weight {int}", function (this: LinklintWorld, code: string, w: number) {
  const reason = this.result.reasons.find((r) => r.code === code);
  assert.ok(reason, `missing reason ${code}`);
  assert.equal(reason.weight, w);
});

Then("checksRun is {string}", function (this: LinklintWorld, csv: string) {
  assert.deepEqual(this.result.checksRun, csv.split(","));
});

Then("checksRun is empty", function (this: LinklintWorld) {
  assert.deepEqual(this.result.checksRun, []);
});

Then("checksSkipped is {string}", function (this: LinklintWorld, csv: string) {
  assert.deepEqual(this.result.checksSkipped, csv.split(","));
});

Then("the schemaVersion is {string}", function (this: LinklintWorld, v: string) {
  assert.equal(this.result.schemaVersion, v);
});

Then("dataVersions is present", function (this: LinklintWorld) {
  assert.ok(this.result.dataVersions);
  assert.ok(this.result.dataVersions.weights);
});
