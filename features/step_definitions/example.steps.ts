import assert from "node:assert/strict";
import { Given, Then, When } from "@cucumber/cucumber";
import { scaffoldReady } from "../../src/index.js";

let projectCreated = false;
let checksAvailable = false;

Given("the project has been created", function () {
  projectCreated = true;
});

When("I run the development checks", function () {
  checksAvailable = scaffoldReady();
});

Then("the TypeScript and feature test setup should be available", function () {
  assert.equal(projectCreated, true);
  assert.equal(checksAvailable, true);
});

