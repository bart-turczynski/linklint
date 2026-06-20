import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { Then, When } from "@cucumber/cucumber";

// Absolute path to the built CLI binary, resolved from this file's location so
// the spawn works regardless of the process cwd.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const CLI_BIN = resolve(REPO_ROOT, "packages", "cli", "dist", "cli.js");
const BATCH_FIXTURE = resolve(
  REPO_ROOT,
  "packages",
  "cli",
  "test",
  "fixtures",
  "batch-urls.txt",
);

/**
 * Per-scenario CLI state. Kept self-contained to the CLI steps (the shared
 * world is owned by the inspect/mcp suites). Cucumber runs scenarios serially,
 * so a module-scoped slot is safe and is reset by each `When` step.
 */
interface CliRun {
  result: SpawnSyncReturns<string>;
}
let lastRun: CliRun | undefined;

function runCli(args: readonly string[], input?: string): void {
  const result = spawnSync("node", [CLI_BIN, ...args], {
    encoding: "utf8",
    ...(input === undefined ? {} : { input }),
  });
  lastRun = { result };
}

function current(): SpawnSyncReturns<string> {
  assert.ok(lastRun, "no CLI run recorded — a When step must run first");
  return lastRun.result;
}

When("I run the CLI with {string}", function (argline: string) {
  const args = argline.split(/\s+/).filter((a) => a.length > 0);
  runCli(args);
});

When("I run the CLI over the batch fixture", function () {
  runCli(["batch", BATCH_FIXTURE, "--no-color"]);
});

When(
  "I pipe URLs to the CLI and run {string}",
  function (argline: string) {
    const args = argline.split(/\s+/).filter((a) => a.length > 0);
    const input = [
      "# piped fixture",
      "https://www.example.com/path",
      "",
      "https://www.gооgle.com@bad.tk/login",
      "",
    ].join("\n");
    runCli(args, input);
  },
);

Then("the CLI exit code is {int}", function (code: number) {
  assert.equal(current().status, code);
});

Then("the CLI output contains {string}", function (needle: string) {
  assert.ok(
    current().stdout.includes(needle),
    `stdout did not contain ${JSON.stringify(needle)}:\n${current().stdout}`,
  );
});

Then("the CLI error output contains {string}", function (needle: string) {
  assert.ok(
    current().stderr.includes(needle),
    `stderr did not contain ${JSON.stringify(needle)}:\n${current().stderr}`,
  );
});
