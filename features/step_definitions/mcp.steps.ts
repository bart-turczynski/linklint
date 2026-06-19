import assert from "node:assert/strict";
import { AfterAll, BeforeAll, Then, When } from "@cucumber/cucumber";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../../packages/mcp/src/server.js";
import type { InspectResult } from "../../packages/core/src/index.js";
import type { LinklintWorld } from "../support/world.js";

let client: Client;

BeforeAll(async function () {
  const server = createServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "linklint-cucumber", version: "0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
});

AfterAll(async function () {
  await client.close();
});

interface ToolCallResult {
  content: Array<{ type: string; text?: string }>;
}

/** The agent's gating policy: only fetch a parsed result below high severity. */
function agentWouldFetch(v: InspectResult): boolean {
  return v.status === "ok" && v.severity !== "high" && v.severity !== "critical";
}

When(
  "the agent checks the URL {string} over MCP",
  async function (this: LinklintWorld, url: string) {
    const res = (await client.callTool({
      name: "check_url",
      arguments: { url },
    })) as unknown as ToolCallResult;
    const text = res.content.find((c) => c.type === "text")?.text;
    this.mcpVerdict = JSON.parse(text!) as InspectResult;
    this.willFetch = agentWouldFetch(this.mcpVerdict);
  },
);

Then("the MCP verdict severity is {string}", function (this: LinklintWorld, severity: string) {
  assert.equal(this.mcpVerdict.severity, severity);
});

Then("the MCP verdict status is {string}", function (this: LinklintWorld, status: string) {
  assert.equal(this.mcpVerdict.status, status);
});

Then("the MCP verdict has reasons", function (this: LinklintWorld) {
  assert.ok(this.mcpVerdict.reasons.length > 0);
});

Then("the agent decides not to fetch", function (this: LinklintWorld) {
  assert.equal(this.willFetch, false);
});

Then("the agent decides to fetch", function (this: LinklintWorld) {
  assert.equal(this.willFetch, true);
});
