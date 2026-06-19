import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { inspect, type InspectResult } from "linklint";
import { createServer } from "../src/server.js";

let client: Client;

beforeAll(async () => {
  const server = createServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "linklint-test", version: "0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
});

interface ToolCallResult {
  content: Array<{ type: string; text?: string }>;
  structuredContent?: Record<string, unknown>;
}

async function call(name: string, args: Record<string, string>): Promise<InspectResult> {
  const res = (await client.callTool({ name, arguments: args })) as unknown as ToolCallResult;
  const textPart = res.content.find((c) => c.type === "text");
  return JSON.parse(textPart!.text!) as InspectResult;
}

describe("MCP surface", () => {
  it("exposes check_url and check_domain with pre-fetch guidance (FR-MCP-3)", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("check_url");
    expect(names).toContain("check_domain");
    for (const t of tools) {
      expect(t.description?.toLowerCase()).toContain("before");
      expect(t.description?.toLowerCase()).toContain("fetch");
    }
  });
});

describe("schema parity with core inspect() (no channel drift)", () => {
  const inputs = [
    "https://paypal.com@xn--pypal-4ve.ru/login",
    "https://example.com/",
    "http://2130706433/",
    "javascript:alert(1)",
    "ht!tp://%%%not a url",
  ];

  for (const input of inputs) {
    it(`check_url matches core for ${JSON.stringify(input)}`, async () => {
      const viaTool = await call("check_url", { url: input });
      expect(viaTool).toEqual(inspect(input));
    });
  }

  it("check_domain returns the same shape as check_url", async () => {
    const viaUrl = await call("check_url", { url: "paypal.com.spoof.info" });
    const viaDomain = await call("check_domain", { domain: "paypal.com.spoof.info" });
    expect(viaDomain).toEqual(viaUrl);
  });
});

describe("SC-3: an agent can act on the verdict before fetching", () => {
  it("returns a structured verdict an agent can gate on", async () => {
    const verdict = await call("check_url", { url: "https://paypal.com@xn--pypal-4ve.ru/login" });
    // The agent's decision logic:
    const shouldFetch = verdict.status === "ok" && verdict.severity !== "high" && verdict.severity !== "critical";
    expect(shouldFetch).toBe(false);
    expect(verdict.severity).toBe("high");
    expect(verdict.reasons.length).toBeGreaterThan(0);
  });

  it("a benign URL is safe to fetch", async () => {
    const verdict = await call("check_url", { url: "https://www.example.com/" });
    const shouldFetch = verdict.status === "ok" && verdict.severity === "info";
    expect(shouldFetch).toBe(true);
  });
});
