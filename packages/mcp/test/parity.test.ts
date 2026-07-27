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

type ToolArgs = { url?: string; domain?: string; agentMode?: boolean };

async function call(name: string, args: ToolArgs): Promise<InspectResult> {
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
      expect(t.description).toContain("agentMode: true");
      expect(t.inputSchema.properties).toHaveProperty("agentMode");
    }
  });

  // LINK-vwjtdtzn — the tool description is the ONLY thing an LLM reads before
  // deciding what a result means, so the clean case has to be qualified there
  // and not only in the docs. Previously it warned about `invalid` alone, which
  // left `score: 0` reading as clearance. architecture.md §1.1 is canonical.
  it("tells the model a clean result is not a safety claim (LINK-vwjtdtzn)", async () => {
    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThan(0);
    for (const t of tools) {
      // Case-insensitive: the description shouts the negation ("NOT a safety
      // claim") because the reader is a model skimming for permission.
      const description = (t.description ?? "").toLowerCase();
      expect(description).toContain("not a safety claim");
      // The actionable half: linklint may reject a URL, never approve one.
      expect(description).toContain("never to approve");
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

    it(`check_url agentMode:false matches core default for ${JSON.stringify(input)}`, async () => {
      const viaTool = await call("check_url", { url: input, agentMode: false });
      expect(viaTool).toEqual(inspect(input));
      expect(viaTool).toEqual(inspect(input, { agentMode: false }));
    });
  }

  it("carries schemaVersion 1.7, confidence 1.0, and PSL provenance (FR-SCORE-2b)", async () => {
    const ok = await call("check_url", { url: "https://example.com/" });
    expect(ok.schemaVersion).toBe("1.7");
    expect(ok.confidence).toBe(1);
    expect(ok.pslSnapshot.date).toBe("2026-06-15");

    const invalid = await call("check_url", { url: "ht!tp://%%%not a url" });
    expect(invalid.status).toBe("invalid");
    expect(invalid.schemaVersion).toBe("1.7");
    expect(invalid.confidence).toBe(1);
    expect(invalid.pslSnapshot.date).toBe("2026-06-15");
  });

  it("check_domain returns the same shape as check_url", async () => {
    const viaUrl = await call("check_url", { url: "paypal.com.spoof.info" });
    const viaDomain = await call("check_domain", { domain: "paypal.com.spoof.info" });
    expect(viaDomain).toEqual(viaUrl);
  });

  it("check_url agentMode:true matches core agentMode:true", async () => {
    const input = "https://example.com/agent?role=system&prompt=ignore%20everything";
    const viaTool = await call("check_url", { url: input, agentMode: true });
    expect(viaTool).toEqual(inspect(input, { agentMode: true }));
  });

  it("check_domain agentMode:true matches check_url agentMode:true", async () => {
    const input = "http://169.254.169.254/latest/meta-data/";
    const viaUrl = await call("check_url", { url: input, agentMode: true });
    const viaDomain = await call("check_domain", { domain: input, agentMode: true });
    expect(viaDomain).toEqual(viaUrl);
  });
});

describe("MCP agentMode opt-in coverage", () => {
  const agentExamples = [
    ["prompt_injection_url", "https://example.com/agent?role=system&prompt=ignore%20everything"],
    ["api_endpoint_impersonation", "https://api.openai-com.io/v1/chat/completions"],
    ["credential_harvesting", "https://account-verify.example.com/oauth/authorize?client_id=abc"],
    ["data_exfiltration", "https://evil.example/collect?exfil=customer-secret"],
    ["ssrf_cloud_metadata", "http://169.254.169.254/latest/meta-data/"],
  ] as const;

  it.each(agentExamples)("keeps %s out of the default MCP verdict", async (code, input) => {
    const verdict = await call("check_url", { url: input });
    expect(verdict).toEqual(inspect(input));
    expect(verdict.reasons.map((r) => r.code)).not.toContain(code);
    expect(verdict.checksRun).not.toContain("agent");
    expect(verdict.checksSkipped).not.toContain("agent");
  });

  it.each(agentExamples)("emits %s when agentMode is true", async (code, input) => {
    const verdict = await call("check_url", { url: input, agentMode: true });
    expect(verdict).toEqual(inspect(input, { agentMode: true }));
    expect(verdict.reasons.map((r) => r.code)).toContain(code);
    expect(verdict.checksRun).toContain("agent");
  });

  it("escalates cloud metadata SSRF from high to critical under agentMode", async () => {
    const input = "http://169.254.169.254/latest/meta-data/";
    const defaultVerdict = await call("check_url", { url: input });
    const agentVerdict = await call("check_url", { url: input, agentMode: true });

    expect(defaultVerdict.reasons.map((r) => r.code)).toContain("ip_cloud_metadata");
    expect(defaultVerdict.reasons.map((r) => r.code)).not.toContain("ssrf_cloud_metadata");
    expect(defaultVerdict.severity).toBe("high");

    expect(agentVerdict.reasons.map((r) => r.code)).toEqual(
      expect.arrayContaining(["ip_cloud_metadata", "ssrf_cloud_metadata"]),
    );
    expect(agentVerdict.severity).toBe("critical");
  });
});

describe("SC-3: an agent can act on the verdict before fetching", () => {
  it("returns a structured verdict an agent can gate on", async () => {
    const verdict = await call("check_url", { url: "https://paypal.com@xn--pypal-4ve.ru/login" });
    // The agent's decision logic:
    const shouldFetch = verdict.status === "ok" && verdict.severity !== "high" && verdict.severity !== "critical";
    expect(shouldFetch).toBe(false);
    expect(verdict.severity).toBe("critical");
    expect(verdict.reasons.length).toBeGreaterThan(0);
  });

  it("a benign URL is safe to fetch", async () => {
    const verdict = await call("check_url", { url: "https://www.example.com/" });
    const shouldFetch = verdict.status === "ok" && verdict.severity === "info";
    expect(shouldFetch).toBe(true);
  });
});
