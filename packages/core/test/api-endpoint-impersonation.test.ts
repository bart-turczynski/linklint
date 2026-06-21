import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// Agent-gated detector: every assertion runs `inspect(url, { agentMode: true })`
// because the detector is silent by default (gating is exercised in the contract
// test). Here we test the SIGNAL boundary: impersonating API hosts fire, the real
// provider does not, path escalation is reflected, near-miss benign stays clean.

const agentReasons = (input: string) =>
  inspect(input, { agentMode: true }).reasons;
const agentCodes = (input: string): string[] => agentReasons(input).map((r) => r.code);

describe("api_endpoint_impersonation — impersonating hosts FIRE (agentMode)", () => {
  it("api.openai-com.io fires", () => {
    expect(agentCodes("https://api.openai-com.io")).toContain("api_endpoint_impersonation");
  });

  it("api.anthropic-com.co fires", () => {
    expect(agentCodes("https://api.anthropic-com.co")).toContain("api_endpoint_impersonation");
  });

  it("a bare provider token glued in a label on a wrong eTLD+1 fires (openai-api.io)", () => {
    expect(agentCodes("https://openai-api.io")).toContain("api_endpoint_impersonation");
  });

  it("the brand token as its own subdomain label on a wrong eTLD+1 fires (openai.evil.com)", () => {
    expect(agentCodes("https://openai.evil.com")).toContain("api_endpoint_impersonation");
  });
});

describe("api_endpoint_impersonation — path escalation", () => {
  it("a real API route prefix is reflected in the detail", () => {
    const reason = agentReasons("https://api.openai-com.io/v1/chat/completions").find(
      (r) => r.code === "api_endpoint_impersonation",
    );
    expect(reason).toBeDefined();
    expect(reason!.detail).toContain("/v1/chat/completions");
    expect(reason!.detail).toMatch(/real API endpoint/);
  });

  it("without an API route, the detail does NOT claim a route match", () => {
    const reason = agentReasons("https://api.openai-com.io/about").find(
      (r) => r.code === "api_endpoint_impersonation",
    );
    expect(reason).toBeDefined();
    expect(reason!.detail).not.toMatch(/real API endpoint/);
  });

  it("/v1/messages escalates for an anthropic impersonator", () => {
    const reason = agentReasons("https://api.anthropic-com.co/v1/messages").find(
      (r) => r.code === "api_endpoint_impersonation",
    );
    expect(reason!.detail).toContain("/v1/messages");
  });
});

describe("api_endpoint_impersonation — conservative: the real provider does NOT fire", () => {
  it("the real api.openai.com does not fire", () => {
    expect(agentCodes("https://api.openai.com/v1/chat/completions")).not.toContain(
      "api_endpoint_impersonation",
    );
  });

  it("the real api.anthropic.com does not fire", () => {
    expect(agentCodes("https://api.anthropic.com/v1/messages")).not.toContain(
      "api_endpoint_impersonation",
    );
  });

  it("a deeper legit subdomain (foo.api.openai.com) does not fire", () => {
    expect(agentCodes("https://foo.api.openai.com")).not.toContain(
      "api_endpoint_impersonation",
    );
  });
});

describe("api_endpoint_impersonation — conservative: near-miss benign does NOT fire", () => {
  it("api.mycompany.com (no provider token) is clean", () => {
    expect(agentCodes("https://api.mycompany.com/v1/chat/completions")).not.toContain(
      "api_endpoint_impersonation",
    );
  });

  it("a label that merely contains a provider token as a substring does not fire", () => {
    // exact separator-delimited token, not substring: `myopenaitools` must stay clean.
    expect(agentCodes("https://myopenaitools.com")).not.toContain(
      "api_endpoint_impersonation",
    );
  });

  it("an IP host does not fire", () => {
    expect(agentCodes("https://127.0.0.1/v1/messages")).not.toContain(
      "api_endpoint_impersonation",
    );
  });
});

describe("api_endpoint_impersonation — weight", () => {
  it("is weight 0.5", () => {
    const r = inspect("https://api.openai-com.io/v1/chat/completions", { agentMode: true });
    expect(
      r.reasons.find((x) => x.code === "api_endpoint_impersonation")!.weight,
    ).toBeCloseTo(0.5, 5);
  });
});
