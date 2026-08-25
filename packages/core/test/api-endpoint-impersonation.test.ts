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

  // Corroboration gate (V4e tuning): a brand word appearing anywhere in the host
  // is too loose on its own (it false-positives on legitimate brand-word
  // subdomains and brand-owned alt-domains like github.io). To impersonate an API
  // ENDPOINT the host must ALSO look like one — an `api`-ish host label OR a known
  // API route path. A bare brand-token subdomain without either does NOT fire.
  it("a bare brand-token subdomain without a corroborating api label/route does NOT fire (openai.evil.com)", () => {
    expect(agentCodes("https://openai.evil.com")).not.toContain("api_endpoint_impersonation");
  });

  it("a bare brand-token subdomain WITH an api host label fires (api.openai.evil.com)", () => {
    expect(agentCodes("https://api.openai.evil.com")).toContain("api_endpoint_impersonation");
  });

  it("a bare brand-token subdomain WITH a known API route fires (openai.evil.com/v1/chat/completions)", () => {
    expect(agentCodes("https://openai.evil.com/v1/chat/completions")).toContain(
      "api_endpoint_impersonation",
    );
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

// ─────────────────────────────────────────────────────────────────────────────
// PIN — current behavior, recorded before the rescope under LINK-eurtxkit.
//
// These four rows are the whole case about the detector, stated as assertions
// rather than prose. They pin what the code does TODAY so that the deletion has
// to move something visible: three of the four change, and the one that does
// not (the homoglyph row) is the structural finding that survives on its own.
// ─────────────────────────────────────────────────────────────────────────────
describe("api_endpoint_impersonation — PIN: the rescope evidence (LINK-eurtxkit)", () => {
  it("PIN api.openai-login.com — 0.50 under agentMode ONLY, from the watchlist lookup alone", () => {
    const plain = inspect("https://api.openai-login.com");
    expect(plain.score).toBe(0);
    expect(plain.reasons).toHaveLength(0);

    const agent = inspect("https://api.openai-login.com", { agentMode: true });
    expect(agent.score).toBeCloseTo(0.5, 5);
    expect(agent.severity).toBe("medium");
    expect(agent.reasons.map((r) => r.code)).toEqual(["api_endpoint_impersonation"]);
  });

  it("PIN api.acme-login.com — the CONTROL: identical shape, unlisted token, 0.00 in BOTH modes", () => {
    // Same structure as the row above in every respect a URL parser can see: an
    // `api` label, a hyphenated `<word>-login` second label, a `.com` eTLD. The
    // only difference is that `openai` is on a commercial watchlist and `acme`
    // is not. That difference is the entire finding.
    const plain = inspect("https://api.acme-login.com");
    expect(plain.score).toBe(0);
    expect(plain.reasons).toHaveLength(0);

    const agent = inspect("https://api.acme-login.com", { agentMode: true });
    expect(agent.score).toBe(0);
    expect(agent.reasons).toHaveLength(0);
  });

  it("PIN api.0penai.com/v1/chat/completions — 0.80 brand_homoglyph in PLAIN mode, no agent gate needed", () => {
    // The structural case. A digit demonstrably folds to a letter, so the
    // finding stands on `skel !== raw` and the watchlist only names the target.
    const plain = inspect("https://api.0penai.com/v1/chat/completions");
    expect(plain.score).toBeCloseTo(0.8, 5);
    expect(plain.severity).toBe("high");
    expect(plain.reasons.map((r) => r.code)).toContain("brand_homoglyph");
  });

  it("PIN api.openai.com.evil.io/v1/chat/completions — DOUBLE-SCORING on one piece of evidence", () => {
    // Plain mode states the structural fact once: a real registrable domain is
    // parked in the subdomain of another. Under agentMode the api detector reads
    // the SAME `openai` label and stacks a second 0.50 on it, taking a medium to
    // a high without any new evidence having been observed.
    const plain = inspect("https://api.openai.com.evil.io/v1/chat/completions");
    expect(plain.score).toBeCloseTo(0.5, 5);
    expect(plain.severity).toBe("medium");
    expect(plain.reasons.map((r) => r.code)).toEqual(["embedded_domain_in_subdomain"]);

    const agent = inspect("https://api.openai.com.evil.io/v1/chat/completions", {
      agentMode: true,
    });
    expect(agent.score).toBeCloseTo(0.75, 5);
    expect(agent.severity).toBe("high");
    expect([...agent.reasons.map((r) => r.code)].sort()).toEqual([
      "api_endpoint_impersonation",
      "embedded_domain_in_subdomain",
    ]);
  });
});
