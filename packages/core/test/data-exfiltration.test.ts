import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// Agent-gated detector: every assertion runs `inspect(url, { agentMode: true })`
// because the detector is silent by default (gating is exercised in the contract
// test). Here we test the SIGNAL boundary: an exfil-marker parameter NAME fires, an
// abnormally long opaque token VALUE fires, and conservative cases (benign long
// natural-language search string, short marker value, plain benign URL) do NOT.

const agentCodes = (input: string): string[] =>
  inspect(input, { agentMode: true }).reasons.map((r) => r.code);

// A 240-char opaque base64-style blob (no spaces, all base64 alphabet) — clears the
// 200-char length floor AND the opaqueness gate.
const OPAQUE_BLOB = "A".repeat(120) + "b3BhcXVlVG9rZW5QYXlsb2Fk" + "Z".repeat(96);

describe("data_exfiltration — exfil-marker parameter NAMES fire (agentMode)", () => {
  it("exfil= with a value fires", () => {
    expect(agentCodes("https://collect.example.com/p?exfil=secretdata")).toContain(
      "data_exfiltration",
    );
  });

  it("beacon= with a value fires", () => {
    expect(agentCodes("https://log.example.net/?beacon=abc123")).toContain("data_exfiltration");
  });

  it("dump= / leak= / payload= each fire", () => {
    expect(agentCodes("https://x.example.com/?dump=v")).toContain("data_exfiltration");
    expect(agentCodes("https://x.example.com/?leak=v")).toContain("data_exfiltration");
    expect(agentCodes("https://x.example.com/?payload=v")).toContain("data_exfiltration");
  });
});

describe("data_exfiltration — overlong opaque token VALUE fires (agentMode)", () => {
  it("a >=200-char opaque base64 token value fires (any param name)", () => {
    expect(agentCodes(`https://log.example.net/?token=${OPAQUE_BLOB}`)).toContain(
      "data_exfiltration",
    );
  });

  it("the overlong opaque value fires even under a short, innocuous param name", () => {
    expect(agentCodes(`https://log.example.net/?d=${OPAQUE_BLOB}`)).toContain("data_exfiltration");
  });
});

describe("data_exfiltration — conservative: benign shapes do NOT fire (agentMode)", () => {
  it("a benign long natural-language q= search string does NOT fire", () => {
    // ~220 chars of spaced natural language: clears the length floor but fails the
    // opaqueness gate (spaces present, low alnum density).
    const sentence =
      "how do i reset my password and recover my account when i have lost access to my email " +
      "and my phone number is no longer valid and i need to contact support for help quickly " +
      "because i can no longer sign in and would really appreciate a step by step guide please";
    expect(sentence.length).toBeGreaterThanOrEqual(200);
    expect(
      agentCodes(`https://www.example.com/search?q=${encodeURIComponent(sentence)}`),
    ).not.toContain("data_exfiltration");
  });

  it("a short exfil= value (boundary: name is a marker but value short) STILL fires by name", () => {
    // The exfil-marker NAME path fires on ANY non-empty value, independent of
    // length — a short value is sufficient. Documents that boundary explicitly.
    expect(agentCodes("https://collect.example.com/?exfil=x")).toContain("data_exfiltration");
  });

  it("an empty exfil-marker value (exfil=) does NOT fire", () => {
    expect(agentCodes("https://collect.example.com/?exfil=")).not.toContain("data_exfiltration");
  });

  it("`data` is NOT a marker — it is an ordinary English word (LINK-uyoocslu)", () => {
    // It read 0.30/medium here on the parameter NAME alone. The value path is
    // untouched: an actual dump under a `data=` name is still caught by length
    // and opaqueness, which are properties of the value.
    expect(agentCodes("https://blog.example.com/download?data=report2024")).not.toContain(
      "data_exfiltration",
    );
    expect(agentCodes("https://collect.example.com/?data=x")).not.toContain("data_exfiltration");
    expect(agentCodes(`https://collect.example.com/?data=${OPAQUE_BLOB}`)).toContain(
      "data_exfiltration",
    );
  });

  it("a short opaque token under a non-marker name does NOT fire (below length floor)", () => {
    expect(agentCodes("https://www.example.com/?token=abc123def456")).not.toContain(
      "data_exfiltration",
    );
  });

  it("a plain benign URL does NOT fire", () => {
    expect(agentCodes("https://www.example.com/dashboard?page=2")).not.toContain(
      "data_exfiltration",
    );
  });
});

describe("data_exfiltration — weight", () => {
  // LINK-brsntven applied §1.1's ruling. The overlong-token branch flags a
  // string that is well-formed, agreed-upon and honest about itself, so it
  // reports rather than scores.
  it("is weight 0 — it reports, it does not score", () => {
    const r = inspect("https://collect.example.com/p?exfil=secretdata", { agentMode: true });
    expect(r.reasons.find((x) => x.code === "data_exfiltration")!.weight).toBe(0);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });
});
