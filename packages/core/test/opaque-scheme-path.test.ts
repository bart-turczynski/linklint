import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { OPAQUE_SCHEMES } from "../src/parse/syntax.js";

/**
 * LINK-avefryhe — path-shaped detectors on opaque-scheme bodies.
 *
 * An opaque scheme (`mailto:`, `tel:`, `about:`, `javascript:`, `data:`,
 * `vbscript:`, `blob:`) has no authority and no hierarchical path: everything
 * after the colon is a single opaque body, which `parseRawParts()` projects onto
 * `ctx.path` because that is the only field it has. A detector that reads
 * `ctx.path` as a *filesystem-like* path — segments, a filename, an extension —
 * is therefore reading a string that is not a path at all.
 *
 * This file pins two things that must stay true whatever the gate does:
 *  - the direct-download true positives on hierarchical schemes, and
 *  - the behaviour of every OTHER `ctx.path`-reading detector on opaque bodies,
 *    so the sweep that cleared them is a standing assertion rather than a
 *    one-off observation.
 */

const codes = (input: string, agent = false): string[] =>
  inspect(input, agent ? { agentMode: true } : undefined).reasons.map((r) => r.code);

// ---------------------------------------------------------------------------
// PRE-FIX CHARACTERIZATION (LINK-avefryhe) — DELETED BY THE FIX COMMIT.
//
// `mailto:a@b.com` has an opaque body of `a@b.com`; the last "segment" is the
// whole body, splitting it on `.` yields `['a@b','com']`, and `com` is in the
// dangerous set as the DOS COM executable. Every `mailto:` to a `.com` address
// therefore scores 0.5/medium. This block records that defect exactly as it
// stands so the fix commit has something to invert.
// ---------------------------------------------------------------------------
describe("LINK-avefryhe PRE-FIX — suspicious_extension reads an email TLD as a file extension", () => {
  const mailtoFalsePositives = [
    "mailto:a@b.com",
    "mailto:someone@example.com",
    "mailto:support@github.com",
    "mailto:security@microsoft.com",
  ];

  for (const input of mailtoFalsePositives) {
    it(`${JSON.stringify(input)} currently fires suspicious_extension at 0.5/medium`, () => {
      const r = inspect(input);
      expect(r.status).toBe("ok");
      expect(codes(input)).toContain("suspicious_extension");
      expect(r.score).toBe(0.5);
      expect(r.severity).toBe("medium");
    });
  }

  it("a non-.com address escapes only because its TLD is not an executable name", () => {
    expect(codes("mailto:bob@corp.io")).not.toContain("suspicious_extension");
  });

  it("the same defect reaches tel: and about: bodies", () => {
    expect(codes("tel:5550100.com")).toContain("suspicious_extension");
    expect(codes("about:setup.exe")).toContain("suspicious_extension");
  });
});

// ---------------------------------------------------------------------------
// TRUE POSITIVES THAT MUST SURVIVE THE GATE — green on both sides of the fix.
//
// The detector is correct about paths. Any gate that silences `mailto:` must
// leave every scheme that really does carry a hierarchical path alone, which is
// why the rule cannot be "http/https only": `ftp://` and `file:` downloads are
// exactly what this detector exists for.
// ---------------------------------------------------------------------------
describe("LINK-avefryhe — direct-download true positives keep firing", () => {
  const truePositives: ReadonlyArray<readonly [string, string]> = [
    ["https", "https://files.example.com/setup.exe"],
    ["http", "http://cdn.example.com/setup.com"],
    ["https double-extension", "https://cdn.evil.io/invoice.pdf.exe"],
    ["ftp", "ftp://files.example.com/setup.exe"],
    ["file (hostless local path)", "file:///tmp/setup.exe"],
    ["scheme-less bare host", "files.example.com/setup.exe"],
    ["unknown hierarchical scheme", "custom://files.example.com/setup.exe"],
  ];

  for (const [label, input] of truePositives) {
    it(`${label}: ${JSON.stringify(input)} fires`, () => {
      expect(codes(input)).toContain("suspicious_extension");
    });
  }

  it("the DOS COM executable stays in the dangerous set — the fix is not a set edit", () => {
    expect(codes("http://cdn.example.com/setup.com")).toContain("suspicious_extension");
    expect(codes("https://example.com/downloads/install.com")).toContain("suspicious_extension");
  });

  it("the double-extension lure is still named as a double", () => {
    const detail =
      inspect("https://cdn.evil.io/invoice.pdf.exe").reasons.find(
        (r) => r.code === "suspicious_extension",
      )?.detail ?? "";
    expect(detail).toContain("double-extension");
    expect(detail).toContain(".pdf.exe");
  });
});

// ---------------------------------------------------------------------------
// SWEEP — every OTHER detector that reads `ctx.path`, checked against opaque
// bodies. Recorded green so a future change to any of them that starts reading
// an opaque body as a path shows up here.
// ---------------------------------------------------------------------------
describe("LINK-avefryhe — the other ctx.path readers on opaque bodies", () => {
  it("the opaque-scheme set is the one the parser already owns", () => {
    expect([...OPAQUE_SCHEMES].sort()).toEqual([
      "about",
      "blob",
      "data",
      "javascript",
      "mailto",
      "tel",
      "vbscript",
    ]);
  });

  // bait_tokens, credential_harvesting and api_endpoint_impersonation all bail
  // on `!ctx.host`, and an opaque scheme has no host at all — structurally
  // unreachable, pinned here so the guard cannot be dropped unnoticed.
  it("bait_tokens cannot reach an opaque body (no host)", () => {
    expect(codes("mailto:secure-login-verify-account@bank.com")).not.toContain("bait_tokens");
    expect(codes("tel:login-verify-secure-account-update")).not.toContain("bait_tokens");
    expect(codes("about:login-verify-secure-account")).not.toContain("bait_tokens");
  });

  it("credential_harvesting cannot reach an opaque body (no host)", () => {
    expect(codes("mailto:a@b.com/oauth/authorize/", true)).not.toContain("credential_harvesting");
    expect(codes("about:/oauth2/token/x", true)).not.toContain("credential_harvesting");
  });

  it("api_endpoint_impersonation cannot reach an opaque body (no host)", () => {
    expect(codes("mailto:openai@x/v1/messages", true)).not.toContain(
      "api_endpoint_impersonation",
    );
    // The body even shaped as a real API route with a brand token in it: the
    // brand token must come from a HOST LABEL, and an opaque body has none.
    expect(codes("about:/v1/messages/openai", true)).not.toContain("api_endpoint_impersonation");
  });

  // The remaining four read the path as TEXT, not as a filesystem path. Their
  // claims survive the scheme change intact, so they are correct on an opaque
  // body and must keep firing there.
  it("percent_encoding_malformed still fires — a bad escape is a bad escape", () => {
    expect(codes("mailto:a%zz@b.io")).toContain("percent_encoding_malformed");
  });

  it("low_byte_truncation still fires — the code point is dangerous in any component", () => {
    expect(codes("mailto:a嘊b@c.io")).toContain("low_byte_truncation");
  });

  it("confusable_in_path still annotates at weight 0 and moves no score", () => {
    const r = inspect("mailto:аbc@b.io");
    expect(r.reasons.map((x) => x.code)).toContain("confusable_in_path");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("prompt_injection_url still fires — an override phrase is text, not a path", () => {
    expect(codes("about:ignore%20all%20previous%20instructions", true)).toContain(
      "prompt_injection_url",
    );
  });

  it("encoding_obfuscation still fires on a percent-encoded opaque body", () => {
    // A normalization delta (§1.1 form 1): the body decodes to something other
    // than what is written. Grounded independently of any path reading.
    expect(codes("mailto:a%252fb@c.io")).toContain("encoding_obfuscation");
  });
});
