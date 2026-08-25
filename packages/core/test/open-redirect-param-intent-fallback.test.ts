import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-mdqykmiz — the Android intent URI `browser_fallback_url` surface.
//
// PIN REVISION 1 (this commit): pins the state of the tree BEFORE any fix, the
// hole included. `open_redirect_param` reads `ctx.query` and `ctx.fragment`
// (LINK-txgqerim), and both are split into `key=value` pairs on `&`. An Android
// intent URI writes its extras into the fragment separated by `;`:
//
//   intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=…;end
//
// so the whole fragment reads as ONE pair whose key is `intent;scheme`. Adding
// `browser_fallback_url` to `REDIRECT_PARAMS` alone therefore changes nothing —
// the name never becomes a key. That measurement is what the HOLE block below
// records, so the next revision cannot claim the list was the whole story.
//
// The BASELINE block is the control: it pins the two surfaces that already work,
// so a regression in the shared machinery is told apart from a change in the
// intent surface.

const reasonCodes = (input: string): string[] =>
  inspect(input)
    .reasons.map((r) => r.code)
    .sort();

const scoreOf = (input: string): number => inspect(input).score ?? 0;

// ---------------------------------------------------------------------------
// Control: the surfaces that already carry a hostless dangerous payload.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — control: query and fragment already carry a hostless payload", () => {
  const CONTROL: ReadonlyArray<readonly [string, string]> = [
    ["query", "https://legit-bank.co.uk/x?next=javascript%3Aalert(1)"],
    ["fragment", "https://legit-bank.co.uk/x#next=javascript%3Aalert(1)"],
  ];

  it.each(CONTROL)("%s: a `next=javascript:` payload fires open_redirect_param", (_what, url) => {
    expect(reasonCodes(url)).toContain("open_redirect_param");
    expect(scoreOf(url)).toBeCloseTo(0.4, 5);
  });

  it("a bare javascript: URL is still critical on its own", () => {
    const r = inspect("javascript:alert(1)");
    expect(r.reasons.map((x) => x.code)).toContain("dangerous_scheme");
    expect(r.score).toBeCloseTo(0.9, 5);
    expect(r.severity).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// THE HOLE. Every row here scores 0.00 with zero reasons today. These rows are
// watched to REDDEN when the intent surface is read.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — HOLE: nothing reads the intent extras (pinned as a hole)", () => {
  const HOLE: ReadonlyArray<readonly [string, string]> = [
    [
      "javascript: fallback under a real bank authority",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end",
    ],
    [
      "javascript: fallback, unencoded colon",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript:alert(1);end",
    ],
    [
      "data: fallback",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=data%3Atext%2Fhtml%2C%3Cb%3Ex%3C%2Fb%3E;end",
    ],
    [
      "cross-authority https fallback",
      "intent://host/#Intent;S.browser_fallback_url=https://evil.example/;end",
    ],
  ];

  it.each(HOLE)("%s: scores 0.00 with no reasons", (_what, url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    expect(r.reasons.map((x) => x.code)).toEqual([]);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("the `S.` typed-extra prefix is why the parameter name alone is not enough", () => {
    // The whole fragment is one `&`-separated pair, so the key the shared pair
    // splitter sees is `intent;scheme`, not any spelling of the fallback name.
    const url =
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end";
    expect(reasonCodes(url)).toEqual([]);
    // Same payload, same parameter name, `&`-separated: still silent, because the
    // name is not in the redirect-parameter list either.
    const ampersand = "https://legit-bank.co.uk/x#browser_fallback_url=javascript%3Aalert(1)";
    expect(reasonCodes(ampersand)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The false-positive class. A legitimate app-handoff link hands off to another
// site BY CONSTRUCTION — that is what a fallback is for. These rows must stay
// clean across the fix.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — legitimate intent app-handoff links stay clean", () => {
  const BENIGN: ReadonlyArray<readonly [string, string]> = [
    ["no fallback at all (the ZXing scan example)", "intent://scan/#Intent;scheme=zxing;end"],
    [
      "Play Store fallback, the documented Android pattern",
      "intent://example.com/deep#Intent;scheme=https;package=com.example.app;S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dcom.example.app;end",
    ],
    [
      "same-authority web fallback",
      "intent://example.com/deep#Intent;scheme=https;S.browser_fallback_url=https%3A%2F%2Fexample.com%2Fdeep;end",
    ],
    [
      "mailto: fallback — not an FR-D-11 executable scheme",
      "intent://example.com/x#Intent;scheme=https;S.browser_fallback_url=mailto%3Asomeone%40example.org;end",
    ],
    [
      "a fragment that only looks intent-ish",
      "https://example.com/x#Intentional;browser_fallback_url=whatever",
    ],
  ];

  it.each(BENIGN)("%s: no open_redirect_param", (_what, url) => {
    expect(reasonCodes(url)).not.toContain("open_redirect_param");
  });
});

// ---------------------------------------------------------------------------
// A hostless intent URI is already reported — it is not a silent pass, so the
// fourth rule of architecture.md §1.1 is not in play for it.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — a hostless intent URI is already explained", () => {
  it("intent: with no authority is invalid and names the failure", () => {
    const r = inspect("intent:#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("parse_error");
  });
});
