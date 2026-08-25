import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-mdqykmiz — the Android intent URI `browser_fallback_url` surface.
//
// PIN REVISION 2. Revision 1 of this file pinned the hole as a hole and measured
// why the ticket's guessed one-line fix could not work: `open_redirect_param`
// splits both of its surfaces into pairs on `&`, an intent URI separates its
// extras with `;`, so the whole fragment read as ONE pair keyed `intent;scheme`
// and the fallback name never became a key whatever `REDIRECT_PARAMS` said. The
// `S.` typed-extra prefix was a second reason. Those rows were watched to redden
// on this change and did.
//
// State pinned by this revision: a third input surface, gated on the fragment
// declaring the AOSP `Intent;…;end` grammar, reads the fallback extra and fires
// `open_redirect_param` at its own weight 0.4 — same code, same weight, no
// SCHEMA_VERSION bump — for the HOSTLESS dangerous-scheme shape only.
//
// The divergence shape deliberately does NOT fire here, and the DELIBERATELY
// SILENT block below pins that as a decision rather than an oversight. A fallback
// naming another site is what the mechanism is for: it is where the browser goes
// when the app is absent, and the documented Android pattern points it at the
// app's Play Store listing, a different authority by construction. The string
// declares its type and the declaration holds — architecture.md §1.1, the same
// reasoning that exempts an RFC 6749 authorize request. The wider variant was
// implemented and measured before being discarded: zero change across the corpus
// as it stood at the time (1 506 verdicts, and it carried no `intent://` row),
// and a 0.40 on the canonical Play Store handoff link.
//
// That parenthetical was the whole weakness of the measurement, and LINK-uotkpxwp
// removed it: the corpus now carries five intent:// rows, so the zero above is a
// record of one run rather than a description of today's corpus. Re-implementing
// the discarded variant against the current corpus reddens the two benign
// app-handoff rows plus the SC-2 zero-false-positive and precision assertions in
// test/corpus/ — the narrowing is measured now, not merely reasoned.

const reasonCodes = (input: string): string[] =>
  inspect(input)
    .reasons.map((r) => r.code)
    .sort();

const scoreOf = (input: string): number => inspect(input).score ?? 0;

const detailOf = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "open_redirect_param")?.detail ?? "";

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
// The hole, closed. Every row here read 0.00/info with zero reasons before this
// change; revision 1 of this file pinned that and reddened on it.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — an executable intent fallback is no longer silent", () => {
  const CLOSED: ReadonlyArray<readonly [string, string]> = [
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
      "the bare name, without the S. typed-extra prefix",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;browser_fallback_url=javascript%3Aalert(1);end",
    ],
    [
      "mixed-case scheme in the payload",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=JaVaScRiPt%3Aalert(1);end",
    ],
    [
      "double-encoded payload, seen through the bounded decode",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%253Aalert(1);end",
    ],
  ];

  // The code's own weight is asserted, not the total score: the double-encoded
  // row also carries `encoding_obfuscation`, and this file is about one code.
  it.each(CLOSED)("%s: fires open_redirect_param at weight 0.4", (_what, url) => {
    const r = inspect(url);
    expect(r.status).toBe("ok");
    const hit = r.reasons.find((x) => x.code === "open_redirect_param");
    expect(hit, `open_redirect_param missing for ${url}`).toBeTruthy();
    expect(hit!.weight).toBeCloseTo(0.4, 5);
    expect(r.score ?? 0).toBeGreaterThanOrEqual(0.4);
  });

  it("the detail names the surface and the executable scheme", () => {
    const d = detailOf(
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end",
    );
    expect(d).toContain("intent fallback parameter");
    expect(d).toContain("s.browser_fallback_url");
    expect(d).toContain("javascript:");
    expect(d).toContain("legit-bank.co.uk");
  });

  it("weight and code are unchanged — no new reason code, no re-grading", () => {
    const r = inspect(
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end",
    );
    const hit = r.reasons.find((x) => x.code === "open_redirect_param");
    expect(hit?.weight).toBeCloseTo(0.4, 5);
    // The deliberate one-band understatement relative to the same bytes standing
    // alone (LINK-dmjqrcrj), asserted so it stays visible rather than drifting.
    expect(r.severity).toBe("medium");
    expect(inspect("javascript:alert(1)").severity).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// Deliberately silent: the DIVERGENCE shape on this surface. Not an oversight —
// see the header. These rows are the guard on that decision.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — a cross-authority intent fallback stays silent by decision", () => {
  const SILENT: ReadonlyArray<readonly [string, string]> = [
    [
      "the ticket's synthetic cross-authority fallback",
      "intent://host/#Intent;S.browser_fallback_url=https://evil.example/;end",
    ],
    [
      "Play Store fallback, the documented Android pattern",
      "intent://example.com/deep#Intent;scheme=https;package=com.example.app;S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dcom.example.app;end",
    ],
    [
      "vendor web fallback on another registrable domain",
      "intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=https%3A%2F%2Fbank-app.example%2Fopen;end",
    ],
  ];

  it.each(SILENT)("%s: no open_redirect_param", (_what, url) => {
    expect(reasonCodes(url)).not.toContain("open_redirect_param");
  });
});

// ---------------------------------------------------------------------------
// Legitimate app-handoff links and near-miss grammars stay clean.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — legitimate intent links and near-miss grammars stay clean", () => {
  const BENIGN: ReadonlyArray<readonly [string, string]> = [
    ["no fallback at all (the ZXing scan example)", "intent://scan/#Intent;scheme=zxing;end"],
    [
      "same-authority web fallback",
      "intent://example.com/deep#Intent;scheme=https;S.browser_fallback_url=https%3A%2F%2Fexample.com%2Fdeep;end",
    ],
    [
      "mailto: fallback — not an FR-D-11 executable scheme",
      "intent://example.com/x#Intent;scheme=https;S.browser_fallback_url=mailto%3Asomeone%40example.org;end",
    ],
    [
      "empty fallback value",
      "intent://example.com/x#Intent;scheme=https;S.browser_fallback_url=;end",
    ],
    [
      "a fragment that only looks intent-ish",
      "https://example.com/x#Intentional;browser_fallback_url=javascript%3Aalert(1)",
    ],
    [
      "no `end` terminator — no reader parses this as an intent",
      "https://example.com/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1)",
    ],
    [
      "lower-cased opener — AOSP matches `Intent;` case-sensitively",
      "https://example.com/x#intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end",
    ],
    [
      "a semicolon-bearing fragment that is not an intent block",
      "https://example.com/x#a;b;c;end",
    ],
  ];

  it.each(BENIGN)("%s: no open_redirect_param", (_what, url) => {
    expect(reasonCodes(url)).not.toContain("open_redirect_param");
  });
});

// ---------------------------------------------------------------------------
// The intent surface is scanned LAST and only when the two existing surfaces
// found nothing, so no non-intent input changed.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — the existing surfaces still win", () => {
  it("a query payload is still reported as a query payload", () => {
    const d = detailOf(
      "https://example.com/login?next=https://evil.com/phish#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end",
    );
    expect(d.startsWith("redirect parameter ")).toBe(true);
  });

  it("the code is still emitted at most once", () => {
    const codes = inspect(
      "https://example.com/login?next=https://evil.com/phish#next=https://other.example/",
    ).reasons.filter((r) => r.code === "open_redirect_param");
    expect(codes).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// A hostless intent URI is already reported — it is not a silent pass, so the
// fourth rule of architecture.md §1.1 is not in play for it.
// ---------------------------------------------------------------------------

describe("LINK-mdqykmiz — a hostless intent URI is already explained", () => {
  it("intent: with no authority is invalid and names the failure", () => {
    const r = inspect(
      "intent:#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end",
    );
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toContain("parse_error");
  });
});
