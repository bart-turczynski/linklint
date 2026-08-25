import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { KNOWN_SCHEMES } from "../src/parse/syntax.js";

/**
 * LINK-iuzphbnp — architecture §1.1's fourth rule: "where a `parse_error` is
 * unavoidable, it names what failed rather than standing in for the whole
 * verdict."
 *
 * This file is the pin for that rule on the scheme-bearing invalid path. Its
 * first commit recorded the pre-fix state — a single `parse_error` carrying the
 * serializer's generic fallback for `mhtml:…!x-usc:…`,
 * `ms-appinstaller:?source=…` and `view-source:https://…` — so the change is
 * readable as a diff of assertions rather than as a claim in a message.
 *
 * Two halves, and both matter:
 *
 *   1. THE DETAIL. Each of those inputs now names the scheme that was read,
 *      whether linklint recognizes it, and what the authority region was.
 *      Alongside them sit the two cases that must NOT move: a schemeless
 *      failure, where there is no name to give, and the non-string
 *      caller-contract failure that already occupied the `parseErrorDetail`
 *      channel.
 *   2. THE VERDICT. Status, score, severity, reason CODES, weights and both
 *      checks lists for the same inputs, asserted identically before and after.
 *      §1.1's fourth rule is a reporting obligation, not a widening of claim
 *      (a). A reviewer reads this half to confirm the change is explanatory
 *      only.
 */

/** The scheme-bearing inputs the fourth rule was failing on. */
const SCHEME_BEARING = [
  [
    "mhtml archive with an x-usc redirect",
    "mhtml:https://example.com/a.mhtml!x-usc:https://evil.test/",
    "mhtml",
  ],
  [
    "ms-appinstaller with a remote source",
    "ms-appinstaller:?source=https://evil.test/app.appinstaller",
    "ms-appinstaller",
  ],
  ["view-source wrapping an https URL", "view-source:https://example.com/", "view-source"],
] as const;

/**
 * The fallback the serializer emits when nothing sharpens the message. Written
 * out literally rather than imported, so a change to the constant shows up here
 * as a failure instead of being tracked silently.
 */
const GENERIC = "input is not a parseable URL or hostname";

describe("parse_error detail on scheme-bearing input (LINK-iuzphbnp)", () => {
  it.each(SCHEME_BEARING)("%s: the detail names the scheme that was read", (_l, url, scheme) => {
    const result = inspect(url);
    expect(result.reasons).toHaveLength(1);
    expect(result.reasons[0]!.code).toBe("parse_error");
    const detail = result.reasons[0]!.detail;
    expect(detail).not.toBe(GENERIC);
    expect(detail).toContain(`'${scheme}:'`);
  });

  it.each(SCHEME_BEARING)("%s: the detail says the body went uninspected", (_l, url) => {
    // Without this clause the message names a scheme and leaves the caller to
    // infer how much of the input was read. The invalid result's
    // `checksSkipped` already says `lexical`; the detail must not disagree.
    expect(inspect(url).reasons[0]!.detail).toContain("was not inspected");
    expect(inspect(url).checksSkipped).toContain("lexical");
  });

  it("says whether the scheme is one linklint recognizes, and gets it right", () => {
    // The recognition clause is the part a caller triages on: an unrecognized
    // scheme has no parse rule at all, a recognized one failed on its body.
    // Asserted against the live set so the two cannot drift apart.
    expect(KNOWN_SCHEMES.has("view-source")).toBe(true);
    expect(KNOWN_SCHEMES.has("mhtml")).toBe(false);
    expect(inspect("view-source:https://example.com/").reasons[0]!.detail).toContain(
      "is a scheme linklint recognizes",
    );
    expect(
      inspect("mhtml:https://example.com/a.mhtml!x-usc:https://evil.test/").reasons[0]!.detail,
    ).toContain("is not a scheme linklint recognizes");
  });

  it("distinguishes an absent authority from one that is not a host", () => {
    // `ms-appinstaller:?source=…` has no authority region at all, while
    // `view-source:https://…` has one — the nested `https:` — that is not a
    // host. Collapsing both into one sentence would lose the fact that names
    // the failure.
    expect(
      inspect("ms-appinstaller:?source=https://evil.test/app.appinstaller").reasons[0]!.detail,
    ).toContain("no authority follows it");
    expect(inspect("view-source:https://example.com/").reasons[0]!.detail).toContain(
      "the authority region 'https:' is not a host",
    );
  });

  it("truncates a very long authority region rather than dumping it", () => {
    // A `detail` is a line of text; the verbatim `input` echo is where the
    // untruncated string lives.
    const long = `nonesuch:${"a".repeat(200)}:99999/`;
    const detail = inspect(long).reasons[0]!.detail;
    expect(detail).toContain("…");
    // Bounded by the cap, not by the input: the echoed run stops well short of
    // the 200 characters that were written.
    expect(detail).not.toContain("a".repeat(41));
    expect(detail.length).toBeLessThan(200);
    // …and the untruncated string is still recoverable from the result.
    expect(inspect(long).input).toBe(long);
  });
});

describe("verdicts on the scheme-bearing invalid path do not move (LINK-iuzphbnp)", () => {
  it.each(SCHEME_BEARING)("%s: fail-closed shape is exactly as shipped", (_label, url) => {
    const result = inspect(url);
    expect(result.status).toBe("invalid");
    expect(result.score).toBeNull();
    expect(result.severity).toBeNull();
    expect(result.parsed).toBeNull();
    expect(result.reasons.map((r) => r.code)).toEqual(["parse_error"]);
    expect(result.reasons.map((r) => r.weight)).toEqual([0]);
    expect(result.checksRun).toEqual([]);
    expect(result.checksSkipped).toEqual(["lexical", "resolution", "reputation"]);
  });

  it("a schemeless parse failure keeps the generic fallback", () => {
    // The counterweight to the sharpening above: with no scheme token there is
    // nothing to name, so this input's detail is the one that must stay put.
    // `non-string-input.test.ts` pins the same string for "not a url at all";
    // this is the cucumber-pinned SC-2a vector.
    const result = inspect("ht!tp://%%%not a url");
    expect(result.reasons.map((r) => r.code)).toEqual(["parse_error"]);
    expect(result.reasons[0]!.detail).toBe(GENERIC);
  });

  it("a non-string input keeps its own sharpened detail", () => {
    // The existing occupant of the `parseErrorDetail` channel. Populating the
    // channel from the parse path must not displace the caller-contract case.
    const result = inspect(null as unknown as string);
    expect(result.reasons[0]!.detail).toContain("not a string");
  });

  it("the out-of-range-port failure gains the region and keeps its verdict", () => {
    // `http://example.com:65536/` already resolved to parse_error (LINK-drucugmm)
    // and still does — same status, same score, same single code. What changed
    // is that the caller can now see which text was rejected instead of being
    // told the whole input was unreadable.
    for (const url of ["http://example.com:65536/", "http://[::1]:99999/"]) {
      const result = inspect(url);
      expect(result.status, url).toBe("invalid");
      expect(result.score, url).toBeNull();
      expect(result.reasons.map((r) => r.code), url).toEqual(["parse_error"]);
      expect(result.reasons[0]!.detail, url).toContain("'http:'");
    }
    expect(inspect("http://example.com:65536/").reasons[0]!.detail).toContain(
      "'example.com:65536' is not a host",
    );
  });

  it("a findings-bearing invalid result is untouched — no parse_error fires", () => {
    // The sharpened detail rides on the fallback branch of `buildInvalidResult`.
    // When a structural scan already explained the failure there is no
    // `parse_error` at all, and passing a detail must not resurrect one.
    const result = inspect("https:///evil.com");
    expect(result.reasons.map((r) => r.code)).not.toContain("parse_error");
    expect(result.reasons.length).toBeGreaterThan(0);
  });
});

describe("view-source is a live KNOWN_SCHEMES entry, not a dead one (LINK-iuzphbnp)", () => {
  it("membership is load-bearing: it keeps a digit tail from reading as a port", () => {
    // The whole effect of `KNOWN_SCHEMES` is `looksLikeHostPort`. Drop
    // `view-source` from the set and this input becomes host `view-source` on
    // port 8080 — a different verdict, which is why the entry stays. The
    // contrast case is a name that is genuinely not in the set.
    const known = inspect("view-source:8080");
    expect(known.parsed?.scheme).toBe("view-source");
    expect(known.parsed?.port).toBeNull();

    const unknown = inspect("nonesuch:8080");
    expect(unknown.parsed?.scheme).toBeNull();
    expect(unknown.parsed?.effectiveHost).toBe("nonesuch");
    expect(unknown.parsed?.port).toBe(8080);
  });

  it("membership is not a promise that the nested scheme is unwrapped", () => {
    // Chrome reads `view-source:` as a wrapper around the URL that follows.
    // linklint does not, and this pins that it still does not: the input fails
    // closed. Changing that would move verdicts and is out of this scope.
    const result = inspect("view-source:https://paypal.com.evil.test/");
    expect(result.status).toBe("invalid");
    expect(result.score).toBeNull();
    expect(result.reasons.map((r) => r.code)).toEqual(["parse_error"]);
  });
});
