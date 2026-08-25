import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-txgqerim — the INPUT SURFACE `open_redirect_param` reads.
//
// This file pins the surface itself, separately from `open-redirect-param.test.ts`
// (which pins the payload grammar) and `open-redirect-param-gate.test.ts` (which
// pins the divergence gate). It is written as a paired table: for each payload the
// QUERY spelling and the FRAGMENT spelling are asserted side by side, and the
// fragment's code set is compared to the query's code set. That comparison is the
// whole point — it states the relationship between the two surfaces rather than a
// list of codes, so it survives unrelated detectors coming and going.
//
// State pinned by this revision (LINK-txgqerim): the detector reads BOTH `ctx.query`
// and `ctx.fragment`, so the two surfaces produce the SAME code set — same reason
// code, same weight, wider input surface. The previous revision of this file pinned
// the opposite (fragment silent) and its four fragment rows were watched to redden
// on this change.

const codes = (input: string): string[] =>
  inspect(input)
    .reasons.map((r) => r.code)
    .sort();

const detailOf = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "open_redirect_param")?.detail ?? "";

/** Payloads that fire in the query today, paired with their fragment spelling. */
const PAIRS: ReadonlyArray<{
  readonly what: string;
  readonly query: string;
  readonly frag: string;
}> = [
  {
    what: "absolute cross-authority URL",
    query: "https://example.com/login?next=https://evil.com/phish",
    frag: "https://example.com/login#next=https://evil.com/phish",
  },
  {
    what: "protocol-relative payload",
    query: "https://example.com/login?redirect=//evil.com/",
    frag: "https://example.com/login#redirect=//evil.com/",
  },
  {
    what: "IP-literal target (the LINK-cvcjgewz pivot)",
    query: "https://example.com/login?url=http://169.254.169.254/latest/meta-data/",
    frag: "https://example.com/login#url=http://169.254.169.254/latest/meta-data/",
  },
  {
    what: "double-encoded cross-host value",
    query: "https://example.com/?url=https%253A%252F%252Fevil.com%252Fp",
    frag: "https://example.com/#url=https%253A%252F%252Fevil.com%252Fp",
  },
];

describe("LINK-txgqerim — the query surface fires (unchanged baseline)", () => {
  for (const { what, query } of PAIRS) {
    it(`query: ${what} fires`, () => {
      expect(codes(query)).toContain("open_redirect_param");
      expect(inspect(query).score ?? 0).toBeGreaterThanOrEqual(0.4);
    });
  }
});

describe("LINK-txgqerim — the fragment surface fires identically to the query", () => {
  for (const { what, query, frag } of PAIRS) {
    it(`fragment: ${what} produces the SAME code set as its query twin`, () => {
      expect(codes(frag)).toEqual(codes(query));
      expect(codes(frag)).toContain("open_redirect_param");
    });

    it(`fragment: ${what} scores the same as its query twin`, () => {
      expect(inspect(frag).score).toBe(inspect(query).score);
      expect(inspect(frag).severity).toBe(inspect(query).severity);
    });
  }

  it("same reason code and same weight — no new code, no SCHEMA_VERSION bump", () => {
    const r = inspect("https://example.com/login#next=https://evil.com/phish");
    const finding = r.reasons.find((x) => x.code === "open_redirect_param");
    expect(finding).toBeDefined();
    expect(finding!.weight).toBeCloseTo(0.4, 5);
  });

  it("the detail names the surface, so a consumer can tell the two apart", () => {
    expect(detailOf("https://example.com/login#next=https://evil.com/phish")).toContain(
      "fragment redirect parameter 'next'",
    );
    expect(detailOf("https://example.com/login?next=https://evil.com/phish")).toContain(
      "redirect parameter 'next'",
    );
    expect(detailOf("https://example.com/login?next=https://evil.com/phish")).not.toContain(
      "fragment",
    );
  });

  it("a hash ROUTE with its own query is read after the first '?'", () => {
    expect(codes("https://example.com/#/checkout?next=https://evil.com/x")).toContain(
      "open_redirect_param",
    );
  });

  it("the query is preferred when both surfaces carry a payload", () => {
    expect(
      detailOf("https://example.com/?next=https://evil.com/a#next=https://other.example.net/b"),
    ).toContain("evil.com");
  });
});

describe("LINK-txgqerim — the fragment surface must not over-flag (SC-2)", () => {
  const benign = [
    "https://example.com/#/dashboard", // hash route, no pairs at all
    "https://example.com/#section-3", // ordinary document fragment
    "https://example.com/#next=/dashboard", // relative same-host value
    "https://example.com/#next=https://app.example.com/home", // same registrable domain
    "https://example.com/#ref=https://evil.com", // not a redirect param name
    "https://example.com/#url=2", // not URL-like
    "https://example.com/#next=", // empty value
    "https://example.com/#/route?q=hello&page=2", // hash route with an ordinary query
  ];
  for (const input of benign) {
    it(`no open_redirect_param for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("open_redirect_param");
    });
  }

  it("a junk fragment does not throw and does not fire", () => {
    const input = "https://example.com/#next=%%%not-a-url%%%";
    expect(() => inspect(input)).not.toThrow();
    expect(codes(input)).not.toContain("open_redirect_param");
  });

  it("the RFC 6749 exemption applies on the fragment, decided per surface", () => {
    // Both markers on the same surface: the string declares its own type.
    expect(
      codes("https://idp.example.org/authorize#client_id=x&redirect_uri=https://myapp.io/cb"),
    ).not.toContain("open_redirect_param");
    // Markers split across surfaces: no declaration on either, so it still fires.
    expect(
      codes("https://idp.example.org/authorize?client_id=x#redirect_uri=https://myapp.io/cb"),
    ).toContain("open_redirect_param");
  });
});
