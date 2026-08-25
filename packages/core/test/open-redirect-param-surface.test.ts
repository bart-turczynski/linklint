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
// State pinned by this revision: the detector passes `ctx.query` and nothing else,
// so a payload in the fragment is silent — the fragment's code set is the query's
// MINUS `open_redirect_param`. The fragment IS carried through `parse/context.ts`
// and IS read by `encoding-obfuscation`, `low-byte-truncation` and
// `percent-encoding-malformed`, so this is an input-surface omission and not a
// parsing limit.

const codes = (input: string): string[] =>
  inspect(input)
    .reasons.map((r) => r.code)
    .sort();

const without = (list: string[], code: string): string[] => list.filter((c) => c !== code);

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

describe("LINK-txgqerim — the fragment surface is CURRENTLY SILENT (pinned, to be changed)", () => {
  for (const { what, query, frag } of PAIRS) {
    it(`fragment: ${what} does NOT fire — code set is the query's minus open_redirect_param`, () => {
      expect(codes(frag)).toEqual(without(codes(query), "open_redirect_param"));
    });
  }

  it("the fragment reaches the detector context even though nothing reads it here", () => {
    const r = inspect("https://example.com/login#next=https://evil.com/phish");
    expect(r.parsed?.fragment).toBe("next=https://evil.com/phish");
  });

  it("an SPA hash route carrying an off-site URL is silent too", () => {
    expect(codes("https://example.com/#/route?url=https://cdn.example.org/x")).not.toContain(
      "open_redirect_param",
    );
  });
});
