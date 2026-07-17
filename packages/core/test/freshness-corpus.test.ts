import { describe, expect, it } from "vitest";
import { parse as tldtsParse } from "tldts";
import { analyzeHost } from "../src/parse/psl.js";

/**
 * PSL-freshness harm corpus — McQuistin, Snyder, Perkins, Haddadi, Tyson,
 * "A First Look at the Privacy Harms of the Public Suffix List" (IMC '23),
 * Table 2. (P2 / LINK-rkhuihjx; rides alongside the paper-vector corpus import
 * LINK-krzcupbk.)
 *
 * The paper's harm: an OUTDATED PSL silently yields the wrong registrable
 * domain. When a newly-added multi-tenant eTLD is missing from a stale list, a
 * tenant host such as `foo.myshopify.com` collapses to registrable domain
 * `myshopify.com`, treating every tenant as the same site (paper §3, Table 2).
 *
 * These tests pin Table-2 eTLDs against the BUNDLED tldts PSL so we can never
 * ship a snapshot stale enough to reintroduce the documented tenant-collapse.
 * The discriminating assertion IS the harm: two distinct tenants must NOT
 * collapse to a shared registrable domain.
 *
 * They probe tldts with `allowPrivateDomains: true` — the PRIVATE section of the
 * PSL is where these multi-tenant eTLDs live, so this is the freshness gate on
 * the bundled data. (linklint's own analyzeHost() deliberately uses
 * `allowPrivateDomains: false`; that tradeoff is documented in its own test
 * block below.)
 *
 * Table 2 mixes two rule shapes:
 *   * plain    (e.g. `myshopify.com`)            — the entry IS the eTLD.
 *   * wildcard (e.g. `*.digitaloceanspaces.com`) — the eTLD is one label below
 *     the entry, so the bare entry is NOT itself a public suffix.
 */

// Plain Table-2 eTLDs: each entry is itself a public suffix.
const freshnessPlain = [
  "myshopify.com",
  "readthedocs.io",
  "netlify.app",
  "web.app",
  "carrd.co",
] as const;

// Wildcard Table-2 eTLDs: listed as `*.<entry>`, so the boundary sits one label
// below the entry and the bare entry is not itself a public suffix.
const freshnessWildcard = ["digitaloceanspaces.com", "r.appspot.com"] as const;

/** Registrable domain under the PSL private section (the freshness-gated view). */
function privateDomain(host: string): string | null {
  return tldtsParse(host, { allowPrivateDomains: true }).domain;
}

describe("PSL freshness — plain Table-2 eTLDs (IMC '23)", () => {
  it.each(freshnessPlain)(
    "%s puts the trust boundary below the tenant label",
    (etld) => {
      const r = tldtsParse(`tenant.${etld}`, { allowPrivateDomains: true });
      // Suffix is the eTLD itself — not the bare TLD a stale list would report.
      expect(r.publicSuffix).toBe(etld);
      // Registrable domain keeps the tenant label, so distinct tenants stay
      // distinct instead of collapsing onto the shared eTLD (the paper's harm).
      expect(r.domain).toBe(`tenant.${etld}`);
    },
  );

  it.each(freshnessPlain)("distinct tenants of %s stay distinct", (etld) => {
    // The concrete privacy harm: on a stale list both collapse to the eTLD.
    const foo = privateDomain(`foo.${etld}`);
    const bar = privateDomain(`bar.${etld}`);
    expect(foo).toBe(`foo.${etld}`);
    expect(bar).toBe(`bar.${etld}`);
    expect(foo).not.toBe(bar);
    expect(foo).not.toBe(etld);
  });
});

describe("PSL freshness — wildcard Table-2 eTLDs (IMC '23)", () => {
  it.each(freshnessWildcard)(
    "%s: boundary sits one label below the entry",
    (entry) => {
      // Under a `*.<entry>` rule the boundary is `<label>.<entry>`, so a tenant
      // two labels deep keeps its own label as the registrable domain.
      const foo = privateDomain(`foo.reg.${entry}`);
      const bar = privateDomain(`bar.reg.${entry}`);
      expect(foo).toBe(`foo.reg.${entry}`);
      expect(bar).toBe(`bar.reg.${entry}`);
      expect(foo).not.toBe(bar);
    },
  );
});

/**
 * Documented tradeoff (NON-goal of P2): linklint's analyzeHost() uses
 * `allowPrivateDomains: false` DELIBERATELY, so an embedded `github.io` is still
 * seen as a registrable domain by FR-D-8. The consequence, from the same paper,
 * is that at the linklint layer these private-suffix tenants DO collapse onto
 * the ICANN registrable domain (good.myshopify.com and evil.myshopify.com both
 * resolve to `myshopify.com`). This block PINS that behavior so the tradeoff is
 * explicit and any future flip of the flag is a conscious, tested change. It is
 * recorded as a candidate follow-up (per-detector boundary choice), NOT fixed
 * here.
 */
describe("documented tradeoff — analyzeHost uses ICANN-only rules", () => {
  it.each(freshnessPlain)(
    "collapses tenants of %s to the ICANN registrable domain",
    (etld) => {
      // ICANN-only: the private suffix is invisible, so tenants collapse. This is
      // the deliberate P2 non-goal; the freshness gate above uses the private
      // view instead.
      expect(analyzeHost(`good.${etld}`).registrableDomain).toBe(etld);
      expect(analyzeHost(`evil.${etld}`).registrableDomain).toBe(etld);
    },
  );
});
