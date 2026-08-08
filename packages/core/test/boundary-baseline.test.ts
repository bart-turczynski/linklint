import { describe, expect, it } from "vitest";
import {
  buildBaseline,
  collectHosts,
  diffBaselines,
  readBaseline,
  rowFor,
} from "./boundary-baseline.js";
import { BRAND_DOMAINS } from "../src/data/brands.js";
import { DATA_VERSIONS } from "../src/data/versions.js";

/**
 * U3 (LINK-jwnqtase) — the pin-bump gate.
 *
 * U1 and U2 assert linklint still agrees with UPSTREAM. This asserts linklint
 * still agrees with ITSELF: a `tldts` or `tr46` bump can be perfectly conformant
 * upstream (a genuinely new PSL rule, a newly-assigned code point) and still
 * silently redraw the registrable domain of a watchlist brand. That is the change
 * class nothing else here catches.
 *
 * On failure the diff names every host that moved, so the reviewer sees the blast
 * radius rather than a bare "snapshot differs". Accepting a bump means re-running
 * `pnpm data:boundary` and committing the refreshed baseline in the SAME commit.
 */

const committed = readBaseline();
const current = buildBaseline();

describe("boundary baseline — linklint's own answers have not moved", () => {
  it("no host changed its boundary or normalization result", () => {
    const diff = diffBaselines(committed, current);
    // Rendered as text so a failure reads as a review list, not an object dump.
    expect(diff.join("\n")).toBe("");
  });

  it("covers the same host set", () => {
    expect(Object.keys(current.hosts).sort()).toEqual(Object.keys(committed.hosts).sort());
    expect(current._meta.hosts).toBe(committed._meta.hosts);
  });

  it("is stamped with the pins it was generated against", () => {
    // If a pin moves without the baseline being refreshed, this fails alongside
    // the diff above and names the culprit directly.
    expect(committed._meta.publicSuffixList).toBe(DATA_VERSIONS.publicSuffixList);
    expect(committed._meta.idna).toBe(DATA_VERSIONS.idna);
  });
});

describe("the input set is the one that matters", () => {
  const hosts = new Set(collectHosts());

  it("covers every brand watchlist domain", () => {
    // Brand matching compares whole registrable domains, so a boundary move here
    // changes detector behaviour directly.
    expect(BRAND_DOMAINS.length).toBeGreaterThan(0);
    for (const domain of BRAND_DOMAINS) expect(hosts, domain).toContain(domain);
  });

  it("covers the IMC '23 multi-tenant eTLDs and a tenant under each", () => {
    for (const etld of ["myshopify.com", "github.io", "netlify.app", "r.appspot.com"]) {
      expect(hosts, etld).toContain(etld);
      expect(hosts, `tenant.${etld}`).toContain(`tenant.${etld}`);
    }
  });

  it("covers the upstream PSL rule shapes and the corpus hosts", () => {
    for (const host of ["a.b.test.ck", "www.ck", "b.c.mm", "city.kobe.jp", "uk.com"]) {
      expect(hosts, host).toContain(host);
    }
    expect(hosts.size).toBeGreaterThan(200);
  });

  it("is deterministic — sorted, de-duplicated, no clock or network", () => {
    const a = collectHosts();
    const b = collectHosts();
    expect(a).toEqual(b);
    expect(a).toEqual([...a].sort());
    expect(new Set(a).size).toBe(a.length);
  });
});

describe("the diff actually detects the changes it claims to", () => {
  // A snapshot gate that cannot fail is worthless. These mutate a copy of the
  // baseline and assert the diff names the right class — the negative control.
  const clone = (): ReturnType<typeof buildBaseline> =>
    JSON.parse(JSON.stringify(current)) as ReturnType<typeof buildBaseline>;

  it("reports a moved registrable domain", () => {
    const after = clone();
    (after.hosts["paypal.com"] as { icannDomain: string | null }).icannDomain = "com";
    const diff = diffBaselines(current, after).join("\n");
    expect(diff).toContain("CHANGED ANSWERS");
    expect(diff).toContain("paypal.com: registrable domain (ICANN-only)");
  });

  it("reports an ICANN/PRIVATE section move SEPARATELY from other changes", () => {
    // The distinct, reviewable event: a rule crossing the section boundary moves
    // one view while leaving the other intact.
    const after = clone();
    (after.hosts["tenant.myshopify.com"] as { isIcann: boolean | null }).isIcann = true;
    const diff = diffBaselines(current, after).join("\n");
    expect(diff).toContain("SECTION MOVES (1)");
    expect(diff).toContain("tenant.myshopify.com: PSL SECTION: false -> true");
  });

  it("reports a moved normalization result", () => {
    const after = clone();
    (after.hosts["paypal.com"] as { asciiT: string | null }).asciiT = "xn--nope";
    expect(diffBaselines(current, after).join("\n")).toContain("toASCII transitional");
  });

  it("reports added and removed hosts, and a pin change", () => {
    const after = clone();
    delete (after.hosts as Record<string, unknown>)["paypal.com"];
    (after.hosts as Record<string, unknown>)["brand-new.example"] = rowFor("brand-new.example");
    (after._meta as { publicSuffixList: string }).publicSuffixList = "tldts@9.9.9";
    const diff = diffBaselines(current, after).join("\n");
    // Read the "before" side off the live stamp: this asserts the PIN line is
    // RENDERED, not what the pin currently is (`data-versions.test.ts` owns
    // that), so a legitimate bump does not fail the formatter's own test.
    expect(diff).toContain(`PIN  tldts: ${DATA_VERSIONS.publicSuffixList} -> tldts@9.9.9`);
    expect(diff).toContain("REMOVED  paypal.com");
    expect(diff).toContain("ADDED    brand-new.example");
  });

  it("an unchanged baseline diffs to nothing", () => {
    expect(diffBaselines(current, clone())).toEqual([]);
  });
});

describe("recorded rows carry both PSL views", () => {
  it("a PRIVATE-section tenant differs between the two views", () => {
    // This asymmetry is the whole reason both views are recorded: the ICANN-only
    // view (what inspect() uses) collapses tenants; the PRIVATE view does not.
    const row = rowFor("tenant.myshopify.com");
    expect(row.icannDomain).toBe("myshopify.com");
    expect(row.privateDomain).toBe("tenant.myshopify.com");
    expect(row.isIcann).toBe(false);
  });

  it("an ordinary ICANN host is identical in both views", () => {
    const row = rowFor("www.example.com");
    expect(row.icannDomain).toBe("example.com");
    expect(row.privateDomain).toBe("example.com");
    expect(row.isIcann).toBe(true);
  });

  it("records normalization for IDN hosts", () => {
    const row = rowFor("xn--fa-hia.de");
    expect(row.unicode).toBe("faß.de");
    expect(row.asciiN).toBe("xn--fa-hia.de");
  });
});
