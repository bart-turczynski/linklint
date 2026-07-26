import { describe, expect, it } from "vitest";
import { inspect, inspectAsync } from "../src/index.js";
import type {
  Enricher,
  EnricherFinding,
  EnrichmentContext,
  EnrichmentLayer,
  InspectResult,
} from "../src/schema/types.js";
import type { InspectAsyncOptions } from "../src/inspect-async.js";

/**
 * Contract tests for the caller false-positive escape hatch
 * (`InspectOptions.suppressReasons`, LINK-qowyxkem / architecture §9).
 *
 * A suppression rule says "this reason is a false positive — mark it fine":
 * the matched reason STAYS in `reasons[]` (annotated `suppressed: true`) but its
 * scoring weight is zeroed so `score`/`severity` drop as if the signal were
 * absent. It generalizes the single-heuristic `idnPolicy`/`idnAllowlist` opt-out
 * to EVERY reason code, and works identically for enricher-layer reasons.
 */

const IDN = "https://münchen.de"; // single scoring reason: idn_host (0.7 → high)
const codesOf = (r: InspectResult) => r.reasons.map((x) => x.code);
const reason = (r: InspectResult, code: string) => r.reasons.find((x) => x.code === code);

describe("suppressReasons — global (no host) suppression", () => {
  it("marks the reason suppressed, zeroes its weight, and lowers severity", () => {
    const base = inspect(IDN);
    expect(base.severity).toBe("high");
    expect(reason(base, "idn_host")?.weight).toBeCloseTo(0.7, 5);

    const r = inspect(IDN, { suppressReasons: [{ code: "idn_host" }] });
    const idn = reason(r, "idn_host");
    // The reason is NOT deleted — linklint is never silently clean.
    expect(codesOf(r)).toContain("idn_host");
    expect(idn?.suppressed).toBe(true);
    expect(idn?.weight).toBe(0);
    // Score drops as if the signal were absent.
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("leaves other reasons untouched", () => {
    // A URL with two scoring reasons: userinfo_present (0.5) + idn_host (0.7).
    const url = "https://paypal.com@münchen.de/";
    const base = inspect(url);
    expect(codesOf(base)).toEqual(expect.arrayContaining(["userinfo_present", "idn_host"]));

    const r = inspect(url, { suppressReasons: [{ code: "idn_host" }] });
    expect(reason(r, "idn_host")?.suppressed).toBe(true);
    // userinfo_present is untouched: still weighted, no suppressed marker.
    const userinfo = reason(r, "userinfo_present");
    expect(userinfo?.suppressed).toBeUndefined();
    expect(userinfo?.weight).toBeCloseTo(0.5, 5);
    // Score reflects only the surviving signal.
    expect(r.score).toBeCloseTo(0.5, 5);
  });
});

describe("suppressReasons — host-scoped suppression", () => {
  it("applies only to the matching registrable domain", () => {
    const rule = { code: "idn_host", host: "münchen.de" } as const;

    const match = inspect(IDN, { suppressReasons: [rule] });
    expect(reason(match, "idn_host")?.suppressed).toBe(true);
    expect(match.severity).toBe("info");

    // A different IDN registrable domain is NOT suppressed by the scoped rule.
    const other = inspect("https://köln.de", { suppressReasons: [rule] });
    expect(reason(other, "idn_host")?.suppressed).toBeUndefined();
    expect(other.severity).toBe("high");
  });

  it("covers subdomains of the listed registrable domain", () => {
    const r = inspect("https://shop.münchen.de", {
      suppressReasons: [{ code: "idn_host", host: "münchen.de" }],
    });
    expect(reason(r, "idn_host")?.suppressed).toBe(true);
    expect(r.severity).toBe("info");
  });

  it("matches across Unicode and punycode presentations (like idnAllowlist)", () => {
    // Unicode rule host exempts a punycode input …
    const a = inspect("https://xn--mnchen-3ya.de/", {
      suppressReasons: [{ code: "idn_host", host: "münchen.de" }],
    });
    expect(reason(a, "idn_host")?.suppressed).toBe(true);
    // … and a punycode rule host exempts a Unicode input.
    const b = inspect(IDN, {
      suppressReasons: [{ code: "idn_host", host: "xn--mnchen-3ya.de" }],
    });
    expect(reason(b, "idn_host")?.suppressed).toBe(true);
  });
});

describe("suppressReasons — suppressing every scoring reason drives score→0 / info", () => {
  it("zeroes a multi-signal verdict", () => {
    const url = "https://paypal.com@xn--pypal-4ve.ru/login";
    const base = inspect(url);
    expect(base.score).toBeGreaterThan(0);
    const scoringCodes = base.reasons.filter((x) => x.weight > 0).map((x) => x.code);
    expect(scoringCodes.length).toBeGreaterThan(1);

    const r = inspect(url, {
      suppressReasons: scoringCodes.map((code) => ({ code: code as never })),
    });
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    // Every scoring reason is still present, annotated suppressed.
    for (const code of scoringCodes) {
      expect(reason(r, code)?.suppressed).toBe(true);
    }
  });
});

describe("suppressReasons — checksRun marker honesty", () => {
  it("adds the suppression token only when the option is configured", () => {
    expect(inspect(IDN).checksRun).not.toContain("suppression");
    // Present even when it is an empty array (configured, suppresses nothing).
    expect(inspect(IDN, { suppressReasons: [] }).checksRun).toContain("suppression");
    expect(inspect(IDN, { suppressReasons: [] }).reasons.some((x) => x.suppressed)).toBe(false);
    // And when it actually matches.
    expect(inspect(IDN, { suppressReasons: [{ code: "idn_host" }] }).checksRun).toContain(
      "suppression",
    );
  });

  it("keeps the deterministic channel order lexical → policy → agent → suppression", () => {
    const r = inspect("https://köln.de", {
      denyTlds: ["de"],
      agentMode: true,
      suppressReasons: [{ code: "idn_host" }],
    });
    expect(r.checksRun).toEqual(["lexical", "policy", "agent", "suppression"]);
  });
});

describe("suppressReasons — DEFAULT-OFF invariant (byte-for-byte unchanged)", () => {
  const urls = [
    "https://www.example.com/",
    IDN,
    "https://paypal.com@xn--pypal-4ve.ru/login",
    "javascript:alert(1)",
    "ht!tp://%%%not a url",
  ];

  it.each(urls)("inspect(%s) with no option deep-equals the pre-change output", (url) => {
    const r = inspect(url);
    // No suppression field anywhere; schema version unchanged.
    expect(r.reasons.every((x) => !("suppressed" in x))).toBe(true);
    expect(r.checksRun).not.toContain("suppression");
    expect(r.schemaVersion).toBe("1.6");
  });

  it.each(urls)("inspectAsync(%s) (no enrichers, no option) deep-equals inspect(%s)", async (url) => {
    expect(await inspectAsync(url)).toEqual(inspect(url));
  });
});

/** A no-network enricher returning a fixed scoring finding (a plausible L2 hit). */
class FixedEnricher implements Enricher {
  constructor(
    readonly id: string,
    readonly layer: EnrichmentLayer,
    private readonly findings: EnricherFinding[],
  ) {}
  async enrich(_r: InspectResult, _ctx: EnrichmentContext): Promise<EnricherFinding[]> {
    return this.findings;
  }
}

describe("suppressReasons — enricher-emitted reasons are equally suppressible", () => {
  const enricher = new FixedEnricher("dns", "resolution", [
    { code: "ip_private", detail: "resolved host maps to a private/internal IP" },
  ]);

  it("suppresses an enricher reason by the same mechanism", async () => {
    const base = await inspectAsync("https://www.example.com/", { enrichers: [enricher] });
    expect(reason(base, "ip_private")?.weight).toBeCloseTo(0.2, 5);
    expect(base.score).toBeCloseTo(0.2, 5);

    const r = await inspectAsync("https://www.example.com/", {
      enrichers: [enricher],
      suppressReasons: [{ code: "ip_private" }],
    });
    const ip = reason(r, "ip_private");
    expect(ip?.suppressed).toBe(true);
    expect(ip?.weight).toBe(0);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    // The escape-hatch marker rides through from the sync base.
    expect(r.checksRun).toContain("suppression");
    // The enricher still counts as run.
    expect(r.checksRun).toContain("resolution:dns");
  });

  it("host-scoped rule targets an enricher reason on the matching domain only", async () => {
    const opts: InspectAsyncOptions = {
      enrichers: [enricher],
      suppressReasons: [{ code: "ip_private", host: "example.com" }],
    };
    const match = await inspectAsync("https://www.example.com/", opts);
    expect(reason(match, "ip_private")?.suppressed).toBe(true);

    const other = await inspectAsync("https://www.example.org/", opts);
    expect(reason(other, "ip_private")?.suppressed).toBeUndefined();
    expect(other.score).toBeCloseTo(0.2, 5);
  });
});
