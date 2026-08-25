import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-mgnbgicq — PIN COMMIT. This file is written BEFORE the code it is about,
// and every assertion below states the behaviour as it ships TODAY: the RFC 6761
// special-use name set is entirely silent. `https://foo.invalid/` returns
// `0.00`/`info` with an EMPTY reason list, in host position and as a suffix, in
// plain mode and under `agentMode`.
//
// The point of pinning the silence first is that the next commit has to argue
// with a written-down fact rather than with a memory. Architecture §1.1's fourth
// rule says a `0.00` with no reasons asserts "there is nothing to say about this
// URL", and that assertion is false for a name RFC 6761 guarantees will never
// work. These assertions are the "before" half of that argument; the commit that
// adds `special_use_name` CONVERTS them rather than deleting them, so the
// conversion is visible in one diff.
//
// The third block is different in kind: it pins behaviour that must NOT move.
// `metadata.google.internal` already carries a verdict (`ip_cloud_metadata` at
// 0.75, `ssrf_cloud_metadata` at 1.00 under the gate), and the neighbouring
// benign guards from LINK-hvawpgos hold that table to whole-host equality. Those
// values are identical before and after; if any of them changes, the
// informational code has reached into a scoring one's territory.

const NAMES = [
  "localhost",
  "test",
  "invalid",
  "example",
  "local",
  "onion",
  "internal",
  "home.arpa",
  "alt",
] as const;

/** Every name in host position and as `foo.<name>` — the two shapes that matter. */
const SHAPES = NAMES.flatMap((name) => [
  [`https://${name}/`, name] as const,
  [`https://foo.${name}/`, name] as const,
]);

const MODES = [
  ["plain", undefined],
  ["agentMode", { agentMode: true }],
] as const;

describe("the RFC 6761 special-use set is silent today (LINK-mgnbgicq pin)", () => {
  for (const [modeLabel, options] of MODES) {
    it.each(SHAPES.map(([url, name]) => [url, name] as const))(
      `${modeLabel}: %s scores 0.00/info with NO reasons at all`,
      (url) => {
        const r = inspect(url, options);
        expect(r.status).toBe("ok");
        expect(r.score).toBe(0);
        expect(r.severity).toBe("info");
        // The assertion the fourth rule objects to. It is TRUE as of this commit.
        expect(r.reasons.map((x) => x.code)).toEqual([]);
      },
    );
  }

  it("the whole set really is reachable as a public suffix — the pin is not vacuous", () => {
    // If tldts ever stopped treating these as suffixes the block above would
    // still pass while covering nothing, because a non-suffix name is silent too.
    for (const name of NAMES) {
      expect(inspect(`https://foo.${name}/`).parsed?.publicSuffix).toBe(name);
    }
  });
});

describe("the RFC 6761 EXAMPLE DOMAINS are a different reservation (LINK-mgnbgicq pin)", () => {
  // RFC 6761 §6.5 reserves `.example` AND `example.com` / `.net` / `.org` in the
  // same section, but the two halves are not the same fact. `.example` is a TLD
  // that was never delegated. `example.com` is a SECOND-LEVEL reservation under
  // `com`, which is delegated and which resolves — IANA operates the site. The
  // measurable difference is the public suffix, pinned here, and it is what a
  // suffix-scoped check keys on.
  it.each(["example.com", "example.net", "example.org"])(
    "%s has a DELEGATED public suffix and is not a special-use TLD",
    (host) => {
      const r = inspect(`https://${host}/`);
      expect(r.parsed?.publicSuffix).toBe(host.split(".")[1]);
      expect(r.parsed?.registrableDomain).toBe(host);
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).toEqual([]);
    },
  );
});

describe("the cloud-metadata verdict must not move (LINK-hvawpgos invariant)", () => {
  const GCP = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

  it("plain mode: metadata.google.internal scores 0.75/high on ip_cloud_metadata", () => {
    const r = inspect(GCP);
    expect(r.score).toBe(0.75);
    expect(r.severity).toBe("high");
    expect(r.reasons.map((x) => x.code)).toContain("ip_cloud_metadata");
  });

  it("agentMode: it stacks to 1.00/critical with ssrf_cloud_metadata", () => {
    const r = inspect(GCP, { agentMode: true });
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("ip_cloud_metadata");
    expect(codes).toContain("ssrf_cloud_metadata");
  });

  it.each([
    "http://metadata.google.internal.evil.com/",
    "http://svc.internal/",
    "http://foo.metadata.example.com/",
    "http://metadata.mycorp.com/",
    "http://my-instance-data.example.org/",
  ])("%s is not a metadata endpoint, in either mode", (url) => {
    for (const options of [undefined, { agentMode: true }]) {
      const codes = inspect(url, options).reasons.map((x) => x.code);
      expect(codes).not.toContain("ip_cloud_metadata");
      expect(codes).not.toContain("ssrf_cloud_metadata");
    }
  });

  it("svc.internal — LINK-hvawpgos's own independence example — scores 0.00 in both modes", () => {
    for (const options of [undefined, { agentMode: true }]) {
      const r = inspect("http://svc.internal/", options);
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
    }
  });
});
