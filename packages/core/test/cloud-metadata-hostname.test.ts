import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { analyzeIpv4, analyzeIpv6 } from "../src/parse/ip.js";
import {
  CLOUD_METADATA_ENDPOINTS,
  CLOUD_METADATA_HOSTNAMES,
  matchCloudMetadataHostname,
} from "../src/data/cloud-metadata.js";
import { classifyHost } from "../src/detectors/ip-classification.js";

/**
 * Cloud metadata endpoints named by HOSTNAME rather than by address
 * (LINK-hvawpgos).
 *
 * The gap this closes, as it was measured before the change:
 *
 *   http://169.254.169.254/latest/meta-data/         0.75 high / 1.00 critical
 *   http://metadata.google.internal/…/default/token  0.00 info / 0.00 info
 *
 * Same endpoint, same credentials, same theft — and the silent spelling is the
 * one Google's own documentation recommends over the address. The first
 * describe below was committed asserting the silence, then flipped; the address
 * assertions are the control and did not move in either commit.
 *
 * Everything here is one of three things: the positives, the FALSE positives,
 * and the table discipline that keeps the second set empty. The third is not
 * decoration. A metadata hostname table is one careless `endsWith` away from
 * being a blocklist that puts a `high` verdict on somebody's internal host,
 * which is why the matcher is tested against suffix, prefix, and substring
 * attacks rather than only against the names it is supposed to know.
 */

const HOSTNAME_URLS = [
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  "http://metadata.goog/computeMetadata/v1/instance/service-accounts/default/token",
  "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
  "http://metadata.exoscale.com/latest/meta-data",
];

/**
 * Hostnames that must stay silent whatever happens above. Each is a near-miss
 * of a real entry: an RFC 6761 special-use name that is not a metadata endpoint
 * (`svc.internal`, LINK-mgnbgicq's own example), the metadata label in a
 * subdomain, the same label under someone's own registrable domain, and a
 * documented label as a substring of a longer one. A merely internal-LOOKING
 * hostname is not a metadata endpoint.
 */
const BENIGN_URLS = [
  "http://svc.internal/",
  "http://foo.metadata.example.com/",
  "http://metadata.mycorp.com/",
  "http://my-instance-data.example.org/",
];

const codesOf = (url: string, agentMode = false): string[] =>
  inspect(url, agentMode ? { agentMode: true } : undefined).reasons.map((r) => r.code);

describe("cloud metadata hostnames score exactly as their addresses do", () => {
  // Spelled out rather than generated, so a row quietly leaving the table fails
  // a named test instead of shortening a loop.
  for (const url of HOSTNAME_URLS) {
    it(`lands high with ip_cloud_metadata in default mode: ${url}`, () => {
      const r = inspect(url);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0.75);
      expect(r.severity).toBe("high");
      expect(r.reasons.map((x) => x.code)).toContain("ip_cloud_metadata");
      // Agent-gated, so a default caller (a log scanner, cloud-ops tooling)
      // keeps the overridable `high` verdict rather than a hard block.
      expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
    });

    it(`blocks as critical under agentMode: ${url}`, () => {
      const r = inspect(url, { agentMode: true });
      expect(r.score).toBe(1);
      expect(r.severity).toBe("critical");
      expect(r.reasons.map((x) => x.code)).toEqual(
        expect.arrayContaining(["ip_cloud_metadata", "ssrf_cloud_metadata"]),
      );
    });
  }

  // Data-driven backstop: the named cases above are the ones a reader checks,
  // this one holds for whatever the table contains, so a new row cannot land
  // untested. `>=` rather than `=` because an unrelated detector may legitimately
  // stack on a particular host — see the IBM case below.
  it("every row in the table scores, in both modes", () => {
    expect(CLOUD_METADATA_HOSTNAMES.length).toBeGreaterThan(0);
    for (const row of CLOUD_METADATA_HOSTNAMES) {
      const url = `http://${row.hostname}/`;
      expect(inspect(url).score ?? 0, url).toBeGreaterThanOrEqual(0.75);
      expect(codesOf(url), url).toContain("ip_cloud_metadata");
      expect(inspect(url, { agentMode: true }).severity, url).toBe("critical");
      expect(codesOf(url, true), url).toContain("ssrf_cloud_metadata");
    }
  });

  // Recorded rather than tuned. `api.metadata.cloud.ibm.com` used to score 0.50
  // BEFORE this slice existed, because `embedded_domain_in_subdomain` read
  // `metadata.cloud` as a domain embedded under `ibm.com`, and the true positive
  // stacked on top to 0.875 / critical — louder than the 0.75 / high the address
  // form gets. LINK-hvawpgos declined to correct that asymmetry, on the grounds
  // that suppressing a pre-existing reason to protect a symmetry would be tuning
  // the score to match the prose.
  //
  // LINK-vuqdzmzy removed it from the other end, and the distinction matters:
  // `.cloud` is a 2012-round gTLD, and a window under an expansion-era suffix is
  // measured as evidence of BENIGNITY, so the 0.50 was withdrawn on its own
  // evidence rather than to make this number tidy. The symmetry with the address
  // form is a side effect. The pin moves to the new value so the composite stays
  // a decision someone made rather than a number that drifted.
  it("the IBM host scores exactly as its address form does", () => {
    const r = inspect("http://api.metadata.cloud.ibm.com/metadata/v1/instance/");
    expect(r.score).toBe(0.75);
    expect(r.reasons.map((x) => x.code)).toEqual(["ip_cloud_metadata"]);
  });

  // Case folding: the authority is case-insensitive and a URL may be written in
  // any of them.
  it("matches regardless of case", () => {
    expect(codesOf("http://METADATA.GOOGLE.INTERNAL/x")).toContain("ip_cloud_metadata");
    expect(codesOf("http://MeTaDaTa.GoOg/x")).toContain("ip_cloud_metadata");
  });

  // The trailing root dot resolves identically and is the documented Smokescreen
  // allow-list bypass (see fqdn-root-label.ts). A matcher that missed it would
  // ship the bypass alongside the check.
  it("matches through a trailing root label, and still reports it", () => {
    const codes = codesOf("http://metadata.google.internal./computeMetadata/v1/");
    expect(codes).toContain("ip_cloud_metadata");
    expect(codes).toContain("fqdn_root_label");
  });
});

describe("cloud metadata by ADDRESS — the control, must not move", () => {
  it("169.254.169.254 lands high with ip_cloud_metadata in default mode", () => {
    const r = inspect("http://169.254.169.254/latest/meta-data/");
    expect(r.score).toBe(0.75);
    expect(r.severity).toBe("high");
    expect(r.reasons.map((x) => x.code)).toContain("ip_cloud_metadata");
    expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
  });

  it("169.254.169.254 blocks as critical under agentMode", () => {
    const r = inspect("http://169.254.169.254/latest/meta-data/", { agentMode: true });
    expect(r.score).toBe(1);
    expect(r.severity).toBe("critical");
    expect(r.reasons.map((x) => x.code)).toEqual(
      expect.arrayContaining(["ip_cloud_metadata", "ssrf_cloud_metadata"]),
    );
  });

  it("the detail names the provider, not a bare bucket", () => {
    const r = inspect("http://169.254.169.254/");
    const reason = r.reasons.find((x) => x.code === "ip_cloud_metadata");
    expect(reason?.detail).toContain("AWS / Azure / GCP / DigitalOcean / OpenStack");
  });

  // An address in the URL really does resolve to the endpoint; a NAME does not,
  // and the wording below is what keeps the two apart.
  it("an address still reads 'resolves to'", () => {
    const reason = inspect("http://169.254.169.254/").reasons.find(
      (x) => x.code === "ip_cloud_metadata",
    );
    expect(reason?.detail).toContain("resolves to");
  });
});

describe("internal-LOOKING hostnames stay silent", () => {
  for (const url of BENIGN_URLS) {
    it(`is benign in default mode: ${url}`, () => {
      const r = inspect(url);
      expect(r.status).toBe("ok");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
    });

    it(`is benign in agent mode: ${url}`, () => {
      const r = inspect(url, { agentMode: true });
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
      expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
      expect(r.reasons.map((x) => x.code)).not.toContain("ip_cloud_metadata");
    });
  }

  // The three shapes a lazier matcher would have got wrong, stated as attacks
  // rather than as trivia: each is a live way to make a check fire on a host
  // its vendor never published.
  it("a documented name as a SUFFIX of an attacker domain is not a metadata endpoint", () => {
    const codes = codesOf("http://metadata.google.internal.evil.com/", true);
    expect(codes).not.toContain("ip_cloud_metadata");
    expect(codes).not.toContain("ssrf_cloud_metadata");
    // It used to be caught by `embedded_domain_in_subdomain` at 0.50, for what
    // it actually is. It is not any more: the sole window here is
    // `metadata.google`, `.google` is a 2012-round brand gTLD, and LINK-vuqdzmzy
    // stopped scoring that class on measured evidence. This is the accepted
    // recall cost landing on a named host, so it is asserted rather than left to
    // be discovered — the claim THIS test makes (not a metadata endpoint) is
    // unaffected either way.
    expect(codes).toEqual([]);
  });

  it("a documented name with a PREFIX glued on is not a metadata endpoint", () => {
    for (const host of ["xmetadata.goog", "notmetadata.google.internal"]) {
      expect(codesOf(`http://${host}/`, true), host).not.toContain("ip_cloud_metadata");
    }
  });

  it("the private namespaces the names live in are not covered", () => {
    // Ordinary vendor-issued instance names. Covering `*.internal` or
    // `*.ec2.internal` would flag every GCE and EC2 host in an internal log.
    for (const host of [
      "ip-10-251-50-12.ec2.internal",
      "my-vm.c.my-project.internal",
      "instance-1.europe-west1-b.c.example.internal",
    ]) {
      expect(codesOf(`http://${host}/`, true), host).not.toContain("ip_cloud_metadata");
    }
  });
});

describe("the emitted detail asserts a citation, not a DNS lookup", () => {
  const detail = (url: string): string =>
    inspect(url).reasons.find((r) => r.code === "ip_cloud_metadata")?.detail ?? "";

  it("names the address as the vendor's documented name, not as a resolution", () => {
    const d = detail("http://metadata.google.internal/computeMetadata/v1/");
    expect(d).toContain("the vendor-documented name for 169.254.169.254");
    // `inspect()` is zero-network. A detail that said "resolves to" would be
    // asserting a DNS outcome this library never observed — and would be wrong
    // on any host whose resolver says otherwise.
    expect(d).not.toContain("resolves to");
  });

  it("names the provider whose credentials are at stake", () => {
    expect(detail("http://metadata.google.internal/")).toContain("GCP");
    expect(detail("http://metadata.tencentyun.com/")).toContain("Tencent Cloud");
  });

  it("the agentMode detail describes the same endpoint the classifier does", () => {
    const r = inspect("http://metadata.tencentyun.com/", { agentMode: true });
    const ssrf = r.reasons.find((x) => x.code === "ssrf_cloud_metadata")?.detail ?? "";
    expect(ssrf).toContain("Tencent Cloud instance-metadata endpoint");
    expect(ssrf).toContain("169.254.0.23");
    expect(ssrf).toContain("blocked");
  });
});

describe("the matcher is whole-host equality and nothing looser", () => {
  it("matches the exact host", () => {
    expect(matchCloudMetadataHostname("metadata.google.internal")?.provider).toBe("GCP");
  });

  it("folds case and one trailing root dot", () => {
    expect(matchCloudMetadataHostname("METADATA.GOOG")?.hostname).toBe("metadata.goog");
    expect(matchCloudMetadataHostname("metadata.goog.")?.hostname).toBe("metadata.goog");
  });

  it("refuses suffix, prefix, substring, and the empty host", () => {
    for (const host of [
      "metadata.google.internal.evil.com",
      "evil.metadata.google.internal",
      "xmetadata.goog",
      "metadata.goo",
      "my-instance-data.example.org",
      "metadata",
      "",
    ]) {
      expect(matchCloudMetadataHostname(host), host).toBeUndefined();
    }
  });

  // Two or more trailing dots create an empty label and fail parsing as
  // `invalid` long before a detector runs, so this only records that the
  // matcher does not paper over them.
  it("does not strip a second trailing dot", () => {
    expect(matchCloudMetadataHostname("metadata.goog..")).toBeUndefined();
  });
});

describe("table integrity — the discipline that keeps this out of blocklist territory", () => {
  it("every hostname is stored lowercase, bare, and host-shaped", () => {
    for (const row of CLOUD_METADATA_HOSTNAMES) {
      expect(row.hostname, row.hostname).toBe(row.hostname.toLowerCase());
      expect(row.hostname.endsWith("."), row.hostname).toBe(false);
      const label = "[a-z0-9]([a-z0-9-]*[a-z0-9])?";
      expect(row.hostname, row.hostname).toMatch(new RegExp(`^${label}(\\.${label})*$`));
    }
  });

  it("no hostname is an IP literal — those belong in the address table", () => {
    for (const row of CLOUD_METADATA_HOSTNAMES) {
      expect(analyzeIpv4(row.hostname) ?? analyzeIpv6(row.hostname), row.hostname).toBe(null);
    }
  });

  it("hostnames are unique", () => {
    const names = CLOUD_METADATA_HOSTNAMES.map((r) => r.hostname);
    expect(new Set(names).size).toBe(names.length);
  });

  // THE invariant behind "the table supplies only the NAME" (architecture §1.1).
  // A row may only name an endpoint this file already classifies by address; the
  // moment one could point anywhere, the table would be creating findings of its
  // own rather than spelling existing ones differently.
  it("every hostname names an endpoint the address table already carries", () => {
    const addresses = new Set(CLOUD_METADATA_ENDPOINTS.map((e) => e.address));
    for (const row of CLOUD_METADATA_HOSTNAMES) {
      expect(addresses.has(row.address), `${row.hostname} → ${row.address}`).toBe(true);
    }
  });

  // Sourcing is an acceptance criterion, not a courtesy: an unsourced row is a
  // `high` verdict on a name nobody published.
  it("every row cites vendor documentation", () => {
    for (const row of CLOUD_METADATA_HOSTNAMES) {
      expect(row.source, row.hostname).toMatch(/^https:\/\//);
      expect(row.provider.length, row.hostname).toBeGreaterThan(0);
    }
  });

  // classifyHost is public API and @linklint/online calls it on a RESOLVED
  // address to decide whether a connection may proceed. The name lookup lives in
  // the detector bodies precisely so that contract does not change under a
  // caller outside this package.
  it("classifyHost stays IP-only", () => {
    for (const row of CLOUD_METADATA_HOSTNAMES) {
      expect(classifyHost(row.hostname), row.hostname).toBeNull();
    }
    expect(classifyHost("169.254.169.254")?.bucket).toBe("ip_cloud_metadata");
  });
});

describe("docs/reason-codes.md reproduces the hostname table", () => {
  const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const doc = readFileSync(join(REPO_ROOT, "docs", "reason-codes.md"), "utf8");

  // Same reasoning as the address-table check in docs-validation.test.ts: a
  // reader treats the documented list as the answer to "is my provider
  // covered?", and nothing but a test couples it to the code. Three columns, not
  // two — the address-table check greps every 2-column row after the
  // `ip_cloud_metadata` heading, so a second 2-column table there would break it.
  it("lists exactly the rows in CLOUD_METADATA_HOSTNAMES, in order", () => {
    // Bounded at the next h3 (LINK-tviundio) for the reason the comment above
    // predicted: an unbounded slice makes this grep a claim about every later
    // section of the document as well as this one.
    const start = doc.search(/^### `ip_cloud_metadata`/m);
    const ends = [doc.indexOf("\n### ", start + 1), doc.indexOf("\n## ", start + 1)].filter(
      (i) => i !== -1,
    );
    const section = doc.slice(start, ends.length === 0 ? undefined : Math.min(...ends));
    const rows = [
      ...section.matchAll(/^\s*\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|\s*$/gm),
    ].map((m) => ({ hostname: m[1] as string, provider: m[2] as string, address: m[3] as string }));

    expect(rows.map((r) => r.hostname)).toEqual(CLOUD_METADATA_HOSTNAMES.map((r) => r.hostname));
    expect(rows.map((r) => r.address)).toEqual(CLOUD_METADATA_HOSTNAMES.map((r) => r.address));
    for (const [i, row] of rows.entries()) {
      // The doc's provider cell is prose that starts with the code's attribution.
      expect(row.provider.startsWith(CLOUD_METADATA_HOSTNAMES[i]!.provider)).toBe(true);
    }
  });
});
