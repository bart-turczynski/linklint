import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { classifyHost, classifyMetadataHostname } from "../src/detectors/ip-classification.js";
import {
  CLOUD_METADATA_ENDPOINTS,
  CLOUD_METADATA_HOSTNAMES,
} from "../src/data/cloud-metadata.js";

/**
 * GCP's IPv6 metadata endpoint, `fd20:ce::254` (LINK-eyjfhbzu).
 *
 * THE SHAPE OF THE GAP, as measured before the change:
 *
 *   http://169.254.169.254/computeMetadata/v1/      0.75 high     / 1.00 critical
 *   http://metadata.google.internal/…               0.75 high     / 1.00 critical
 *   http://[fd20:ce::254]/computeMetadata/v1/       0.20 low      / 0.20 low
 *
 * One deployment shape — a GCP instance configured IPv6-only — is the single
 * case where the credential endpoint is under-scored, and it is under-scored
 * because `fd20:ce::254` falls inside `fc00::/7` and picks up the generic
 * `ip_private` bucket on the way past. Google documents all three spellings on
 * ONE page, side by side, as endpoints of the same metadata server:
 * https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
 * lists "http://metadata.google.internal/computeMetadata/v1" (recommended),
 * "http://169.254.169.254/computeMetadata/v1", and
 * "http://fd20:ce::254/computeMetadata/v1" (for IPv6-only instances).
 *
 * The first describe below was committed asserting the UNDER-SCORING, then
 * flipped. The second and third describes are the control: they were written in
 * the same commit and did not move in either one. A fix that raised the v6
 * address by loosening the table — a prefix test on `fd20:ce`, say — would show
 * up in the benign guard, not in the positives.
 */

const V6 = "http://[fd20:ce::254]/computeMetadata/v1/instance/service-accounts/default/token";
const V4 = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";
const NAME =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

const codesOf = (url: string, agentMode = false): string[] =>
  inspect(url, agentMode ? { agentMode: true } : undefined).reasons.map((r) => r.code);
const scoreOf = (url: string, agentMode = false): number =>
  inspect(url, agentMode ? { agentMode: true } : undefined).score;

describe("the GCP IPv6 metadata endpoint is under-scored (LINK-eyjfhbzu, PINNED)", () => {
  it("fd20:ce::254 lands in the generic ULA bucket, not the metadata bucket", () => {
    expect(codesOf(V6)).toEqual(["ip_private"]);
    expect(scoreOf(V6)).toBeCloseTo(0.2, 5);
    expect(inspect(V6).severity).toBe("low");
  });

  it("classifyHost calls it ip_private, with an IANA range citation", () => {
    const c = classifyHost("fd20:ce::254");
    expect(c?.bucket).toBe("ip_private");
    expect(c?.rangeName).toBe("Unique-Local");
    expect(c?.provider).toBeUndefined();
  });

  // The escalation is not reachable independently: `ssrf_cloud_metadata` asks
  // `classifyHost` for the `ip_cloud_metadata` bucket, so an address that never
  // reaches that bucket cannot reach the blocker either. The under-scoring is
  // therefore two findings deep — 0.20 instead of 0.75 always-on, and no
  // agent-mode block at all.
  it("agentMode adds nothing — the blocker rides on the bucket it never gets", () => {
    expect(codesOf(V6, true)).toEqual(["ip_private"]);
    expect(scoreOf(V6, true)).toBeCloseTo(0.2, 5);
  });

  it("the address is absent from the endpoint table", () => {
    expect(CLOUD_METADATA_ENDPOINTS.map((e) => e.address)).not.toContain("fd20:ce::254");
  });
});

describe("the spellings that already score, and must not move (LINK-eyjfhbzu control)", () => {
  it("the IPv4 address is ip_cloud_metadata at 0.75, escalating to 1.00", () => {
    expect(codesOf(V4)).toEqual(["ip_cloud_metadata"]);
    expect(scoreOf(V4)).toBeCloseTo(0.75, 5);
    expect(codesOf(V4, true).sort()).toEqual(["ip_cloud_metadata", "ssrf_cloud_metadata"]);
    expect(scoreOf(V4, true)).toBeCloseTo(1, 5);
  });

  it("the documented hostname is ip_cloud_metadata at 0.75, escalating to 1.00", () => {
    expect(codesOf(NAME)).toEqual(["ip_cloud_metadata"]);
    expect(scoreOf(NAME)).toBeCloseTo(0.75, 5);
    expect(codesOf(NAME, true).sort()).toEqual(["ip_cloud_metadata", "ssrf_cloud_metadata"]);
    expect(scoreOf(NAME, true)).toBeCloseTo(1, 5);
  });

  // The hostname rows carry an `address` tie, and the emitted detail quotes it.
  // Adding a SECOND GCP address to the endpoint table widens the set of
  // addresses a GCP name could legally point at, so the tie is pinned to the
  // specific row here rather than left to the table-membership check, which
  // would accept either. `metadata.google.internal` names the metadata server,
  // not one address family of it, and the address it quotes is the one nearly
  // every instance reaches it on.
  it.each(["metadata.google.internal", "metadata.goog"])(
    "%s quotes the IPv4 endpoint, and keeps quoting it",
    (hostname) => {
      const row = CLOUD_METADATA_HOSTNAMES.find((r) => r.hostname === hostname);
      expect(row?.address).toBe("169.254.169.254");
      expect(classifyMetadataHostname(hostname)?.canonical).toBe("169.254.169.254");
      expect(inspect(`http://${hostname}/`).reasons[0]?.detail).toContain("169.254.169.254");
    },
  );
});

describe("ordinary fc00::/7 addresses stay exactly where they are (benign guard)", () => {
  // A CONTROL, not proof: these are green on both sides of the change, because
  // the table is a /128 overlay keyed on the parsed address and cannot widen a
  // bucket it does not match. What the guard buys is the failure mode it would
  // catch — a fix written as a text prefix test on `fd20:ce` or as a new range
  // rule would sweep these up with it, and nothing else in the suite is looking
  // at the neighbours of a metadata endpoint.
  it.each([
    "fd20:ce::255", // one bit away in the low hextet
    "fd20:ce::1", // same /64, ordinary host
    "fd20:ce:0:0:0:0:0:253",
    "fc00::1", // the enclosing ULA block
    "fd00::254", // the ::254 host id under a different ULA prefix
  ])("%s is ip_private and nothing more", (host) => {
    const r = inspect(`http://[${host}]/`, { agentMode: true });
    expect(r.reasons.map((x) => x.code)).toContain("ip_private");
    expect(r.reasons.map((x) => x.code)).not.toContain("ip_cloud_metadata");
    expect(r.reasons.map((x) => x.code)).not.toContain("ssrf_cloud_metadata");
    expect(classifyHost(host)?.bucket).toBe("ip_private");
  });
});
