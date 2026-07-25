/**
 * Curated cloud instance-metadata endpoint table (LINK-yyqnmipb).
 *
 * The link-local metadata endpoint is THE canonical SSRF credential-theft
 * target, but it is not one address: the industry converged on
 * `169.254.169.254` for most providers while several large clouds ship their
 * own well-known address (Oracle's `192.0.0.192`, Alibaba's
 * `100.100.100.200`), and AWS additionally serves the IMDS over IPv6 at
 * `fd00:ec2::254`. Hardcoding a single constant left three of those scoring as
 * "reserved" or as an ordinary public IP.
 *
 * PROVENANCE. This table is NOT IANA-derived — IANA's special-purpose registries
 * describe *ranges* (169.254.0.0/16 link-local, 100.64.0.0/10 CGNAT), not which
 * single address inside them a given cloud vendor answers metadata on. Every row
 * here is sourced from the vendor's own documentation and the entries carry
 * their own version stamp, {@link CLOUD_METADATA_VERSION} (surfaced as
 * `dataVersions.cloudMetadata`), deliberately separate from any IANA registry
 * stamp so the two can be refreshed and audited independently.
 *
 * CANONICAL COMPARISON. Addresses below are matched on their PARSED value, never
 * as text: consumers run each `address` through the same IPv4/IPv6 parser used
 * on the host under inspection and compare the decoded bits (see
 * `detectors/ip-classification.ts`). Text matching is a documented production
 * bug class — a prefix test on the string `fd00:ec2:` blocks `fd00:ec2::254`
 * while letting `fd00:0ec2::254` through, though both spell the same 128 bits.
 * Writing a row in any legal spelling is therefore safe.
 *
 * ORDERING. Every address here sits inside a broader special-use range
 * (`169.254.169.254` inside link-local, `100.100.100.200` inside CGNAT), so the
 * table must be consulted BEFORE the range buckets for most-specific-wins to
 * hold.
 */

/**
 * Version stamp for this curated table, surfaced as
 * `dataVersions.cloudMetadata`. Bump deliberately whenever a row is added,
 * removed, or re-attributed.
 */
export const CLOUD_METADATA_VERSION = "2026-07-25-providers";

/** One cloud vendor's well-known instance-metadata endpoint. */
export interface CloudMetadataEndpoint {
  /**
   * The endpoint address. Any legal IPv4/IPv6 spelling is accepted — consumers
   * canonicalize it through the shared parser before comparing.
   */
  address: string;
  /**
   * Provider attribution, rendered verbatim into the emitted reason detail.
   * `169.254.169.254` is shared by many clouds, so its attribution names them
   * together rather than guessing one.
   */
  provider: string;
  /** Vendor documentation the row was verified against (auditability). */
  source: string;
}

/**
 * The endpoints linklint recognizes as `ip_cloud_metadata`. Deliberately small
 * and vendor-documented: a false positive here costs a `high` verdict on an
 * ordinary address, so speculative entries are kept out.
 */
export const CLOUD_METADATA_ENDPOINTS: readonly CloudMetadataEndpoint[] = [
  {
    // The de-facto shared endpoint. AWS EC2 IMDS, Azure IMDS, GCP (also reached
    // via metadata.google.internal), DigitalOcean, and OpenStack — on which
    // several of the others are modeled — all answer here.
    address: "169.254.169.254",
    provider: "AWS / Azure / GCP / DigitalOcean / OpenStack",
    source: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
  },
  {
    // AWS IMDS over IPv6 (Nitro instances in an IPv6-enabled subnet). Same
    // service, different family — a validator that only knows the v4 address is
    // bypassed by the v6 spelling.
    address: "fd00:ec2::254",
    provider: "AWS (IPv6 IMDS)",
    source:
      "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
  },
  {
    // Oracle Cloud Infrastructure's own endpoint, outside the link-local range
    // entirely — it looks like an ordinary public address to a range-only check.
    address: "192.0.0.192",
    provider: "Oracle Cloud",
    source: "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm",
  },
  {
    // Alibaba Cloud ECS. Sits inside 100.64.0.0/10 (CGNAT), so a range-only
    // check classifies it as merely "reserved".
    address: "100.100.100.200",
    provider: "Alibaba Cloud",
    source: "https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/",
  },
];
