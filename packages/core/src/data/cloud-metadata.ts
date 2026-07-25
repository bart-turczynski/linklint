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
 * ORDERING. Nearly every address here sits inside a broader special-use range
 * (`169.254.169.254` inside link-local, `100.100.100.200` inside CGNAT), so the
 * table must be consulted BEFORE the range buckets for most-specific-wins to
 * hold.
 *
 * THE PUBLIC-SPACE EXCEPTION. Two rows are not carved out of any special-use
 * range: Oracle's `192.0.0.192` and Azure's `168.63.129.16`. For those the table
 * is not merely a precedence win over a coarser bucket — it is the ONLY thing
 * that produces a bucket at all, because no range rule reaches them. Dropping
 * such a row degrades silently to `info` 0.00 with zero reasons rather than
 * visibly to a weaker bucket, so they carry dedicated tests.
 *
 * HOSTNAMES ARE NOT ROWS. Several vendors document a name instead of, or as well
 * as, an address (`metadata.tencentyun.com`, `metadata.google.internal`).
 * Resolving one is a network call and `inspect()` is zero-network by contract,
 * so only numeric endpoints are listed and each row is cited to a vendor page
 * that actually writes the number down.
 */

/**
 * Version stamp for this curated table, surfaced as
 * `dataVersions.cloudMetadata`. Bump deliberately whenever a row is added,
 * removed, or re-attributed.
 */
export const CLOUD_METADATA_VERSION = "2026-07-25-second-tier";

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

  // --- Second tier (LINK-vniqhcln) ---------------------------------------
  // Held back from the initial table not because they were doubtful but because
  // that table shipped only the endpoints its own issue named. Each row below is
  // quoted from the vendor's documentation in its comment.
  {
    // Azure's WireServer / host-agent channel. NOT the Azure IMDS — that is the
    // shared 169.254.169.254 row above. This is a separate address in genuine
    // PUBLIC space that Microsoft presents as a "virtual public IP", reachable
    // only from inside a VM, and it is the reason this row matters most: every
    // other endpoint in this table sits inside a special-use range and so picks
    // up at least a link-local or private bucket, while 168.63.129.16 scored
    // `info` 0.00 with ZERO reasons before this row landed. No range rule can
    // ever reach it. Microsoft: "The virtual machine Agent requires outbound
    // communication over ports 80/tcp and 32526/tcp with WireServer
    // (168.63.129.16)." The agent fetches goal state and certificates there.
    address: "168.63.129.16",
    provider: "Azure (WireServer host channel)",
    source:
      "https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16",
  },
  {
    // AWS ECS task credentials (and task metadata v2/v3). The SDK credential
    // chain resolves AWS_CONTAINER_CREDENTIALS_RELATIVE_URI against this
    // address, so it vends task IAM role credentials directly — the same prize
    // as IMDS, at an address an IMDS-only blocklist misses. Cited to the task
    // IAM role page, which annotates the route `169.254.170.2/32 ... #
    // credentials API`, rather than the task-metadata-v2 page: AWS marks v2
    // "no longer being actively maintained", but the credentials endpoint is
    // current.
    address: "169.254.170.2",
    provider: "AWS (ECS task credentials)",
    source: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html",
  },
  {
    // AWS EKS Pod Identity Agent, which vends pod-scoped IAM credentials.
    // AWS: "the EKS Pod Identity Agent listens on an IPv4 and IPv6 address for
    // pods to request credentials. The agent uses the loopback (localhost) IP
    // address 169.254.170.23 for IPv4 and the localhost IP address
    // [fd00:ec2::23] for IPv6."
    address: "169.254.170.23",
    provider: "AWS (EKS Pod Identity)",
    source: "https://docs.aws.amazon.com/eks/latest/userguide/pod-id-agent-setup.html",
  },
  {
    // The v6 half of the pair above. Not hypothetical: AWS documents that the
    // agent listens on both by default and "can't start" if IPv6 addresses are
    // unavailable, so a v4-only table leaves the documented default half-blind.
    address: "fd00:ec2::23",
    provider: "AWS (EKS Pod Identity, IPv6)",
    source: "https://docs.aws.amazon.com/eks/latest/userguide/pod-id-agent-setup.html",
  },
  {
    // Tencent Cloud CVM. Sourcing note: Tencent's own instance-metadata guide
    // (product/213/4934) documents ONLY the hostname metadata.tencentyun.com and
    // never names an address, so it would be a bad citation for a numeric row.
    // The Cloudbase-Init page cited here is where Tencent writes the address
    // down (`metadata_base_url=http://169.254.0.23/`). The hostname itself is
    // deliberately not a row: resolving it is a network call, and `inspect()` is
    // zero-network by contract.
    address: "169.254.0.23",
    provider: "Tencent Cloud",
    source: "https://www.tencentcloud.com/document/product/213/32364",
  },
];
