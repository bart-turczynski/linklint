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
 * NOT EVERY ROW IS AN IMDS (LINK-mjbrzxeo). The table's job is "well-known
 * address a cloud answers on from inside a VM", and instance metadata is the
 * common — not the only — shape of that. Azure's `168.63.129.16` is the
 * WireServer / virtual platform channel, which Microsoft documents SEPARATELY
 * from the Azure IMDS at `169.254.169.254`; describing it as an
 * instance-metadata endpoint is simply wrong. Each row therefore declares a
 * {@link CloudMetadataEndpoint.kind}, which selects the emitted wording. It does
 * NOT select the reason code: every row here scores as `ip_cloud_metadata`
 * regardless of kind, so the taxonomy fix costs schema consumers nothing.
 *
 * HOSTNAMES: A SECOND TABLE, NOT A SECOND POLICY (LINK-hvawpgos). This file used
 * to record the decision that hostnames are deliberately not listed at all, on
 * the ground that "resolving one is a network call and `inspect()` is
 * zero-network by contract". That reason is OVERTURNED. It answers a question
 * nobody asked: recognizing `metadata.google.internal` needs no resolution. It
 * is a literal comparison against a fixed name the vendor publishes in the same
 * document as the address — the same comparison the rows below already get, one
 * string instead of thirty-two bits. A resolver would only be needed to prove
 * the name still points where the vendor says it does, and this table never
 * claimed that about the numbers either: `169.254.169.254` scores without any
 * check that something answers there. The old note's premise was sound and its
 * conclusion did not follow from it.
 *
 * What the old note protected is kept, narrowed to what it actually protects: a
 * hostname is still not a row of {@link CLOUD_METADATA_ENDPOINTS}. That table is
 * indexed through the IPv4/IPv6 parser, so a hostname row would parse as
 * neither, match nothing, and fail SILENTLY — the failure mode the
 * every-row-is-an-IP-literal test exists to prevent. Names therefore live in
 * {@link CLOUD_METADATA_HOSTNAMES}, with their own matching rule, and the
 * address table's invariant is untouched.
 *
 * WHICH SIDE OF THE NAME-NEVER-CREATE LINE THIS SITS ON (architecture §1.1). The
 * rule is that a watchlist may NAME a structural anomaly detected independently
 * and may never CREATE a finding. A hostname table looks at first glance like
 * the forbidden shape: no structural precondition fires first, and the firing
 * condition is table membership.
 *
 * The rule is written about `data/brands.ts` and claim (b), and what makes that
 * file dangerous is what its rows ASSERT — that a word is a brand worth
 * impersonating. That is a contingent fact about the world, unbounded,
 * incomplete by construction, and undecidable from the string. A row here
 * asserts something of a different kind: that a published vendor specification
 * DEFINES this name to address that vendor's credential-vending endpoint. It is
 * the same class of fact as "127.0.0.1 is loopback" or "169.254.0.0/16 is
 * link-local" — fixed by a naming authority, settleable offline, settleable for
 * all time. `data/ip-ranges.ts` is not a watchlist and neither is this: the
 * finding is created by the structural fact that the URL addresses a
 * provider-defined link-local credential endpoint, and the table supplies only
 * the spelling.
 *
 * The honest form of that argument has to concede its symmetry. If a hostname
 * row creates a finding then so does the `169.254.169.254` row, because nothing
 * about those four octets is structural either. That is the point: the address
 * table has been the shipped and accepted position since LINK-yyqnmipb, and
 * adding a name does not move this file across a line it was already on the far
 * side of.
 *
 * THE DISCIPLINE THAT KEEPS IT THERE — check this on every future row. A name
 * qualifies only if the vendor publishes it as a way to reach an endpoint this
 * file ALREADY carries as an address, cited to the page that publishes it; the
 * `address` field records which row, and a test asserts the tie. The moment a
 * row is added because a name merely LOOKS internal — `metadata.$corp.com`,
 * anything under `*.internal` — this has become a blocklist and the rule is
 * broken. `svc.internal`, `foo.metadata.example.com`, `metadata.mycorp.com` and
 * `my-instance-data.example.org` are pinned benign to hold that line.
 *
 * INDEPENDENT OF LINK-mgnbgicq. That issue asks whether CONTEXT-DEPENDENT names
 * — `svc.internal`, `home.arpa`, the RFC 6761 set — are in scope for claim (a),
 * on the property that the same string names different machines on different
 * networks. Nothing here rides on that property, or on RFC 6761 at all. These
 * names are the opposite case: the provider fixes what the name addresses, so
 * the reason to flag `metadata.google.internal` is not that it means different
 * things in different places, but that it means ONE published thing and that
 * thing vends credentials. The test of independence is that mgnbgicq cannot move
 * this behaviour either way. Rule the RFC 6761 class OUT of scope and these rows
 * still fire, because they were never fired on for being context-dependent; rule
 * it IN and they gain nothing. `svc.internal` — mgnbgicq's own worked example —
 * stays at 0.00 under both outcomes, which is what the independence looks like
 * from the corpus.
 */

/**
 * Version stamp for this curated table, surfaced as
 * `dataVersions.cloudMetadata`. Bump deliberately whenever a row is added,
 * removed, or re-attributed.
 */
export const CLOUD_METADATA_VERSION = "2026-08-25-hostnames";

/**
 * What a row IS, which selects the noun used to describe it in the emitted
 * detail. Wording only — both kinds classify as the same `ip_cloud_metadata`
 * bucket and carry the same weight, so this is not a scoring or schema input.
 *
 * - `instance-metadata` — an IMDS: the address a guest queries for its own
 *   instance identity and, in practice, for role credentials.
 * - `provider-internal` — other vendor platform infrastructure reachable only
 *   from inside a VM, which the vendor documents as something OTHER than its
 *   IMDS. Azure's WireServer is the case this exists for.
 */
export type CloudEndpointKind = "instance-metadata" | "provider-internal";

/** One cloud vendor's well-known metadata / provider-internal endpoint. */
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
  /**
   * Which flavour of vendor endpoint this is. Omitted means
   * `"instance-metadata"` — the overwhelmingly common case, so only the
   * exceptions carry the field and a new IMDS row needs no ceremony.
   */
  kind?: CloudEndpointKind;
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
    //
    // Hence `provider-internal` (LINK-mjbrzxeo): Microsoft's own page for this
    // address describes a virtual platform channel used for VM/host
    // communication — DHCP, DNS, load-balancer health probes, guest agent goal
    // state — and points elsewhere for instance metadata. Calling this an
    // instance-metadata endpoint in the emitted detail contradicts the vendor
    // documentation the row is cited to. Blocking and scoring it is untouched:
    // it is security-sensitive provider-internal infrastructure either way.
    address: "168.63.129.16",
    provider: "Azure (WireServer host channel)",
    kind: "provider-internal",
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
    // not a row of THIS table — it is not an IP literal and would match nothing
    // here — but it is no longer unrepresented: see CLOUD_METADATA_HOSTNAMES.
    address: "169.254.0.23",
    provider: "Tencent Cloud",
    source: "https://www.tencentcloud.com/document/product/213/32364",
  },
];

/**
 * One vendor-published NAME for an endpoint that {@link CLOUD_METADATA_ENDPOINTS}
 * already carries as an address.
 */
export interface CloudMetadataHostname {
  /**
   * The full host, lowercase and without a trailing root dot. Matched as a WHOLE
   * host, never as a suffix — see {@link matchCloudMetadataHostname}.
   */
  hostname: string;
  /**
   * The endpoint this name addresses, as the vendor publishes it. Required, and
   * required to be a row of {@link CLOUD_METADATA_ENDPOINTS}: that tie is what
   * makes "the table supplies only the spelling" a checkable statement rather
   * than a slogan, and it is asserted by the table-integrity test.
   */
  address: string;
  /** Provider attribution, rendered verbatim into the emitted detail. */
  provider: string;
  /** As {@link CloudMetadataEndpoint.kind}; omitted means `instance-metadata`. */
  kind?: CloudEndpointKind;
  /** Vendor documentation this NAME was verified against (auditability). */
  source: string;
}

/**
 * The hostnames linklint recognizes as `ip_cloud_metadata` (LINK-hvawpgos).
 *
 * SOURCING IS THE ACCEPTANCE CRITERION, not a courtesy. Every row below was
 * checked against the vendor's own current documentation and carries the page it
 * was read from, exactly as the address rows do. Names that circulate widely in
 * SSRF cheat-sheets but that no vendor page writes down are NOT here: an
 * over-broad row is a `high` verdict on somebody's legitimate internal
 * hostname, and there is no such thing as a harmless one.
 *
 * The rows deliberately stop at the endpoint's own names. They do not extend to
 * the private namespaces those names live in — `*.internal`, `*.ec2.internal`,
 * `*.compute.internal` are ordinary vendor-issued instance names and stay
 * silent.
 */
export const CLOUD_METADATA_HOSTNAMES: readonly CloudMetadataHostname[] = [
  {
    // GCP's RECOMMENDED spelling — not an alias anyone can be talked out of
    // using. Google's own endpoint list gives
    // "http://metadata.google.internal/computeMetadata/v1" first and marks it
    // recommended, with "http://169.254.169.254/computeMetadata/v1" beside it as
    // the same server. Every GCP SSRF write-up and every GCP code sample uses
    // the name; only linklint was reading the address.
    hostname: "metadata.google.internal",
    address: "169.254.169.254",
    provider: "GCP",
    source: "https://docs.cloud.google.com/compute/docs/metadata/querying-metadata",
    // #endpoints — "http://metadata.google.internal/computeMetadata/v1"
  },
  {
    // The second name on the same Google page —
    // "http://metadata.goog/computeMetadata/v1" — listed as an HTTP endpoint of
    // the same metadata server. Worth its own row because it is not a subdomain
    // of anything already listed and shares no suffix with it: a check written
    // against `*.google.internal` misses it entirely.
    hostname: "metadata.goog",
    address: "169.254.169.254",
    provider: "GCP",
    source: "https://docs.cloud.google.com/compute/docs/metadata/querying-metadata",
    // #endpoints — "http://metadata.goog/computeMetadata/v1"
  },
  {
    // Tencent Cloud CVM. Tencent's instance-metadata guide documents the NAME
    // and nothing else — "http://metadata.tencentyun.com/latest/meta-data/" —
    // which is the mirror image of the sourcing problem on the address row
    // above, and the reason that row had to be cited to the Cloudbase-Init page
    // instead.
    //
    // The `address` tie is Tencent's two pages read together, not a sentence
    // either page contains: the metadata guide names the host, the
    // Cloudbase-Init page sets `metadata_base_url=http://169.254.0.23/` for the
    // same service. Recorded plainly because the tie is an inference — it picks
    // the numeric endpoint quoted in the detail, and nothing else.
    hostname: "metadata.tencentyun.com",
    address: "169.254.0.23",
    provider: "Tencent Cloud",
    source: "https://www.tencentcloud.com/document/product/213/4934",
  },
  {
    // IBM Cloud VPC. The strongest name-to-address tie in this table: IBM's
    // metadata API reference states that the endpoint URL "may contain either
    // the service's IP address http://169.254.169.254 or the service's hostname
    // http://api.metadata.cloud.ibm.com", and that over HTTPS it MUST be the
    // hostname — so an address-only check is blind to IBM's own secure mode.
    // IBM's published docs source uses both independently as well: the
    // access-instance-metadata page curls the hostname, the security
    // best-practices page calls 169.254.169.254 "the metadata link-local
    // address".
    hostname: "api.metadata.cloud.ibm.com",
    address: "169.254.169.254",
    provider: "IBM Cloud VPC",
    source: "https://cloud.ibm.com/apidocs/vpc-metadata",
  },
  {
    // Exoscale. The vendor page introduces the service as published "on the Link
    // Local Address 169.254.169.254 which is private between the hypervisor and
    // the running instance" and then gives the access examples as
    // `curl http://metadata.exoscale.com/latest/meta-data`. One page, one
    // service, both spellings — the `address` tie is that adjacency, not a
    // sentence stating an A record.
    hostname: "metadata.exoscale.com",
    address: "169.254.169.254",
    provider: "Exoscale",
    source:
      "https://community.exoscale.com/product/compute/instances/how-to/cloud-init-user-data/",
  },
];

/**
 * NAMES CONSIDERED AND DECLINED (LINK-hvawpgos). Recorded so the same four
 * candidates are not re-proposed from the same cheat-sheets they came from, and
 * so the sourcing bar is visible rather than asserted.
 *
 * Each was checked against the vendor's own current documentation and each
 * failed. `instance-data` / `instance-data.ec2.internal` do not appear as a host
 * anywhere in the current EC2 User Guide — the one occurrence of the string is
 * a local output filename — and AWS documents only `169.254.169.254` and
 * `fd00:ec2::254`. `metadata.azure.internal` appears nowhere on Microsoft's IMDS
 * page or in its upstream doc source; `metadata.azure.com` DOES appear there,
 * but as a TLS certificate SAN for validating attested data, which is not an
 * address you reach IMDS at and must not be laundered into this table as a
 * substitute. `metadata.oraclecloud.com` appears nowhere in Oracle's metadata
 * documentation, which states plainly that "the service is an HTTP endpoint
 * listening on 169.254.169.254"; the `oraclecloud.com` hits in search are
 * Oracle's documentation CDN.
 *
 * Two more were sourceable and still declined:
 *
 * - Bare `metadata`. It survives only in App Engine flexible runtime code
 *   samples (`http://metadata/computeMetadata/v1/…`) and is absent from the
 *   Compute Engine Root URLs table that lists the other four GCP forms. It is
 *   also the highest false-positive risk any row could carry: whole-host
 *   equality on a SINGLE LABEL puts a `high` verdict — and an agent-mode block —
 *   on any organization that happens to run a host called `metadata`. A legacy
 *   sample on a legacy runtime does not buy that. Reopen if Google lists it in
 *   the Compute Engine endpoint table.
 * - `metadata.platformequinix.com`. Genuinely documented, but Equinix Metal was
 *   sunset on 2026-06-30 and the citing page is scheduled for removal on
 *   2026-09-30. A row whose only source expires before the next data refresh
 *   fails the requirement that entries be checkable against CURRENT vendor
 *   documentation.
 */

/**
 * Index for {@link matchCloudMetadataHostname}, built once at module load.
 * Per-call cost is one lowercase, one possible slice, and one Map lookup.
 */
const HOSTNAME_INDEX = new Map<string, CloudMetadataHostname>(
  CLOUD_METADATA_HOSTNAMES.map((row) => [row.hostname, row]),
);

/**
 * The vendor-documented metadata hostname `host` names, or undefined.
 *
 * WHOLE-HOST EQUALITY, after case folding and after dropping ONE trailing root
 * dot. Nothing looser. A suffix test would fire on `metadata.google.internal`
 * *.evil.com and a substring test on `my-instance-data.example.org`; both are
 * how a specification index quietly becomes a blocklist.
 *
 * The trailing dot is not a nicety. `metadata.google.internal.` resolves
 * identically and is the documented Smokescreen allow-list bypass (see
 * `detectors/fqdn-root-label.ts`), so a matcher that missed it would ship the
 * bypass along with the check. Two or more trailing dots never reach here —
 * they create an empty label and fail parsing as `invalid`.
 *
 * Zero-network: this is a string comparison against a fixed table. No lookup is
 * performed and none is implied.
 */
export function matchCloudMetadataHostname(host: string): CloudMetadataHostname | undefined {
  if (host === "") return undefined;
  const bare = host.endsWith(".") ? host.slice(0, -1) : host;
  return HOSTNAME_INDEX.get(bare.toLowerCase());
}
