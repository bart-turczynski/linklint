# LINK-yyqnmipb — S2: cloud-metadata provider table

> **Historical worklog.** Written against `3e48ab7` (2026-07-25), the commit
> that shipped `LINK-yyqnmipb`. The table it describes has since roughly
> tripled and gained a second, hostname-keyed half. The only current-behavior
> authority is `packages/core/src/data/cloud-metadata.ts` itself, whose header
> comment carries the live sourcing rules; read this file for the reasoning that
> produced the first four rows, not for the table's present contents.
>
> **Superseded figures, as of 2026-08-25.** `CLOUD_METADATA_VERSION` is
> `"2026-08-25-gcp-ipv6"`, not the `"2026-07-25-providers"` quoted below.
> `CLOUD_METADATA_ENDPOINTS` carries **10** address rows, not 4, and a companion
> `CLOUD_METADATA_HOSTNAMES` carries 5 vendor-published names — a table that did
> not exist when this was written and that has its own sourcing bar
> (`LINK-hvawpgos`). Rows also now declare a `kind`, distinguishing an IMDS from
> other provider-internal infrastructure (`LINK-mjbrzxeo`).

## What landed

- New `packages/core/src/data/cloud-metadata.ts`: `CLOUD_METADATA_ENDPOINTS`
  (4 rows at the time: address + provider + vendor-doc source) and
  `CLOUD_METADATA_VERSION` (then `"2026-07-25-providers"`).
- `detectors/ip-classification.ts`: the two literals (`0xa9fea9fe`,
  `"fd00:ec2::254"`) are gone. Two lookup maps are built once at module load by
  running every table row through the SAME parser (`analyzeIpv4`/`analyzeIpv6`)
  used on the host under inspection: v4 keyed by the 32-bit int, v6 keyed by the
  RFC 5952 canonical string. Per-call cost is one `Map.get`.
- `dataVersions.cloudMetadata` added (`schema/result.ts` type +
  `data/versions.ts` value).
- Tests: alternate-spelling lock, per-provider classification/detail, table
  integrity, stamp; 3 new corpus rows.
- `docs/reason-codes.md`: prose only, under the unchanged
  `### \`ip_cloud_metadata\`` heading.

## Non-obvious judgment calls

1. **Canonicalize BOTH sides, not just the host.** The constraint was "compare on
   the parsed address". I went further: table rows are canonicalized through the
   same parser at load, so the table is spelling-agnostic in both directions. A
   future contributor who writes `fd00:0ec2::254` or `FD00:EC2::254` in the data
   file gets identical behaviour — the string in the data file is never compared
   to anything. Test `alternate spelling %s is the same endpoint` covers 5
   spellings of the AWS v6 bits, plus a negative (`fd00:ec2::255` → `ip_private`)
   proving the match is on bits, not a prefix.

2. **Unparseable rows are skipped, not thrown on.** A `throw` at module load
   would make a data typo break every import of the library (and `inspect()` must
   never throw). Instead the loop skips a row it cannot parse, and a test asserts
   every row parses — a typo fails CI loudly rather than silently dropping an
   endpoint in production.

3. **`provider` is an optional field on the exported `IpClassification`.**
   `classifyHost` is public API (`index.ts` + `experimental.ts`, pinned by
   `public-api-contract.test.ts` as a KEY only). Adding an optional field is
   source-compatible; `packages/online/src/transport/address.ts` (the only
   external consumer) reads `bucket` and is untouched. The generic range buckets
   leave `provider` undefined and keep their exact previous detail wording — only
   `ip_cloud_metadata` details changed, gaining the provider name.

4. **Shared endpoint attributed as a group.** `169.254.169.254` is answered by
   AWS, Azure, GCP, DigitalOcean and OpenStack alike; there is no lexical signal
   that picks one. Provider string is
   `"AWS / Azure / GCP / DigitalOcean / OpenStack"` rather than a guess.

5. **Version value.** `"2026-07-25-providers"` follows the curated-table
   convention already used by `riskyTlds` (`"2026-06-19"`) and `brands`
   (`"2026-06-20-watchlist"`) — a date stamp, not a `pkg@semver` stamp, so the
   `data-versions.test.ts` dependency-stamp check (which only covers
   `publicSuffixList` and `idna`) correctly does not apply.

6. **No new reason code, no weight change.** `192.0.0.192` moves from *no reason
   at all* (score 0.00) to `ip_cloud_metadata` 0.75; `100.100.100.200` moves from
   `ip_reserved` 0.20 to `ip_cloud_metadata` 0.75. Both are now `high`, i.e. they
   fail the default `--fail-on high` gate. That is the intended severity move.

## Provider-endpoint sourcing

| Endpoint | Provider | Source |
| --- | --- | --- |
| `169.254.169.254` | AWS / Azure / GCP / DigitalOcean / OpenStack | AWS EC2 IMDS docs (`instancedata-data-retrieval.html`); Azure IMDS docs (`learn.microsoft.com/azure/virtual-machines/instance-metadata-service`) confirm the same address |
| `fd00:ec2::254` | AWS (IPv6 IMDS) | AWS docs `configuring-instance-metadata-service.html` — "The IMDS has two endpoints: IPv4 (169.254.169.254) and IPv6 ([fd00:ec2::254])"; Nitro instances in an IPv6-enabled subnet, opt-in |
| `192.0.0.192` | Oracle Cloud | Oracle OCI "Getting instance metadata" docs; endpoint family `http://192.0.0.192/latest/{meta-data,user-data,attributes}` |
| `100.100.100.200` | Alibaba Cloud | Alibaba ECS "View instance metadata" docs (`alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/`) — `http://100.100.100.200/latest/meta-data/` |

## Additions found and deferred at the time — all four have since landed

> **This section is closed. Do not read it as an open proposal.** Scope for
> `LINK-yyqnmipb` said exactly four rows, so the four candidates below were
> recorded rather than added. Every one of them has since been verified against
> vendor documentation and shipped as a second tier of
> `CLOUD_METADATA_ENDPOINTS` under `LINK-vniqhcln`, and `169.254.170.23`'s IPv6
> partner `fd00:ec2::23` shipped alongside it. Azure's `168.63.129.16` was
> additionally re-classified `kind: "provider-internal"` by `LINK-mjbrzxeo`,
> because Microsoft documents WireServer separately from the Azure IMDS and
> calling it an instance-metadata endpoint contradicted the row's own citation.
> The live rows and their current citations are in
> `packages/core/src/data/cloud-metadata.ts`; the paragraphs below are the
> 2026-07 scouting notes that preceded them and their citations were superseded
> at landing. Nothing here is a request to widen the table.

1. **`168.63.129.16` — Azure WireServer / IMDS-adjacent host-agent channel.**
   Microsoft-documented "special public IP" used by the Azure VM agent; also
   proxies some platform metadata. Notable because it is OUTSIDE any special-use
   range and currently classifies as an ordinary public address.
   Citation: `learn.microsoft.com/en-us/answers/questions/2137124/what-is-the-difference-between-169-254-169-254-and`.
2. **`169.254.170.2` — AWS ECS task metadata endpoint (v2/v3/v4).**
   Distinct from the EC2 IMDS address; today it lands as `ip_link_local` (0.20)
   rather than metadata. Citation: AWS re:Post
   `repost.aws/questions/QU5ELLj4a2Qya4ETj7omJyUA/...` and AWS ECS task-metadata
   docs.
3. **`169.254.170.23` (+ IPv6 `fd00:ec2::23`) — AWS EKS Pod Identity Agent.**
   Same family as (2), newer; credential-bearing. Citation: same AWS re:Post
   thread; AWS EKS Pod Identity docs.
4. **`169.254.0.23` — Tencent Cloud (`metadata.tencentyun.com`).**
   Citation: `cloud.tencent.com/document/product/213/4934` (Querying Instance
   Metadata) / `tencentcloud.com/document/product/213/4934`.

Note that (2), (3) and (4) sit inside `169.254.0.0/16`, so adding them only
raised them from `ip_link_local` 0.20 to `ip_cloud_metadata` 0.75 — no new range
logic needed, just table rows. (1) was the one that changes a *public* address's
verdict, so it got the most scrutiny (false-positive cost is a `high` verdict on
a routable IP); that reasoning is now recorded on the shipped row itself.

## Verification

`pnpm check` exit 0 at `3e48ab7` — `Test Files 102 passed`, `Tests 2027 passed`
(baseline 2006 + 21 new), `51 scenarios`, `215 steps`. Those totals are a
2026-07-25 reading and have moved with every slice since. No pre-existing
failures touched; the pinned link-local corpus rows stay green.

**Corpus citation, re-anchored.** This paragraph originally cited
`corpus.ts:781,789`. Both line numbers rotted — as of 2026-08-25 they land on
`https://accounts.google.com` and `https://amazon.com`, unrelated benign brand
rows. The rows actually meant are the two `V1b link-local bucket` entries in
`packages/core/test/corpus/corpus.ts`: `http://169.254.10.20/` and
`https://[fe80::abcd]/`, both `label: "deceptive"` with
`expectReasons: ["ip_link_local"]` and `forbidReasons` including
`ip_cloud_metadata`. Grep for the URL, not the line — both still score `0.20` on
`ip_link_local` alone today.
