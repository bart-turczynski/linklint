# @linklint/online

Explicit, caller-composed Node/server capabilities for `linklint`.

The package is being delivered capability by capability. Importing it performs
no network I/O, and the existing `linklint`, `@linklint/cli`, and
`@linklint/mcp` packages remain offline.

The Node-only `@linklint/online/transport` subpath exposes the shipped L0 safe
destination boundary. Each manual HTTP(S) hop requires exact-URL caller
authorization, re-resolves the hostname and classifies every address that
resolution returns, pins the approved socket while preserving
Host/SNI/certificate identity, strips ambient headers,
and enforces cumulative hop, encoded-byte, decoded-byte, and total-time limits.
Redirects are returned to the caller; they are never followed implicitly.

```ts
import { createNodeSafeTransport } from "@linklint/online/transport";

const session = createNodeSafeTransport().createSession();
const url = "https://example.com/";
const outcome = await session.fetch({
  url,
  authorization: { kind: "destination-fetch", url },
});
```

The outcome statuses and cause vocabularies a caller branches on are enumerated
at runtime from the same subpath, stamped by `TRANSPORT_SCHEMA_VERSION`
(currently `1.0`), and published in
[`docs/safe-transport.md`](../../docs/safe-transport.md). A value added to or
removed from one of them moves the stamp.

```ts
import {
  isTransportCauseCode,
  TRANSPORT_CAUSE_CODES,
  TRANSPORT_SCHEMA_VERSION,
} from "@linklint/online/transport";
```

The `@linklint/online/resolution` subpath exposes shipped local embedded-wrapper
decoding. It recognizes only exact, version-pinned Microsoft Safe Links and
Proofpoint URL Defense formats, applies mandatory length/nesting bounds, and
never calls a vendor decoder or any other network service. The enricher factory
re-inspects every recovered target through synchronous core Layer 1.

```ts
import { inspectAsync } from "linklint";
import { createEmbeddedWrapperEnricher } from "@linklint/online/resolution";

const result = await inspectAsync(wrappedUrl, {
  enrichers: [createEmbeddedWrapperEnricher()],
});
```

The same subpath exposes caller-authorized bounded redirect/refresh expansion.
It uses one L0 session across the chain, requests fresh exact-URL authorization
for every discovered target, supports GET/HEAD plus 301/302/303/307/308,
resolves relative `Location` values, and parses HTTP/HTML refresh only under
finite byte, MIME, charset, delay, hop, and total-transport budgets.

```ts
import { createRedirectChainEnricher } from "@linklint/online/resolution";
import { createNodeSafeTransport } from "@linklint/online/transport";

const redirectChain = createRedirectChainEnricher({
  transport: createNodeSafeTransport(),
  authorize: ({ url }) => callerApproved(url)
    ? { kind: "destination-fetch", url }
    : null,
});
```

## Terms are a construction gate

Every reputation and mirror enricher factory takes a **required** `terms`
argument — the caller's licensing posture for that source — and checks it against
the source's descriptor before the enricher exists. There is no default: only you
know your commercial posture, and inventing one would be the silent downgrade the
contract forbids.

```ts
import { createUrlhausEnricher } from "@linklint/online/mirrors";

// Throws OnlineSourceConfigError('unsupported-commercial-mode'): abuse.ch grants
// free non-commercial / fair use, and commercial use needs a separate plan.
createUrlhausEnricher({
  terms: { commercialMode: "commercial", acceptAttribution: true },
  resolveIndex,
});

// Accepted.
createUrlhausEnricher({
  terms: { commercialMode: "fair-use", acceptAttribution: true },
  resolveIndex,
});
```

Only the two mirrors can refuse today. RDAP, live TLS and DNS declare all three
commercial modes and require no attribution, so no legal `terms` value makes
their gate throw — a property of those descriptors, not an exemption. The gate
is terms-only and never asks for a feed credential: the Auth-Key and app key are
revealed by the *updaters* below, and querying a snapshot you already own must
not demand the key that downloaded it. The resolution enrichers take no `terms`
at all; a destination is authorized per hop, not per construction.

## Caller-owned threat-feed mirrors

The `@linklint/online/mirrors` subpath exposes the URLhaus and PhishTank
mirrors. Both are *local* mirrors: the dataset is downloaded once — with a
caller-owned credential where the provider needs one — and queried offline, so a
lookup discloses nothing about the inspected URL. Neither dataset is bundled in
this package or redistributed.

Each feed ships a bounded Node HTTP client for the download. Both sit outside
the L0 destination boundary — a feed host is a provider, not an inspected
destination — but both classify every address they would connect to with the
same table L0 pins destinations with, so a mis-configured download URL cannot
reach loopback, link-local, or cloud-metadata space. Both refuse a non-HTTPS
download URL, because a request they make may carry your credential and neither
client can tell from the URL whether this one does. Both follow a redirect,
within bounds that keep your credential away from a host you did not name
(`LINK-scectgty`): up to three redirects are followed and a fourth fails with
`hop-limit`; every hop URL passes the same HTTPS-only gate as yours, so a
`Location:` naming `http:` fails with `unsupported-scheme`; a hop to another
origin carries only `Accept`, `Accept-Encoding` and `User-Agent`, so URLhaus's
`Auth-Key` is dropped and stays dropped on a hop back; and each hop's address is
classified before its socket opens. The response reports the hops as origins
only, with no path or query, since PhishTank's key is a path segment. A 3xx with
no `Location` is not followed; the updater reports it as an HTTP error naming
the status. Register entry F18 and `docs/online-runtime-boundary.md` state the
same bounds.

```ts
import {
  createNodeUrlhausHttpClient,
  updateUrlhausSnapshot,
} from "@linklint/online/mirrors";
import { createOnlineSecret } from "@linklint/online";

const result = await updateUrlhausSnapshot({
  client: createNodeUrlhausHttpClient(),
  store: myUrlhausStore,          // yours — see below
  credential: createOnlineSecret(process.env.URLHAUS_AUTH_KEY!),
  clock: { now: () => new Date() },
  cadenceMs: 3_600_000,
});
```

PhishTank is the same shape, with a descriptive `User-Agent` the provider
requires and an app key that is **optional** — supplied, it goes into the
download URL's path rather than a header; omitted, the public feed URL is
requested instead:

```ts
import {
  createNodePhishTankHttpClient,
  updatePhishTankSnapshot,
} from "@linklint/online/mirrors";

const result = await updatePhishTankSnapshot({
  client: createNodePhishTankHttpClient(),
  store: myPhishTankStore,
  clock: { now: () => new Date() },
  userAgent: "phishtank/your-username",
  // Optional. Sent in the URL path when present:
  // appKey: createOnlineSecret(process.env.PHISHTANK_APP_KEY!),
});
```

#### Why the PhishTank app key is optional, and how the download completes

Measured against the live provider on **2026-09-05**. PhishTank serves this feed
to an unkeyed request:

```console
$ curl -sSI -A 'linklint-phishtank-mirror' \
    https://data.phishtank.com/data/online-valid.csv
HTTP/2 302
location: https://cdn.phishtank.com/datadumps/verified_online.csv?Expires=…&Signature=…
x-request-limit: 75
x-request-limit-interval: 259200 Seconds

$ curl -sSL -A 'linklint-phishtank-mirror' \
    https://data.phishtank.com/data/online-valid.csv | wc -l
   74540                       # 74,539 records + header
```

Substituting a syntactically plausible but fictional key —
`https://data.phishtank.com/data/deadbeef…/online-valid.csv` — returns the
identical `302`. The key position is not authenticating anything today, so
declaring the credential `required` stated a provider precondition that does not
exist, and turned `preflightOnlineSource` into a `credentials-missing` skip for
every operator who had none. A key is still honoured when supplied: PhishTank's
access policy has changed before, and a registered caller should keep
identifying itself rather than be silently anonymised.

Note also that the feed is **not** compressed on the wire — `content-type:
text/csv`, no `content-encoding`, 14,268,656 bytes — so nothing here depends on
the decode path. A `.csv.gz` variant exists as a separate URL and is not what
this updater asks for.

**The bundled Node client follows that hop** (`LINK-scectgty`). The `302`
points at `cdn.phishtank.com`, a host the caller did not name, and the client
follows it under the bounds stated above: it is one cross-origin hop, so only
`Accept`, `Accept-Encoding` and `User-Agent` go with it, and the signed CDN URL
is the provider's `Location`, not a URL built from your key.
`createNodePhishTankHttpClient` with no app key therefore completes the default
download; the client once stopped at the `302` and reported
`phishtank-http-error` / `PhishTank status 302`, and that was the only reason a
caller-supplied `PhishTankHttpClient` was needed. The follow was measured by
hand against the live provider when it shipped (`200`, `text/csv`, one hop); the
test suite exercises the same cross-origin shape on loopback and does not reach
PhishTank. `baseUrl` is still no way around the hop: the signed target is
`verified_online.csv` under a signature bound to that exact path, so a base
pointed at it gets `online-valid.csv` appended and answers `404`.

Feed exports are large, so these clients default to wider byte and time budgets
than a single-document fetch (`DEFAULT_MIRROR_DOWNLOAD_POLICY`: 64 MiB encoded,
256 MiB decoded, two minutes). Pass `policy` to narrow them. The response-header
budgets are not widened.

### The snapshot store is yours

`@linklint/online` deliberately ships **no** filesystem snapshot store — for
either mirror, and for the RDAP bootstrap registry either. The package holds the
`UrlhausSnapshotStore` / `PhishTankSnapshotStore` *interface*; you supply the
directory, database, or object store, because that is the piece whose durability,
concurrency, and retention policy belong to your deployment rather than to a
library. `docs/online-runtime-boundary.md` states the rule: "`@linklint/online`
ships interfaces too, not stores: a caller supplies the database, directory, or
store."

That is settled, not pending (`LINK-tkafhtrf`): an fs-backed store was
considered for this package and declined, and none will ship. The filesystem
stays on the caller's side of the runtime boundary, and the write-then-rename
sketch below is the permanent answer rather than a stand-in for a future
export.

The one property the updaters rely on is that `replace` is **atomic**: a reader
must never observe a partial dataset. On a POSIX filesystem, write-then-rename
gives you that:

```ts
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type {
  UrlhausSnapshot,
  UrlhausSnapshotMetadata,
  UrlhausSnapshotStore,
} from "@linklint/online/mirrors";

function fileUrlhausStore(path: string): UrlhausSnapshotStore {
  return {
    async readMetadata(): Promise<UrlhausSnapshotMetadata | null> {
      try {
        const raw = await readFile(path, "utf8");
        return (JSON.parse(raw) as UrlhausSnapshot).metadata;
      } catch {
        // No snapshot yet, or an unreadable one: report "none stored" so the
        // updater downloads a fresh dump rather than trusting a damaged file.
        return null;
      }
    },
    async replace(snapshot: UrlhausSnapshot): Promise<void> {
      await mkdir(dirname(path), { recursive: true });
      // Same directory as the target, so the rename is same-filesystem and
      // therefore atomic. A reader sees the old snapshot or the new one.
      const staging = join(dirname(path), `.${process.pid}.tmp`);
      await writeFile(staging, JSON.stringify(snapshot), "utf8");
      await rename(staging, path);
    },
  };
}
```

Two things this sketch leaves to you, because they are deployment decisions: it
does not `fsync` the staging file or its directory before the rename (durability
across a power loss, at a write-latency cost), and it assumes one writer at a
time (two concurrent updaters would each stage under their own pid and the last
rename would win, which is safe but wasteful — take a lock if you schedule them
independently).

The repository includes deterministic resolver, connector, HTTP, and clock
fixtures for transport tests. They are internal test infrastructure rather than
a supported package export; production code cannot discover or enable them.

A worked composition root — transport, redirect chain, DNS, and TLS wired
together, with the per-hop `authorize` contract and a guide to reading
`result.enrichment.outcomes[]` — is in
[`docs/online-composition-root.md`](../../docs/online-composition-root.md).

See [`docs/online-runtime-boundary.md`](../../docs/online-runtime-boundary.md)
for ownership and [`docs/safe-transport.md`](../../docs/safe-transport.md) for
the complete authorization, address, budget, and outcome contract. Local
wrapper formats and outcomes are documented in
[`docs/wrapper-decoding.md`](../../docs/wrapper-decoding.md); bounded redirect
and refresh behavior is documented in
[`docs/redirect-chain-resolution.md`](../../docs/redirect-chain-resolution.md).
