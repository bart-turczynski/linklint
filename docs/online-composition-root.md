# Composing an online run

- **Status:** implemented
- **Issue:** `LINK-qeinctxz`
- **Public exports:** `@linklint/online/transport`, `/resolution`, `/reputation`

Running the shipped online checks means writing a composition root: the caller
builds the adapters, supplies the consent callback, and hands the resulting plan
to `inspectAsync()`. That explicitness is the accepted design (`LINK-ryfztgke`,
[`docs/online-runtime-boundary.md`](./online-runtime-boundary.md)) — nothing here
is discovered from the environment. This document is the worked example that was
missing, so the shape does not have to be reconstructed from the source.

## The root

Four subpath imports, three adapters, one consent callback. The snippet below
was executed as written against a live network before it was documented.

```ts
import { inspectAsync } from "linklint";
import {
  createRedirectChainEnricher,
  type RedirectChainAuthorizationRequest,
} from "@linklint/online/resolution";
import {
  createDnsStateEnricher,
  createNodeDnsResolver,
  createTlsCertificateEnricher,
} from "@linklint/online/reputation";
import {
  createNodeSafeTlsInspector,
  createNodeSafeTransport,
  type DestinationFetchAuthorization,
} from "@linklint/online/transport";

// 1. Consent. Called once per hop, before any DNS query or socket.
const approvedHosts = new Set(["example.com", "www.example.com"]);

function authorize(
  request: RedirectChainAuthorizationRequest,
): DestinationFetchAuthorization | null {
  let host: string;
  try {
    host = new URL(request.url).hostname;
  } catch {
    return null;
  }
  if (!approvedHosts.has(host)) return null;
  return { kind: "destination-fetch", url: request.url };
}

// 2. Adapters. Constructing one opens no socket.
const transport = createNodeSafeTransport();
const tlsInspector = createNodeSafeTlsInspector();
const dnsResolver = createNodeDnsResolver();

// 3. Plan, in caller order.
const enrichers = [
  createRedirectChainEnricher({ transport, authorize }),
  createDnsStateEnricher({ resolver: dnsResolver }),
  createTlsCertificateEnricher({ inspector: tlsInspector }),
];

// 4. Run.
const result = await inspectAsync("https://example.com/", { enrichers });
```

### Which factory takes which adapter

The three enrichers reach the network through three different ports, so they do
not share one argument name. This is the part that otherwise requires reading
the source:

| Enricher factory | Subpath | Adapter option | Adapter factory |
| --- | --- | --- | --- |
| `createRedirectChainEnricher` | `./resolution` | `transport: SafeTransport` | `createNodeSafeTransport()` (`./transport`) |
| `createDivergenceProbeEnricher` | `./resolution` | `transport: SafeTransport` | `createNodeSafeTransport()` (`./transport`) |
| `createTlsCertificateEnricher` | `./reputation` | `inspector: SafeTlsInspector` | `createNodeSafeTlsInspector()` (`./transport`) |
| `createDnsStateEnricher` | `./reputation` | `resolver: DnsResolverPort` | `createNodeDnsResolver()` (`./reputation`) |
| `createRdapAgeEnricher` | `./reputation` | `client: RdapHttpClient` + `registry` | `createNodeRdapHttpClient()` (`./reputation`) |
| `createEmbeddedWrapperEnricher` | `./resolution` | none — local decoding only | — |

The transport is entered through `SafeTransport.createSession()`, not a bare
`fetch()`. The redirect-chain enricher does that for you and keeps one session
across the whole chain so the cumulative hop, byte, and elapsed-time budgets
apply to the chain rather than to each request; a caller driving L0 by hand
opens the session itself, as shown in
[`packages/online/README.md`](../packages/online/README.md).

The DNS resolver is the one adapter that lives on `./reputation` rather than
`./transport`, because it is a record-query port rather than a destination
connection.

## The `authorize` callback

`authorize` is a per-hop consent boundary, not a per-run switch. The redirect
chain calls it for the initial URL and again for every discovered target, and a
refusal stops that hop before DNS resolution or connection. Driving the example
above at `http://iana.org/` with an allow-all callback invokes it twice:

| `hop` | `reason` | `method` | `url` | `fromUrl` |
| --- | --- | --- | --- | --- |
| 1 | `initial` | `GET` | `http://iana.org/` | absent |
| 2 | `http-redirect` | `GET` | `https://www.iana.org/` | `http://iana.org/` |

The request carries `url`, `hop`, `method`, `reason` (`initial`, or the
transition kind that discovered the target) and, from the second hop onward,
`fromUrl`. Returning `null` refuses; a returned authorization is re-checked by
L0 for an exact match against the URL it is about to fetch, so an authorization
minted for one URL does not carry to the next one. The full transition and
budget contract is in
[`docs/redirect-chain-resolution.md`](./redirect-chain-resolution.md).

**The rubber stamp is for local experiments only.** This form:

```ts
// UNSUITABLE FOR PRODUCTION — approves every destination the chain discovers.
const authorize = ({ url }: RedirectChainAuthorizationRequest) =>
  ({ kind: "destination-fetch", url }) as const;
```

turns the callback into a no-op and lets an inspected URL steer the process
into fetching any public destination it names, one redirect at a time. A
production root decides per hop against something the caller owns — an
allowlist, a user action, a quota, a policy service — and returns `null` for
everything else. Installation and construction are not consent
([`docs/online-runtime-boundary.md`](./online-runtime-boundary.md) §
"Opt-in and authorization rules").

## Loopback is refused by the address policy

An example pointed at a local server does not work, by design. L0 classifies
every address that resolution returns, and a loopback address is prohibited:
the run produces a `skipped` outcome with `cause.code: "prohibited-address"` and
`cause.details` of `{ address: "127.0.0.1", category: "ip_loopback" }` — even
when `authorize` approved the URL. Point experiments at a real public host, or
at a fixture-driven transport in tests. The address categories are listed in
[`docs/safe-transport.md`](./safe-transport.md).

## Reading the result

The scored fields are unchanged by composition: evidence-only sources such as
DNS and TLS add artifacts without moving `score` or `severity`. What the online
run adds is `result.enrichment` plus the coverage tokens.

### Coverage tokens

`checksRun` and `checksSkipped` carry one `<layer>:<id>` token per configured
enricher — `resolution:redirect-chain.http`, `reputation:dns.state`,
`reputation:tls.live-endpoint`. Before any enricher is configured, the layer
placeholders `resolution` and `reputation` sit in `checksSkipped` instead, which
is how an unconfigured layer stays visible rather than reading as clean.

The example above, run against `https://example.com/`:

```
checksRun:      lexical, resolution:redirect-chain.http, reputation:dns.state, reputation:tls.live-endpoint
checksSkipped:
```

The same root run against `https://iana.org/`, a host outside `approvedHosts`:

```
checksRun:      lexical, reputation:dns.state, reputation:tls.live-endpoint
checksSkipped:  resolution:redirect-chain.http
```

The refusal is visible in the coverage lists rather than being folded into the
score.

### `enrichment.outcomes[]`

Each entry is attributed and self-describing. The fields a consumer reads first:

| Field | Meaning |
| --- | --- |
| `sourceId` | The producing enricher's id, matched against the enricher that ran. |
| `layer` | `resolution` or `reputation`; with `sourceId` it forms the coverage token. |
| `status` | `success`, `no-hit`, `skipped`, or `failure`. |
| `subject` | What this outcome is *about* — a `{ kind, value }` pair whose `kind` is `url` or `host`. A redirect chain reports per-hop subjects, so one source can emit several. |
| `cause` | Present on `skipped`/`failure`: a machine-readable `code`, plus structured `details`. |
| `evidence` | Source artifacts (`dns.records`, `tls.certificate`, `resolution.chain-hop`, …). |
| `findings` | Scored reasons; permitted only on `success`. |

Printed for the two runs above:

```
resolution:redirect-chain.http  success  url=https://example.com/
reputation:dns.state            success  host=example.com
reputation:tls.live-endpoint    success  host=example.com

resolution:redirect-chain.http  skipped  url=https://iana.org/  cause=authorization-denied
reputation:dns.state            success  host=iana.org
reputation:tls.live-endpoint    success  host=iana.org
```

A `skipped` or `failure` outcome is an operational state, not a verdict, and a
`no-hit` is evidence about one source at one time rather than a safety claim.
The full status table, the core-generated cause codes, provenance/freshness,
staged `dependsOn` plans, and the caching rules are in
[`docs/enrichment-outcomes.md`](./enrichment-outcomes.md); this section covers
only what a composition root needs to read its own output.

## Sources this root deliberately omits

- **RDAP** (`createRdapAgeEnricher`) is runnable — `createNodeRdapHttpClient`
  supplies the HTTP client and `updateRdapBootstrap` refreshes the IANA routing
  snapshot — but the bootstrap snapshot is caller-owned storage. With
  `registry: null`, every lookup is `skipped` with
  `rdap-bootstrap-unavailable`; past a snapshot's `expiresAt`, with
  `rdap-bootstrap-stale`. Adding it to a root therefore means deciding where the
  snapshot lives and how often it is updated, which is an application decision
  rather than a line of composition.
- **URLhaus and PhishTank** (`@linklint/online/mirrors`) ship no Node client or
  store adapter (`LINK-mpkglaqb`), so they cannot appear in a runnable example
  yet. Their mirrors are caller-owned by design.

## Why there is no `createDefaultOnlineEnrichers()`

A one-call helper returning "the standard bundle" was considered for this work
and declined. Four reasons, recorded so the question does not have to be
reopened from scratch:

1. **There is no honest default bundle.** RDAP needs caller-owned bootstrap
   storage and the mirrors have no Node adapter, so any blessed set today is a
   partial one that would read as complete.
2. **It has no home in the export map.** The package exposes exactly five
   subpaths; `.` re-exports the source contract only, and a helper spanning
   transport, resolution, and reputation would force a cross-layer import into
   whichever of the other subpaths hosted it.
3. **The adapters differ per enricher.** A single-argument helper would have to
   hard-code `createNodeSafeTransport()`, `createNodeSafeTlsInspector()`, and
   `createNodeDnsResolver()` internally, swallowing the policy, resolver, and
   clock injection points those factories exist to expose — an ambient default
   wearing a factory's clothes.
4. **The measured gap was documentation, not API.** What cost the reader time
   was discovering which factory takes which port and that consent is per hop.
   This page closes that at zero added public surface, and the explicit root
   stays explicit.

If it is reopened, it should be against a concrete caller whose root this
actually shortens, not against the general shape of the boilerplate.
