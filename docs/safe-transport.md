# Safe destination transport

- **Status:** implemented
- **Issue:** `LINK-cjkdyxau` (L0)
- **Public export:** `@linklint/online/transport`

The safe transport is the only built-in connection boundary for fetching an
inspected HTTP(S) destination. It is Node/server-only, caller-composed, and
side-effect free until an explicitly authorized request is made. Core, the
existing CLI, and the existing MCP server do not import it.

## Use

```ts
import { createNodeSafeTransport } from "@linklint/online/transport";

const session = createNodeSafeTransport().createSession();
const url = "https://example.com/start";
const outcome = await session.fetch({
  url,
  authorization: { kind: "destination-fetch", url },
  method: "GET",
});
```

Authorization names the exact request URL. A redirect response is returned
without being followed. The caller must resolve the `Location`, inspect the new
target offline, make a new consent decision, and call `fetch()` again with a
new exact-URL authorization. Reusing the session preserves one cumulative
budget across the chain.

`createSafeTransport()` accepts injected resolver, connector, HTTP, and clock
ports for deterministic tests and controlled server composition.
`createNodeSafeTransport()` supplies the built-in system resolver, pinned
TCP/TLS connector, HTTP/1.1 client, and clock. Construction performs no DNS or
network I/O. The raw built-in socket implementation is not exported, so other
built-in adapters cannot bypass the authorization layer.

## Binding request rules

- Only absolute `http:` and `https:` URLs and `GET`/`HEAD` are accepted.
- URL userinfo is blocked. There is no request-body field, cookie jar, proxy,
  environment credential discovery, client certificate, or automatic redirect.
- A fresh destination header set is built for every request. Only `Accept`,
  `Accept-Language`, and `User-Agent` may pass from caller input. `Host` and
  `Accept-Encoding` are set by the transport. Authorization, proxy
  authorization, cookies, Referer, API keys, and all other ambient headers are
  never copied.
- `Referer` has one dedicated channel, `sameOriginReferer`, and is never
  forwarded from `headers`. The candidate must be an absolute `http(s)` URL,
  free of userinfo, at most 2048 characters, and same-origin with the request
  URL (scheme, host, and effective port all equal); its fragment is dropped.
  Anything else blocks the request with `referer-not-same-origin` before any
  DNS or connection, so a caller-held cross-origin or private referrer cannot
  leave through this boundary.
- Every hostname is resolved again for every authorized hop. All answers are
  validated and classified before connection; one prohibited or malformed
  answer prevents any connection. Literal addresses are classified directly.
- The selected allowed address is passed explicitly to the connector. The
  connected remote address and port must match it. HTTPS keeps the original
  hostname for SNI and certificate identity validation.
- HTTP redirects remain manual. This boundary never converts a response into
  permission to connect to its target.

The connection classifier reuses core's most-specific metadata, loopback,
link-local, private, and reserved classification. It additionally blocks
documentation, benchmarking, discard, translation, transition, mapped-address,
and other non-global ranges that may be useful lexical examples but are unsafe
as network destinations. If a DNS set mixes global and prohibited answers, the
entire request is blocked before socket creation.

## Mandatory cumulative budgets

Every session has finite limits; zero, negative, non-finite, and timer-overflow
configuration is rejected.

| Limit | Default | Scope |
| --- | ---: | --- |
| `maxHops` | 10 | Explicitly authorized requests in the session |
| `maxResponseBytes` | 1 MiB | Encoded response-body bytes across all hops |
| `maxDecompressedBytes` | 4 MiB | Decoded body bytes across all hops |
| `maxTotalTimeMs` | 10,000 ms | Whole session, including time between hops and body decoding |
| `minThroughputBytes` | 512 B | Encoded body bytes required per throughput window |
| `minThroughputWindowMs` | 2,000 ms | Length of that window while a body is read |

The wall-clock deadline caps how long a destination can hold the session; the
throughput floor caps how long it can hold it *while delivering nothing useful*.
A destination that trickles bytes, or falls silent mid-body, closes a window
below the floor and the attempt ends with `response-too-slow` — the Slowloris
pattern inverted onto the client. The two limits are independent: the floor is
set far below the rate any body finishing inside `maxTotalTimeMs` must sustain,
so a slow but progressing response is not cut short.

Gzip, deflate, and Brotli are decoded under the remaining decompressed-byte
budget. Unknown encodings, malformed compressed bodies, byte exhaustion,
throughput starvation, and deadline exhaustion stop with explicit incomplete
causes. `response.body` is
the decoded bounded body; response headers remain the observed original headers.

Decoding uses zlib's synchronous entry points, which offer no interruptible
form, so a large body can hold the event loop past `maxTotalTimeMs` while the
timer racing the operation is unable to fire. `maxTotalTimeMs` is a bound on the
reported *outcome* rather than on CPU time: the session's elapsed time is read
again once decoding returns, and a decode that lands after the deadline ends the
attempt with `timeout` instead of `success` (`LINK-ktjbhvqd`). The encoded and
decoded byte caps are what bound the decode work itself — with the defaults, at
most 1 MiB in and 4 MiB out across the whole session, which keeps the practical
overrun in the low milliseconds.

## Outcomes and evidence

`SafeFetchOutcome.status` is one of:

- `success` — an authorized request completed and contains the bounded response;
- `blocked` — authorization or destination policy refused the request; or
- `incomplete` — DNS, connection, TLS, HTTP, cancellation, timeout,
  decompression, or budget failure prevented completion.

Every outcome carries the URL subject, observation time, and
`transport.attempt` evidence. Once known, the evidence also records the hop,
protocol, hostname, port, complete resolved-address set, and selected pinned
address. Runtime-specific exception messages are not copied into causes.

These are transport outcomes, not phishing verdicts. L1 maps them into the
versioned enrichment contract, re-inspects every discovered hop through the
offline pipeline, and preserves incomplete or blocked coverage honestly.

## Observational TLS inspection

`createSafeTlsInspector` / `createNodeSafeTlsInspector` add a strictly
observational capability that captures the certificate an HTTPS host presents,
without fetching anything. It reuses the exact SSRF/DNS-pinning decision the
fetch path uses (`pinDestination`), connects to the pinned address with the
original-host SNI, and reads the peer certificate with socket validation
**disabled** (`rejectUnauthorized: false`) so that an expired, not-yet-valid,
hostname-mismatched, or untrusted/self-signed certificate can be **observed**
rather than refused. The observe socket is read once and destroyed; it is never
reused, never handed to the HTTP layer, and never treated as a trusted
connection. The observe port is deliberately separate from the fetch connector,
so observe mode cannot leak into the fail-closed fetch path.

A successful observation is **non-authoritative**: it records what the peer
presented and how it validates, and never implies a normal fetch would be
allowed. `normalizeTlsCertificate` turns a raw handshake into evidence with three
independent axes — chain trust (from the handshake), validity window (from the
certificate's own notBefore/notAfter versus the observation instant), and
hostname identity (recomputed with Node's standard identity checker) — plus the
DNS SANs and certificate-policy OIDs (`readCertificatePolicyOids`, parsed from
preserved DER because Node's high-level APIs omit them). Chain depth, certificate
size, handshake time, and parsing are all bounded.

`TlsObservationOutcome.status` is `observed`, `blocked`, or `incomplete`.
`blocked` is reserved for transport-policy refusal (a prohibited pinned address);
DNS, connection, handshake, certificate-analysis, timeout, and cancellation
failures are `incomplete` with a typed cause. A TLS failure is never a safety
claim. `notBefore` is a validity start, **not** reliable issuance age.
