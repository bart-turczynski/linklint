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

Those built-in adapters never route through Node's ambient proxy configuration.
The connector opens its own `net`/`tls` socket to the pinned address, and the
HTTP/1.1 client hangs that already-connected socket off a freshly constructed
agent that is given no proxy environment, so `HTTP_PROXY`, `HTTPS_PROXY`,
`NODE_USE_ENV_PROXY`, and a runtime `http.setGlobalProxyFromEnv()` all leave the
connection direct. The limit of that claim is the built-ins: a caller-supplied
connector or HTTP port owns its own proxy behavior, and this boundary makes no
statement about an adapter it did not build.

## Binding request rules

- Only absolute `http:` and `https:` URLs and `GET`/`HEAD` are accepted.
- URL userinfo is blocked. There is no request-body field, cookie jar, proxy,
  environment credential discovery, client certificate, or automatic redirect.
- A fresh destination header set is built for every request. Only `Accept`,
  `Accept-Language`, and `User-Agent` may pass from caller input. `Host` and
  `Accept-Encoding` are set by the transport. Authorization, proxy
  authorization, cookies, Referer, API keys, and all other ambient headers are
  never copied.
- Those three forwarded values pass two independent checks, and neither check
  can end an attempt with an untyped exception. A value carrying CR, LF, or NUL
  is a request-splitting attempt and is dropped before any HTTP port sees it —
  that check is port-agnostic, so a caller-supplied port is never handed one
  either. A value the built-in HTTP/1.1 adapter cannot put on the wire ends the
  attempt as `incomplete` with the `http-malformed` cause, before the request is
  sent, and the cause never quotes the refused value. The sendable set is the
  HTTP/1.1 field-value set that adapter writes — HTAB, printable ASCII, and the
  `obs-text` range — so an ordinary `Accept-Language: de-DE, fr;q=0.9` and any
  value containing `ü` reach the destination byte for byte, while a value
  outside Latin-1 such as `Accept-Language: 日本語` is refused rather than
  truncated, re-encoded, or silently dropped. The second check belongs to the
  adapter and not to this boundary because the sendable set is a property of the
  wire a port writes; a caller-supplied port answers for its own.
- `Referer` has one dedicated channel, `sameOriginReferer`, and is never
  forwarded from `headers`. The candidate must be an absolute `http(s)` URL,
  free of userinfo, at most 2048 characters, and same-origin with the request
  URL (scheme, host, and effective port all equal); its fragment is dropped.
  Anything else blocks the request with `referer-not-same-origin` before any
  DNS or connection, so a caller-held cross-origin or private referrer cannot
  leave through this boundary.
- Every hostname is resolved again for every authorized hop, and every address
  that resolution returns is validated and classified before connection; one
  prohibited or malformed answer prevents any connection. Literal addresses are
  classified directly.
- The selected allowed address is passed explicitly to the connector. The
  connected remote address and port must match it. HTTPS keeps the original
  hostname for SNI and certificate identity validation.
- The built-in HTTP and TLS-observation adapters report the peer address and
  port they observed on the socket, and fail the connect when either is absent
  or malformed instead of echoing the requested values. Because that same check
  compares the reported peer against the pin, a substituted pin would confirm
  itself.
- HTTP redirects remain manual. This boundary never converts a response into
  permission to connect to its target.

The connection classifier reuses core's most-specific metadata, loopback,
link-local, private, and reserved classification. It additionally blocks
documentation, benchmarking, discard, translation, transition, mapped-address,
and other non-global ranges that may be useful lexical examples but are unsafe
as network destinations. If a DNS set mixes global and prohibited answers, the
entire request is blocked before socket creation.

### What "every address" is scoped to

The policy is scoped to what resolution returned for that hop, not to what the
authoritative zone holds. The built-in resolver makes one
`dns.lookup(hostname, { all: true, verbatim: true })` call per hop. That is a
`getaddrinfo` query, so its answer set is whatever the platform's configured
sources produce — `nsswitch`/hosts-file entries, the stub-resolver cache, RFC
6724 destination-address filtering, and `AI_ADDRCONFIG` family suppression can
each add to it or take from it — and it carries no TTL, which is why the
reported records show a `ttlSeconds` of 0. A caller-supplied resolver port
defines its own set. Neither is an authoritative A/AAAA RRset, and this
boundary does not claim one.

What the boundary is closed over is that returned set, not the completeness of
it: the connector is never handed an address outside the set that the hop's own
resolution returned, and every member of that set is classified before any
member is selected (`LINK-rbghrpru`).

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
| `maxResponseHeaderBytes` | 16,384 B | Response header block accepted on one hop |
| `maxResponseHeaderFields` | 128 | Response header field occurrences on one hop |

The wall-clock deadline caps how long a destination can hold the session; the
throughput floor caps how long it can hold it *while delivering nothing useful*.
A destination that trickles bytes, or falls silent mid-body, closes a window
below the floor and the attempt ends with `response-too-slow` — the Slowloris
pattern inverted onto the client. The two limits are independent: the floor is
set far below the rate any body finishing inside `maxTotalTimeMs` must sustain,
so a slow but progressing response is not cut short.

The two header limits are per-hop rather than cumulative, because a header block
is a per-response resource: a session that spent its whole encoded-byte budget
on bodies would otherwise leave each head unbounded. They are enforced at two
seams. The built-in HTTP/1.1 adapter hands `maxResponseHeaderBytes` to Node's
response parser as `maxHeaderSize`, so an oversized head stops while it is still
coming off the socket, and the parser's `HPE_HEADER_OVERFLOW` is mapped to the
`response-headers-too-large` cause instead of falling through to the generic
`http-error`. The transport then re-measures the parsed header block against both
limits, before the body is read — that second seam is the one a caller-supplied
HTTP port also passes through, since the adapter option reaches only the
built-in adapter. The re-measurement charges `name: value\r\n` per field
occurrence and leaves the status line free, making it a lower bound on the real
wire size rather than the exact count the parser saw; the adapter's parser limit
is the tight bound and this is the port-agnostic backstop behind it.

The byte default is Node's own `--max-http-header-size`, restated so the limit is
this boundary's rather than the host runtime's — before this budget the head was
bounded by whatever flags the process happened to start with, an overflow was
reported as an ordinary socket fault, and the field count had no bound at all,
since the parser caps total header bytes and not how many fields fit inside them.

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
protocol, hostname, port, resolver-returned address set, and selected pinned
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

Chain trust is the socket's own `authorized` verdict, passed through without
reinterpretation. A TLS verifier exposes a single verification error even when
several faults coexist, so the codes are ambiguous by construction: the committed
`expired` test leaf reports `CERT_HAS_EXPIRED` whether or not the CA that signed it
is trusted. Discounting such "validity-only" codes as still-trusted therefore
reported expired-and-untrusted chains as trusted (`LINK-zgmixagu`). The validity axis
stays independent regardless, because it is recomputed from the leaf's own
notBefore/notAfter against the observation instant, and `trustErrorCode` records the
fault the verifier stopped at. Read the consequence correctly: an expired certificate
carries both the `expired` and the `untrusted` defect, since a verifier that halted at
expiry did not go on to check the rest of the chain.

`TlsObservationOutcome.status` is `observed`, `blocked`, or `incomplete`.
`blocked` is reserved for transport-policy refusal (a prohibited pinned address);
DNS, connection, handshake, certificate-analysis, timeout, and cancellation
failures are `incomplete` with a typed cause. A TLS failure is never a safety
claim. `notBefore` is a validity start, **not** reliable issuance age.
