# Bounded redirect and declarative-refresh resolution

- **Status:** implemented
- **Issue:** `LINK-hvirrwxa` (L1)
- **Public export:** `@linklint/online/resolution`

The redirect-chain enricher expands caller-authorized HTTP redirects and
declarative refreshes without granting ambient network authority. It uses the
L0 safe transport for every connection, retains one transport session across
the chain, and returns structured resolution outcomes for `inspectAsync()`.

## Use

```ts
import { inspectAsync } from "linklint";
import { createRedirectChainEnricher } from "@linklint/online/resolution";
import { createNodeSafeTransport } from "@linklint/online/transport";

const transport = createNodeSafeTransport();
const enricher = createRedirectChainEnricher({
  transport,
  async authorize(request) {
    const approved = await applicationConsentFor(request);
    return approved
      ? { kind: "destination-fetch", url: request.url }
      : null;
  },
});

const result = await inspectAsync("https://example.com/start", {
  enrichers: [enricher],
});
```

Construction is not consent. `authorize()` is called for the initial URL and
again for every HTTP redirect, HTTP Refresh, or HTML meta-refresh target. The
callback receives the exact canonical request URL, hop number, GET/HEAD method,
transition reason, and prior URL. Returning `null` stops before DNS or network
I/O. A returned authorization is still checked for an exact URL match by L0.

## Chain behavior

- Requests are `GET` by default or caller-selected `HEAD`. There is no request
  body, body replay, cookie jar, automatic redirect mode, or JavaScript
  execution.
- Only 301, 302, 303, 307, and 308 are expanded. `Location` may be relative and
  is resolved against the observed response URL. Missing, empty, ambiguous,
  non-HTTP(S), overlong, or malformed targets stop as `invalid-target`.
- Opaque shorteners are ordinary redirects. The adapter does not guess their
  destinations or call a shortener/vendor decoding service.
- Redirect fragments are removed before authorization and fetch because they
  are not sent in an HTTP request. Loop identity uses that canonical request URL.
- Every chain URL is synchronously re-inspected by core before its authorization
  decision and fetch. Evidence retains a compact offline inspection projection.
- One L0 session spans the whole chain, preserving cumulative transport hop,
  encoded-byte, decompressed-byte, and elapsed-time budgets. L1 also enforces a
  default ten-request chain cap, with a hard maximum of 32.

## Declarative refresh policy

HTTP `Refresh` and HTML `<meta http-equiv="refresh">` use the same eligibility
policy:

| Limit | Default | Hard maximum / behavior |
| --- | ---: | --- |
| Decoded response bytes | 64 KiB | 1 MiB |
| Delay | 5,000 ms | 60,000 ms; the adapter records but never sleeps the delay |
| MIME | `text/html`, `application/xhtml+xml` | Other/missing types are not parsed |
| Charset | UTF-8/UTF8, US-ASCII, ISO-8859-1/Latin-1, Windows-1252 | Other declared charsets stop explicitly |

An HTTP Refresh header is considered before a meta element. A `HEAD` request may
follow an eligible HTTP Refresh header but never scans a response body for meta
elements. The bounded meta scanner ignores comments and raw-text script, style,
textarea, and title contents; JavaScript navigation, CAPTCHA interaction, and
browser execution remain out of scope.

Policy and parse stops are explicit: `refresh-body-too-large`,
`refresh-mime-unsupported`, `refresh-charset-unsupported`,
`refresh-delay-exceeded`, and `invalid-refresh`. A refresh with no URL targets
the current document and is therefore reported through the normal loop stop.

`refresh-body-too-large` and `refresh-mime-unsupported` stop the chain as
**skipped**, not failed: the scan budget bounds one optional sub-observation, so
exceeding it says nothing about whether the hops resolved. A chain whose every
hop returned a response therefore reports no `failure` outcome. Raising the limit
is not an alternative — measured on 2026-07-28, 4 of 10 real landing pages exceed
the 64 KiB default and one exceeds the 1 MiB hard ceiling, so any fixed cap is
exceeded by some real page and the outcome type has to stay honest when it is.

## Outcomes and scoring

Each completed request emits an ordered `resolution.chain-hop` artifact with its
timestamp, response status, transition, L0 address/pinning evidence, byte use,
and offline inspection projection. Authorization refusal, L0 blocking,
transport incompleteness, loops, hop exhaustion, and invalid targets remain
separate skipped/failure outcomes with machine-readable causes. A source may
therefore appear in both `checksRun` and `checksSkipped` after partial progress.

All hop evidence is retained, but only the highest-scoring fetched hop projects
findings into the top-level verdict. Each reason code is projected at most once,
and codes already present on the original offline result are not projected
again. This makes the chain's worst observed hop visible without multiplying
the same lexical evidence merely because it appeared at several redirects.

### HTTPS → HTTP downgrade (`https_downgrade_observed`)

A hop fetched over `https:` that hands the chain an `http:` target raises the
informational (weight 0) `https_downgrade_observed` finding, with a
`resolution.https-downgrade` evidence record on the hop that **issued** the
transition. All three transition kinds are covered — HTTP redirect, `Refresh`
header, and `<meta http-equiv="refresh">` — because each arrives at the same
place in the chain loop.

The discriminator is the **transition**, never a single hop's scheme. An
`http://` input at hop 1 is an ordinary plaintext origin, not a downgrade;
neither is an `http:`→`https:` upgrade or an `https:`→`https:` hop. An
`https → http → https` bounce reports once, at the hop that downgraded, and the
rest of the chain is unaffected.

The finding is keyed on the transition rather than on the target hop's fetch, so
a chain cut short after the downgrade — hop cap, denied authorization, transport
failure — still reports the plaintext target it was directed to.

**The chain is never stopped, and there is no option to stop it.** Refusing the
downgraded hop would buy no confidentiality: L0 sends no request body, no cookie
jar and no credentials, and strips the caller's `Referer`, so the plaintext
request discloses only the URL the server itself just named. It would cost
detection, because a refused hop is never fetched and the worst-hop projection,
the open-redirect correlation and the MIME evidence all read fetched hops only.

The finding carries **weight 0** and that is not a placeholder. A downgrade is
not deceptive under §1.1 — the chain plainly says `http://` and no two readers
disagree about what it says. It is reported because the fourth rule is *report
what you can determine, never silently pass*, not because it makes the URL a lie.

## Privacy disclosure (Layer 2 sources)

Layer 2 adds two network-touching resolution sources and one purely local one.
This section states, per source id, exactly what leaves the machine so callers
can reason about egress before enabling a source.

| Source id | Network egress | What is sent |
| --- | --- | --- |
| `redirect-chain.http` | Caller-authorized HTTP(S) to the destination | One request per chain hop, each separately authorized via `authorize()`. Requests are `GET` or caller-selected `HEAD` with no body, no cookie jar, and no credentials. L0 strips ambient credential and `Referer` headers; only `Host`, `Accept`, `Accept-Encoding`, and `User-Agent` are sent. Fragments are removed before the request. |
| `divergence-probe.http` | Caller-authorized HTTP(S) to the destination | One request per bounded variant (default three: baseline, a fixed synthetic desktop `User-Agent`, and a synthetic same-origin `Referer`), each separately authorized. Same header discipline as above — L0 strips ambient credential and caller-supplied `Referer` headers. The alternate `User-Agent` is a fixed benign string, never derived from ambient request state. The only `Referer` ever sent is the probed URL's own origin root (`https://host/`), computed from the destination and re-validated as same-origin by L0's dedicated channel, so no private or user-derived referrer can be disclosed. |
| `embedded-wrapper.local` | None | Nothing leaves the machine. Trusted wrapper formats (Microsoft Safe Links, Proofpoint URL Defense v1/v2/v3) are decoded purely and locally; no network call, no shortener/vendor decode service, and no DNS. |

Construction is never consent for the two `*.http` sources: each hop and each
variant is authorized individually, and returning `null` from `authorize()`
stops before any DNS or network I/O. `embedded-wrapper.local` performs no I/O at
all and is safe to run with no network authority.
