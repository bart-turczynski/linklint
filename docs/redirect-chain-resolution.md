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
