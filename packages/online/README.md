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
