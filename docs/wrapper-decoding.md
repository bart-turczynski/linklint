# Local embedded-wrapper decoding

- **Status:** implemented
- **Issue:** `LINK-ehhmrblq` (L2)
- **Public export:** `@linklint/online/resolution`
- **Format catalog:** `2026-07-17`

The embedded-wrapper decoder recovers only destinations that are already
present in a trusted wrapper URL. It is synchronous, deterministic, and local:
it performs no DNS, HTTP, vendor API, credential discovery, or telemetry call.
Opaque services such as `bit.ly`, `t.co`, and `lnkd.in` are not decoded here;
they remain ordinary redirect-chain work through L0.

## Use

Decode one local wrapper hop:

```ts
import { decodeEmbeddedWrapper } from "@linklint/online/resolution";

const decoded = decodeEmbeddedWrapper(
  "https://nam01.safelinks.protection.outlook.com/" +
    "?url=https%3A%2F%2Fexample.com%2F",
);
```

Or compose bounded nested decoding into `inspectAsync()`:

```ts
import { inspectAsync } from "linklint";
import { createEmbeddedWrapperEnricher } from "@linklint/online/resolution";

const result = await inspectAsync(input, {
  enrichers: [createEmbeddedWrapperEnricher()],
});
```

The factory accepts explicit `inspectOptions` for decoded targets. Callers that
use non-default Layer 1 policy or agent options should pass the same intended
settings here; the core enricher context deliberately does not expose ambient
caller configuration.

## Pinned formats

All formats require `https:`, no userinfo, no explicit port, and an exact
trusted host. Host suffix lookalikes and deeper subdomains do not match.

| Format | Exact local grammar |
| --- | --- |
| Microsoft Safe Links standard (`standard-2026-07`) | Exactly one DNS label below `safelinks.protection.outlook.com`, root path `/`, no fragment, and exactly one `url` query parameter. The value is form/percent-decoded exactly once. |
| Proofpoint URL Defense v1 | Exact host `urldefense.proofpoint.com` or `urldefense.com`, path `/v1/url`, exactly one `u` value and one `k` marker. The `u` value is percent-decoded once (preserving `+`) and common/numeric HTML entities are unescaped. |
| Proofpoint URL Defense v2 | Either exact Proofpoint host, path `/v2/url`, exactly one `u` value and a `d` or `c` marker. The pinned v2 transform maps `-` to `%`, `_` to `/`, percent-decodes once, then unescapes common/numeric HTML entities. |
| Proofpoint URL Defense v3.0.1 | Either exact Proofpoint host and `/v3/__<template>__;<replacement-bytes>!<tracking>$`. Replacement bytes are canonical base64url UTF-8; `*` consumes one character and `**<run-code>` consumes the pinned 2–65-character run. Every replacement character must be consumed exactly. |

Microsoft documents the standard regional Safe Links prefix and wrapped URL
behavior in its [Safe Links overview](https://learn.microsoft.com/defender-office-365/safe-links-about).
Proofpoint documents v1/v2/v3 examples and decoded targets in its
[URL Decoder API reference](https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/URL_Decoder_API)
and publishes the local v3.0.1 utility from its
[rewritten-URL guidance](https://help.proofpoint.com/Threat_Insight_Dashboard/Concepts/How_do_I_decode_a_rewritten_URL%3F).
Those references identify the grammar; this implementation never calls the
decoder API.

## Bounds and outcomes

`decodeEmbeddedWrapper()` is a total one-hop boundary:

- `decoded` returns the exact locally recovered destination plus vendor,
  format, and pinned format version;
- `not-wrapper` means the host is outside the exact local catalog and is not a
  safety claim;
- `unsupported` means a trusted wrapper host used a scheme, path, or version
  outside the pinned catalog; and
- `malformed` distinguishes invalid grammar, an invalid decoded absolute URL,
  and the decoded-length limit.

The default destination/wrapper length bound is 16,384 characters. Invalid
length configuration retains that safe default, and caller values are capped at
1 MiB.

`createEmbeddedWrapperEnricher()` decodes at most four nested wrappers by
default and enforces a hard maximum of eight even if a caller requests more.
Every recovered target is synchronously re-inspected by core before the next
wrapper is considered. Each successful hop emits a `wrapper.decode` artifact
whose subject is the decoded target and whose payload includes the compact
offline inspection projection. Its Layer 1 findings are also projected through
the normal structured outcome path, so target-scoped suppression and scoring
remain honest.

An ordinary non-wrapper produces `no-hit`. Unsupported formats and cancellation
produce `skipped`; malformed input, invalid decoded URLs, length exhaustion, and
depth exhaustion produce `failure`. A chain may therefore appear in both
`checksRun` and `checksSkipped` when earlier hops completed before a later
coverage failure.
