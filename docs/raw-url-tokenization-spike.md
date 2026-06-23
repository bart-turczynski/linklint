# Raw URL tokenization spike

Issue: `LINK-upnumplv`

## Decision

A single raw tokenization pass is viable, but it should be introduced as parser
infrastructure first and wired in small behavior-preserving slices. It should not
replace `parseRawParts()` and `authorityRegion()` in one change.

The current split is defensible: `parseRawParts()` validates enough structure to
produce `RawParts`, while `authorityRegion()` deliberately keeps suspicious raw
syntax so structural scans can explain malformed inputs. The risk is that both
modules independently rediscover the same scheme, authority, path, and fragment
boundaries. That leaves linklint exposed to internal parser drift: a future fix
can update one view and accidentally leave structural scans looking at a
different URL region.

The safer target is a shared tokenizer that records raw spans and delimiter facts
without validating the host. Validated parsing and structural scans should derive
their existing views from those tokens.

## Current split

`packages/core/src/parse/raw-parts.ts`:

- Trims via `prepare()` upstream and recognizes scheme-like prefixes.
- Treats `host:port` without a scheme as a bare host, not a scheme.
- Handles opaque schemes such as `javascript:` and `data:`.
- Special-cases hostless local `file:` forms so `file:/path` and
  `file:///path` remain parseable and reach the `dangerous_scheme` detector.
- Validates the final host token and returns `null` for malformed inputs.
- Extracts `path`, `query`, and `fragment` for parsed-context detectors.

`packages/core/src/parse/authority-region.ts`:

- Repeats scheme detection and authority splitting using shared syntax helpers.
- Keeps raw separator runs of `/` and `\`.
- Keeps an authority token even when it contains whitespace, backslashes,
  multiple ports, or other syntax that parsed URL construction may reject.
- Separates path and fragment for structural detectors, but does not build a
  full parsed `RawParts` shape.

The split exists because structural scans must run before parsing. Inputs such as
`http:\\google.com`, `http://127.0.0.1:11211:80/`, and `http:///google.com`
should be invalid or unresolvable, but they should still explain themselves with
`ambiguous_authority` rather than collapsing to a bare `parse_error`.

## Proposed tokenizer

Add a raw tokenizer with no host validation and no normalization:

```ts
interface RawUrlTokens {
  prepared: string;
  scheme: string | null;
  schemeSeparator: ":" | null;
  opaque: boolean;
  protocolRelative: boolean;
  authorityIntroducer: string;
  authority: string;
  remainder: string;
  path: string;
  query: string | null;
  fragment: string | null;
}
```

The tokenizer should answer only "what was written and where are the raw
delimiters?" It should not decide whether a host is valid, whether a bracketed
literal is valid IPv6, or whether a URL is safe. Those decisions stay in
`parseRawParts()` and detectors.

Derived views:

- `AuthorityRegion` becomes a projection from `RawUrlTokens`.
- `RawParts` becomes a validated projection from `RawUrlTokens`.
- `inspect()` can compute tokens once after `prepare(input)` and pass the
  `AuthorityRegion` projection to structural scans.
- `parse()` can eventually accept already-tokenized input to avoid tokenizing the
  same prepared string twice, but that should be a later cleanup.

## Edge cases to pin

These cases should have regression tests before any migration:

- Hostless `file:`:
  - `file:/etc/passwd` stays parseable with `scheme: "file"`, empty host, and
    path `/etc/passwd`.
  - `file:///etc/passwd` stays parseable with empty authority and path
    `/etc/passwd`.
  - `file://localhost/etc/passwd` keeps `localhost` as the host.
  - `file:// /etc/passwd` stays invalid.
- Opaque schemes:
  - `javascript:alert(1)` and `data:text/html,<script>` remain opaque and do
    not produce authority findings.
  - `mailto:a@b.com` remains opaque for structural authority scans.
- Bare host and host-port:
  - `example.com`, `example.com:8080/x`, and `google.com:8080/x` do not become
    schemes.
  - Unknown `scheme:`-looking strings keep the existing behavior.
- Query and fragment extraction:
  - `https://example.com/a?x=1#frag` preserves path `/a`, query `x=1`, and
    fragment `frag`.
  - `http://google.com#@evil.com/` still exposes a fragment beginning with `@`
    to `ambiguous_authority`.
  - Query text must not be mistaken for authority or path when structural scans
    only need the authority region.
- Ambiguous authority:
  - Multiple userinfo: `http://foo@evil.com:80@google.com/`.
  - Fragment authority confusion: `http://google.com#@evil.com/`.
  - Whitespace in authority:
    `http://foo@127.0.0.1 @google.com:11211/`.
  - Multiple ports: `http://127.0.0.1:11211:80/`.
  - Backslash separator: `http:\\google.com`.
  - Backslash in authority: `http://good.com\@evil.com`.
  - Slash confusion: `http:///google.com`, `http://///evil.com`, and
    `http://target.com/////evil.com`.
  - Protocol-relative `//evil.com` keeps the current invalid-with-reason shape.
- Separator lookalikes:
  - Dot lookalikes in the authority still flag, e.g. `http://paypal。com`.
  - Slash lookalikes in the authority still flag, e.g.
    `https://paypal.com／x@evil.com`.
  - Lookalikes in path/query stay ignored by `separator_lookalike`.
- Malformed inputs:
  - Empty input, whitespace-only input, `ht!tp://%%%not a url`, `http://`,
    `http:// space.com`, `<<<>>>`, `@@@`, and `http://exa mple.com` preserve
    current invalid behavior and never throw.

## Migration plan

1. Add `parse/raw-tokens.ts` plus direct parity tests against a table of the edge
   cases above. No production wiring.
2. Reimplement `authorityRegion()` as a projection from raw tokens. Keep its
   public shape unchanged and run all structural detector tests.
3. Reimplement `parseRawParts()` as a validated projection from raw tokens. Keep
   `parse()` behavior unchanged and run parser, detector, corpus, CLI, and MCP
   tests.
4. Only after those slices are green, consider changing `inspect()`/`parse()` to
   share one tokenization result per inspection. That is a cleanup, not the first
   implementation step.

## Risks and constraints

- Do not collapse validation into tokenization. Structural scans depend on seeing
  malformed raw syntax that validation would reject.
- Do not widen URL acceptance while migrating. A tokenizer can expose spans for
  malformed input, but the parsed result must stay `invalid` unless an existing
  parse path already accepts it.
- Do not remove `AuthorityRegion` immediately. It is a useful detector-facing
  contract and keeps structural scans decoupled from a larger token object.
- Treat the migration as security-sensitive. Each slice needs targeted regression
  tests plus the normal `pnpm check` gate.
