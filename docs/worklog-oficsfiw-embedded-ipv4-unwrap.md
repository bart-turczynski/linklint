# LINK-oficsfiw — S1 embedded-IPv4 unwrap (low-32 wrapper forms)

> **Historical worklog.** Written against the state of the tree at
> `a412476` (2026-07-25), the commit that shipped `LINK-oficsfiw`. It records
> HOW the decision was reached; the description of current behavior is
> `packages/core/src/detectors/ip-classification.ts`, `src/parse/ip.ts` and
> `docs/reason-codes.md`. Claims here are anchored on symbol and date rather
> than on line number, because line-number citations in the sibling worklogs
> rotted within weeks.
>
> **Re-checked 2026-08-25 and still true of the shipped code**: every behavioral
> claim below was re-probed through `inspect()` — `[fe80::1.2.3.4]` emits
> `ip_link_local`, `[::ffff:808:808]` scores `0`, `[2001:db8::1.2.3.4]` scores
> `0.4` on `ip_obfuscation` alone, and `[64:ff9b::]` / `[::ffff:0:0]` both emit
> `ip_reserved`.

Scope executed: the three prefixes that put the IPv4 in the **low 32 bits** only
— `::ffff:0:0/96`, `::/96`, `64:ff9b::/96`. 6to4, Teredo, the RFC 6052
network-specific prefixes and `64:ff9b:1::/48` were left alone (out of scope by
instruction; all four place the address somewhere other than the low 32 bits).
Corpus rows pin that boundary so a later slice cannot silently widen it.

## Judgment calls

### 1. `embeddedIpv4` became purely bit-derived, not textual-OR-bit

The defect was spelling-dependence, so a hybrid (keep the textual match, add a
bit match) would have left residual spelling-dependence exactly where the traps
warn about it: `::0.0.0.1` would keep unwrapping to `0.0.0.1` → `ip_reserved`
while its identical twin `::1` stayed `ip_loopback`. Reading only the bits makes
both `ip_loopback`.

Two consequences, both improvements, neither test-pinned before:

- `fe80::1.2.3.4` now emits `ip_link_local`. It previously emitted nothing: the
  textual rule set `embeddedIpv4 = "1.2.3.4"`, `classifyHost` took the embedded
  branch, found no v4 bucket, and **returned early**, swallowing the link-local
  verdict. `classifyHost` now falls through to `classifyIpv6` instead of
  returning, so a wrapper can never suppress a verdict the literal would earn.
- `2001:db8::1.2.3.4` loses the `(embeds IPv4 1.2.3.4)` clause from its
  `ip_obfuscation` detail. `ip-obfuscation.ts` was not to be touched and reads
  `embeddedIpv4` directly; under the new meaning of that field (an IPv4 behind a
  *transition prefix*) `2001:db8::` does not wrap anything. Score unchanged.

### 2. Wrapping an IPv4 is no longer treated as obfuscation

`analyzeIpv6` computed `obfuscated = embeddedIpv4 !== null || host !== canonical`.
The first clause was **dead code** under the textual rule — a dotted-quad tail
can never equal a canonical form that contains no dots, so the second clause
already covered every case. Under the bit rule it stops being dead and starts
firing on canonical hex spellings, which would have made `[::ffff:808:808]`
(NAT64/mapped 8.8.8.8, an entirely ordinary address) score 0.4 — contradicting
the required negative control. Dropped the clause: it is a no-op for every input
that reached it before.

The resulting split is the honest one. `obfuscated` answers "is this written
non-canonically"; `embeddedIpv4` answers "where does it actually point". A
wrapper redirects, it does not disguise.

### 3. `embeddedIpv4Via` added to `Ipv6Analysis` (and `embeddedVia` to `IpClassification`)

Trap 9 asks the detail to name the mechanism, which needs the wrapper identity
to travel from the parser to the detector. Deriving it in the detector from the
canonical string instead was rejected as unsound: `::ffff:1` is the canonical
form of the **v4-compatible** address 255.255.0.1, and a `startsWith("::ffff:")`
test would mislabel it IPv4-mapped. The alternative — a second exported function
re-parsing the host — buys nothing but a duplicate parse.

Cost: the `analyzeIpv6("::ffff:127.0.0.1")` pin in `ip.test.ts` gained one
property. All three asserted values are byte-identical; only the new key was
added. The `embeddedIpv4: null` pins were untouched (the key is absent, not
`undefined`, when there is no wrapper).

## Deliberate non-change

`64:ff9b::` and `::ffff:0:0` (the bare prefixes, low-32 = 0) now unwrap to
`0.0.0.0` → `ip_reserved`. The 0/1 exclusion is scoped to `::/96` only, per
instruction, because there it is load-bearing (`::`/`::1`). For the other two
prefixes 0.0.0.0 is a correct and harmless verdict — online already blocked
`::ffff:0:0/96` as `ip_reserved`, and `64:ff9b::` merely moves from one blocked
category (`transition`) to another. Not test-pinned either way.
