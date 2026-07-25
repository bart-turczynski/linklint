# Locale-dependent case mapping as a URL attack surface

Issue: `LINK-aiakfzwy`

Research spike. Audits whether linklint is exposed to the locale-tailored case
mapping bug class (the "Turkish-I problem"), and decides whether linklint should
*detect* it in the URLs it inspects.

Filed after a real defect in the sibling `rurl` project (`RURL-ugfpuotu`), where
an R case-normalization step inherited the ambient locale and rewrote hostnames
under `LANG=tr_TR.UTF-8`.

## Decision

Three outcomes, in descending confidence:

1. **linklint's own pipeline is clean, and now stays clean by construction.**
   No source file applies a locale-tailored case mapping to a host, scheme, or
   any other identity-bearing string. A drift-lock test enforces this.
2. **One real locale-dependence defect existed and is fixed**: reason ordering
   went through `String.prototype.localeCompare`, so equal-weight reasons came
   out in a different order on a `cs`/`sk`/`az`/`lt`/`lv`/`th` machine than on an
   `en-US` one. That contradicted the documented determinism guarantee.
3. **A detector for the "manufacture a confusable by case-mapping" direction is
   NOT worth building; a detector for the opposite direction is.** The reasoning
   is in [§4](#4-should-linklint-detect-this) and the gap it closes is in
   [§5](#5-the-u0130-gap-closed-by-locale_case_ambiguity--brand_locale_collapse).
   **Shipped** as `locale_case_ambiguity` / `brand_locale_collapse`
   (`LINK-ynsgmybj`).

## 1. The mechanism

Unicode case mapping is locale-tailored (`SpecialCasing.txt`). Verified on Node
with full ICU:

| Input  | Default (`toLowerCase`) | `tr` / `az`  | `lt`     |
|--------|-------------------------|--------------|----------|
| `I`    | `i`                     | **`ı`** (U+0131) | `i`  |
| `İ`    | `i` + U+0307            | **`i`**      | `i` + U+0307 |
| `WIKI` | `wiki`                  | **`wıkı`**   | `wiki`   |
| `FILE` | `file`                  | **`fıle`**   | `file`   |

And upward: `"i".toLocaleUpperCase("tr")` is `İ` (U+0130), not `I`.

So a case-normalization step that inherits the ambient locale can silently turn
`WIKI.example.com` into `wıkı.example.com` — a **different registrable domain**.
It is a security problem rather than an i18n nit for three reasons:

- It **manufactures a confusable after validation**. The dangerous pair is
  created by our own normalizer, not supplied by the attacker — a
  validate-then-transform TOCTOU.
- It is **client-state-dependent**. The same input behaves differently on a
  Turkish user's machine than on the analyst's, so it evades reproduction and
  will not appear in any corpus.
- It is a **known CVE class** elsewhere: Java `toLowerCase()` without
  `Locale.ROOT`, .NET culture-sensitive `ToLower()`, and the Spring/Android
  security-filter bypasses built on both.

## 2. Audit: does linklint case-normalize in a locale-sensitive way?

**No.** JavaScript is structurally safer here than R, Java, or .NET:
`String.prototype.toLowerCase` is defined by ECMA-262 against the Unicode
Default Case Conversion algorithm with **no locale tailoring**. It is the
`toLocale*` variants that read the ambient locale. This matches the WHATWG URL
Standard, which specifies *ASCII lowercase* — not a Unicode lowercase — for
scheme and host.

Sweep of `packages/core/src`:

| API | Occurrences | Verdict |
|-----|-------------|---------|
| `toLowerCase` / `toUpperCase` | ~45 (host, scheme, TLD, param keys, labels) | Safe — locale-independent by spec |
| `toLocaleLowerCase` / `toLocaleUpperCase` | 0 | — |
| `Intl.Collator` | 0 | — |
| `localeCompare` | 3 | **Defect — see §3** |

IDNA is delegated to the vetted `tr46` package (`FR-LIB-1`: do not hand-roll
IDNA), which implements UTS-46 case folding from the IDNA mapping table. That
table is not locale-tailored, so the `toAscii`/`toUnicode` path in
`unicode/idna.ts` carries no ambient-locale dependence either.

`packages/core/test/locale-independence.test.ts` re-runs this sweep on every CI
run and fails on reintroduction. It matches the *call* shape (`.localeCompare(`)
rather than the bare identifier, so prose about these APIs stays allowed.

## 3. The defect found: locale-dependent reason ordering

`result.reasons` is sorted by descending weight, then ascending reason code. The
tie-break used `a.code.localeCompare(b.code)` with **no locale argument**, which
resolves against the ambient ICU locale. Because many reason codes are
informational (weight 0), equal-weight ties are the common case, not a corner
case.

Measured across the 53 registered reason codes, sorting diverged from the
`en-US` order under **`az`, `cs`, `lt`, `lv`, `sk`, and `th`** — for example
`az` swapped `embedded_domain_in_subdomain` and `excessive_subdomain_depth`, and
`cs`/`sk` swapped `scheme_denied` and `separator_lookalike`.

That breaks the determinism the project advertises throughout
[`architecture.md`](architecture.md): the same input on the same version
produced a different `reasons` array depending on who ran it. It would surface
as unreproducible golden-file and snapshot diffs, and as noise in any consumer
that diffs linklint output across machines.

**Fix.** A single shared comparator, `compareReasons` in
`schema/reason-codes.ts`, now backs all three call sites (`schema/serialize.ts`
×2, `inspect-async.ts` ×1). Reason codes are ASCII `[a-z0-9_]` identifiers, so a
codepoint comparison is both correct and fully locale-independent. Scores,
severities, and the reason *set* are unchanged; only the tie-break order is now
machine-independent.

## 4. Should linklint detect this?

Two directions, and they are not symmetric.

### D1 — manufacture (`I` → `ı`): covered where it matters, not detectable at the input

A victim's client lowercases `WIKI.com` under a Turkish locale and reaches
`wıkı.com`, which the attacker has registered.

A detector on the *input* is not viable. The trigger would be "host contains
`I`" — which fires on essentially every uppercase host, including
`HTTPS://EXAMPLE.COM`. The signal-to-noise ratio is fatal.

But the *product* of the mapping is already covered. U+0131 has a UTS-39
confusable mapping (`ı → i`), so linklint's skeleton folds `wıkı` to `wiki` and
`homograph_latin_skeleton` fires:

```
https://wıkı.com/   score 1.0   homograph_latin_skeleton(1), idn_host(0.7),
                                confusable_char(0), normalization_delta(0)
```

The domain an attacker must actually register to exploit D1 is scored 1.0. That
is the right place for the coverage to sit.

### D2 — collapse (`İ` → `i`): the sharp direction, and it is a real gap

The reverse mapping is the dangerous one, because it is the *validator* that
gets confused rather than the victim's resolver:

1. A checker validates `https://tİktok.com/`. Running under an ambient Turkish
   locale it lowercases the host to `tiktok.com` — a plain-ASCII **exact brand
   match**, with no non-ASCII left to be suspicious of. Allowlist hit. Approved.
2. The requester applies UTS-46, as the URL Standard requires, and resolves
   `xn--tiktok-qyd.com` — the attacker's domain.

This is precisely the Java `toLowerCase()` allowlist-bypass shape, and the
trigger set is small and enumerable — it turned out to be exactly two host forms
(§5) rather than "every host with an `I`". That makes it a viable detector,
unlike D1.

Its natural home is alongside `idna_mapping_ambiguity`, which already implements
exactly this shape one axis over: it flags hosts that *different IDNA standards*
map differently. D2 is the same validate-then-transform split keyed on **locale**
instead of standard.

**Built** as `LINK-ynsgmybj` — see §5 for what it does and why nothing existing
could cover it.

## 5. The U+0130 gap, closed by `locale_case_ambiguity` / `brand_locale_collapse`

Answering the spike's question about whether the confusables corpus carries the
`i`/`ı`/`İ` family as a case-derived pair: **it carries `ı` but not `İ`, and the
omission is upstream, not ours.**

`packages/core/src/data/confusables.generated.ts` is curated from UTS-39
`confusables.txt` by `tools/build-confusables.mjs`, which keeps rows whose
source is a non-ASCII Letter/Mark/Number and whose target is all-ASCII
alphanumeric. `[0x131, "i", ...]` survives that filter.

U+0130 does not survive it — because it is not in the source data at all.
Verified against Unicode 16.0.0 `confusables.txt`: **neither U+0130 nor U+0307
appears anywhere in the file, as a source or as a target.** UTS-39 simply has no
mapping for the dotted capital I. So no amount of re-curation fixes this, and no
confusable-derived detector can fire on it:

```
skeleton("wıkı")   -> "wiki"     collides with the brand
skeleton("tİktok") -> "tİktok"   no collision — U+0307 survives, stays non-ASCII
```

`homograph_latin_skeleton` requires the skeleton to be *entirely* ASCII, so the
surviving combining dot suppresses it. Consequently:

```
https://tİktok.com/   score 0.7   idn_host(0.7), normalization_delta(0)   (before)
```

`tİktok.com` scored identically to a legitimate IDN such as `münchen.de`, and
carried no brand-impersonation signal at all. Note also that UTS-46 does *not*
neutralize the distinction before the registrable-domain comparison — it maps
`İ` to `i` + U+0307 and punycodes the result, preserving a domain that the
tailored mapping collapses to plain ASCII.

Because the gap is unreachable from UTS-39, it needs a bespoke detector rather
than a data fix. That is what shipped.

### What shipped

`packages/core/src/detectors/locale-case-collapse.ts` — one detector emitting two
codes, strongest first:

| Code | Weight | Fires when |
|------|--------|-----------|
| `brand_locale_collapse` | 0.5 | the collapsed form equals a watchlist brand domain **exactly** |
| `locale_case_ambiguity` | 0 | it collapses to pure ASCII, but not onto a brand |

```text
https://tİktok.com/     0.85  brand_locale_collapse(0.5), idn_host(0.7), normalization_delta(0)
https://İstanbul.com/   0.70  idn_host(0.7), locale_case_ambiguity(0), normalization_delta(0)
```

Design points worth keeping:

- **Trigger set is exactly two host forms**, both collapsing to `i`: U+0130 (İ)
  and `I` + U+0307 (the SpecialCasing `After_I` rule — the decomposed spelling of
  the same thing). An exhaustive sweep of every codepoint in Unicode confirms
  U+0130 is the **only** one whose tailored lowercase is pure ASCII while its
  default lowercase is not. Lithuanian never collapses: its tailoring only *adds*
  combining dots.
- **The tr/az mapping is hand-rolled, not `toLocaleLowerCase("tr")`.** Two
  reasons: `toLocaleLowerCase` reads ICU data, so behavior varies with the
  runtime's ICU build (`small-icu` Node, browsers, workers) — a detector that
  silently stops firing on some runtimes is worse than none; and it keeps the
  drift-lock in §2 unconditional. A test asserts the hand-rolled mapping agrees
  with the platform tailoring wherever ICU is available.
- **It reads the RAW host, not `registrableDomain`.** The latter has already been
  default-lowercased, which turns `I` + U+0307 into `i` + U+0307 and destroys the
  `After_I` context before the detector can see it. A tr-locale validator
  lowercases the URL as written, so that is what must be modeled.
- **Informational unless it lands on a brand.** `İstanbul` is ordinary Turkish
  orthography and `İ`-bearing IDNs are legitimately registrable, so the base
  signal must never raise severity on its own (SC-2). The exact-brand escalation
  is the same evidentiary bar as `homograph_skeleton_collision`, hence the same
  weight. This shipped the brand escalation for the locale axis first; the IDNA
  axis followed the same pattern in `brand_idna_collapse` (`LINK-vpajgxxm`).
- **The ACE form does not fire.** `xn--tiktok-qyd.com` is already pure ASCII, so
  no case-normalizer can collapse it; presenting punycode carries no locale
  hazard.

## 6. Prior art consulted

- **UTS #46** §4 (Processing) — the IDNA mapping table, and its non-tailored
  case folding.
- **UTS #39** (Security Mechanisms) — confusable detection and the `MA` table;
  the source of the U+0130 omission documented in §5.
- **Unicode `SpecialCasing.txt`** — the `tr`/`az`/`lt` conditional mappings.
- **WHATWG URL Standard** — *ASCII lowercase* for scheme and host, deliberately
  not a Unicode lowercase.
- **ECMA-262** `String.prototype.toLowerCase` — Unicode Default Case Conversion,
  no tailoring; the reason JS is structurally safer here than R/Java/.NET.
- `rurl` `RURL-ugfpuotu` / commit `bea7316` — the originating defect, including
  the empirical trap that `stringi`'s `locale="root"`/`"und"` do **not** override
  an ambient locale.
