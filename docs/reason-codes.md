# Reason codes

> Version-pinned with the weights table (`docs/scoring.md`). Every verdict from
> `inspect()` carries reason codes from this registry — never a bare boolean
> (PRD Principle 1). The registry source of truth is
> `packages/core/src/schema/reason-codes.ts`.

Each reason is `{ code, layer, detail, weight }`. The `weight` is attached by the
core from the version-pinned table; detectors never supply their own weight.

## Informational codes (weight 0)

These **annotate** but never raise severity. They exist so legitimate IDNs are
explained, not flagged (PRD Principle 5, FR-D-15/16, SC-1a/SC-2). A result whose
only reasons are informational is **benign** (`score: 0`, `severity: "info"`).

### `normalization_delta` — FR-D-1

- **Meaning:** the host differs from its normalized / ACE (punycode) form.
- **Why it's a signal:** any internationalized domain triggers it by definition,
  so on its own it means only "this host uses non-ASCII." It becomes meaningful
  **in combination** with a scoring detector (e.g. `mixed_script`).
- **Example:** `bücher.de` is an IDN; its ASCII/punycode form is `xn--bcher-kva.de`.
  Benign alone — every IDN trips this, so it carries no suspicion by itself.
- **Scoring:** informational, weight 0.

### `confusable_char` — FR-D-2

- **Meaning:** one or more characters in the **host** are confusable with
  characters from another script (per the curated confusables set).
- **Why it's a signal:** annotation only. Scoring a single-script whole-label
  homograph needs a brand/skeleton index (roadmap), so raw confusable annotation
  must not score or legitimate IDNs would be penalized.
- **Example:** Cyrillic `а` (U+0430) where Latin `a` (U+0061) is expected.
- **Scoring:** informational, weight 0. Expanded per-character in `confusables[]`.

### `confusable_in_path` — FR-D-12

- **Meaning:** as `confusable_char`, but for the **path / query** components.
- **Why it's a signal:** annotation only, same reasoning as `confusable_char`.
- **Example:** a Cyrillic letter inside `/раy/`.
- **Scoring:** informational, weight 0. Expanded per-character in `confusables[]`.

### `idna_mapping_ambiguity` — Epic J (J9)

- **Meaning:** the host maps to a **different ASCII domain depending on the IDNA
  standard** applied — so the component that validates the URL and the one that
  resolves it can reach different sites (Tsai, _Abusing IDNA Standard_). Distinct
  from `confusable_char` (visual similarity): this is **resolver disagreement**.
- **Detection:** the host is run through `tr46` in both modes — transitional
  (≈ IDNA2003) and non-transitional (UTS-46/IDNA2008). Two groups fire:
  - **Group A — deviation chars** (ß, ς, ZWJ, ZWNJ): the two ASCII forms differ.
    `wordpreß.com` → `wordpress.com` (IDNA2003) vs `xn--wordpre-6va.com` (UTS-46).
  - **Group B — compatibility folds** (fullwidth / circled Latin): the host folds
    entirely to ASCII with no punycode. `ｇｏｏｇｌｅ.com` → `google.com`.
- **Why informational (weight 0):** a lone ß is a legitimate German IDN (`baß.de`
  is registrable), so the base signal must not raise severity (SC-2). The
  escalation is `brand_idna_collapse`, below — that is where the value is.
  (Resolves the brainstorm's OQ-J9b.)
- **Which group escalates:** only **Group A**. There the two standards reach
  *different* domains, so an IDNA2003 validator can read a brand while the
  request lands elsewhere. Group B is the opposite shape — both standards fold
  `ｇｏｏｇｌｅ.com` to the *real* `google.com`, so the request reaches the genuine
  site and there is nothing to score.
- **Scoring:** informational, weight 0.

### `locale_case_ambiguity` — `LINK-ynsgmybj`

- **Meaning:** the host carries a character that a **Turkish/Azeri lowercase
  erases into a plain ASCII letter**, so a component that case-normalizes with an
  ambient locale reads a *different, fully ASCII* domain than the one the request
  reaches. Same validate-then-transform shape as `idna_mapping_ambiguity`, but
  keyed on the ambient **locale** rather than on the IDNA standard.
- **Detection:** the host is lowercased under an explicit `tr`/`az` tailoring and
  the result compared against its UTS-46 ASCII form. It fires only when the
  tailored form is **entirely ASCII** and differs from what the resolver reaches:

  ```text
  https://İstanbul.com/
    tr/az lowercase (a validator):  istanbul.com
    UTS-46 (the resolver):          xn--stanbul-1cb.com
  ```

- **Trigger set:** exactly two host forms, both collapsing to `i` —
  **U+0130 (İ)** and **`I` + U+0307** (the SpecialCasing `After_I` rule, the
  decomposed spelling of the same thing). An exhaustive codepoint sweep confirms
  U+0130 is the *only* codepoint in Unicode whose tailored lowercase is pure
  ASCII while its default lowercase is not. Lithuanian never collapses — its
  tailoring only *adds* combining dots.
- **Why informational (weight 0):** `İ` is ordinary Turkish orthography
  (`İstanbul` is a real word) and `İ`-bearing IDNs are legitimately registrable,
  so the base signal must not raise severity (SC-2). The escalation is
  `brand_locale_collapse`, below — that is where the value is.
- **Why the opposite direction is absent:** the mirror case (`WIKI.com` under a
  Turkish lowercase becoming the attacker's `wıkı.com`) is deliberately not
  detected here. A detector on the input would trigger on "host contains `I`",
  firing on essentially every uppercase host — and it needs none, because U+0131
  (ı) *is* in the UTS#39 table, so the domain an attacker must register already
  scores 1.0 via `homograph_latin_skeleton`.
- **See also:** [`locale-case-mapping.md`](locale-case-mapping.md) for the full
  audit, the D1/D2 direction analysis, and the UTS#39 gap that makes a
  confusable-based detector impossible here (neither U+0130 nor U+0307 appears
  anywhere in `confusables.txt`).
- **Example:** `https://İstanbul.com/`, `https://İnbox.com/`.
- **Scoring:** informational, weight 0.

## Scoring codes

These contribute to the risk score via probabilistic OR (`docs/scoring.md`).

### `mixed_script` — FR-D-3 · weight 1.0 (blocker)

- **Meaning:** a single host label mixes characters from more than one script
  (e.g. Latin + Cyrillic in one label).
- **Why it's a signal:** the cross-script de-noiser. Legitimate IDNs are
  single-script; mixing scripts within a label is the hallmark of a homograph
  attack. This is the code that actually scores confusable-based deception.
- **Example:** `pаypal.com` where `а` is Cyrillic (label mixes Latin + Cyrillic).

### `ascii_homoglyph` — Epic J (J4) · weight 0.2

- **Meaning:** a host label uses **same-script (ASCII) digit look-alikes for
  letters** — `g00gle`, `paypa1`, `micr0soft`. The general, brand-free counterpart
  to `mixed_script` / `confusable_char`, which only fire when two *different*
  scripts mix and so never see an all-ASCII disguise.
- **Why it's a signal:** a low-weight structural anomaly. A digit standing in for
  the letter it resembles, inside an otherwise alphabetic word, is rare in
  legitimate hosts.
- **Detection & precision (SC-2):** a label flags only when it is pure ASCII
  alphanumeric (length ≥ 5), its first character is a letter (a leading digit
  reads as an obvious number — `1password`, `0day`), every digit is one of the
  unambiguous letter-shaped digits `0`→o / `1`→l / `5`→s (any other digit
  disqualifies the whole label, so `s3`, `web3`, `route53`, `i18n`, `bet365`,
  `blink182` never flag), and letters outnumber those digits. The detail surfaces
  the readable skeleton (`g00gle` → `google`).
- **Out of scope:** letter-multigraph confusions (`rn`→m, `vv`→w) are **not**
  handled here — generically they fire on ordinary words (`modern`, `return`,
  `savvy`) and can only be told apart from an attack by distance to a known brand.
  That, and the scoring escalation when a skeleton equals a real brand, belong to
  the brand-aware layer (Epic G). This base signal stays `low` so a lone
  digit-in-word matters only in combination.
- **Example:** `https://g00gle.com` (reads as `google`); `https://paypa1.com`.

### `brand_homoglyph` — Epic G (G2) · weight 0.5

- **Meaning:** the **registrable domain folds, via ASCII digit look-alikes, to
  exactly a known brand domain.** Folding `0`→o, `1`→l, `5`→s turns `paypa1.com`
  into `paypal.com` and `g00gle.com` into `google.com`. The folded skeleton
  matches a watchlist brand **byte-for-byte**, which makes this the
  highest-confidence brand-impersonation signal linklint emits.
- **Why it's a signal:** this is the **brand-aware escalation** that the J4
  `ascii_homoglyph` layer anticipates. `ascii_homoglyph` is the general,
  brand-free structural anomaly (a digit standing in for a letter, low weight);
  when that same skeleton resolves to an actual brand, the input is almost
  certainly a deliberate impersonation, so it escalates here at a higher weight.
  An input firing both `ascii_homoglyph` and `brand_homoglyph` (e.g. `g00gle.com`)
  is the canonical high-severity look-alike.
- **Detection & precision (SC-2):** the **full registrable domain string** is
  folded with the shared `ASCII_DIGIT_HOMOGLYPHS` map (`data/ascii-confusables.ts`,
  the single source of truth J4 also consumes). Fires only when at least one digit
  is actually folded, the skeleton is alphabetic, and the skeleton equals a
  watchlist brand domain exactly. The exact-match requirement is itself the
  precision backstop — a degenerate mostly-digit string cannot fold into a brand,
  and only `0/1/5` fold (so `s3`, `bet365`, `route53` never reach a brand). The
  real brand itself never fires.
- **Brand list:** the authoritative Epic G watchlist (`BRAND_DOMAINS`),
  version-pinned via `dataVersions.brands`.
- **See also:** `ascii_homoglyph` (J4) — the low-weight, brand-free counterpart;
  `brand_homoglyph` is its brand-confirmed escalation.
- **Example:** `https://paypa1.com` (→ `paypal.com`); `https://g00gle.com`
  (→ `google.com`); `https://revo1ut.com` (→ `revolut.com`).
- **Scoring:** scoring, weight 0.5 (provisional — G5 re-tunes).

### `brand_lookalike` — Epic G (G2) · weight 0.4

- **Meaning:** the **registrable domain is a fuzzy near-miss of a known brand
  domain** — one (occasionally two) transposition-aware edit operations away,
  where the difference is *not* a clean digit fold. This is dnstwist's permutation
  logic run in reverse: rather than generating typo variants of a brand and
  checking the registry, we take the input and ask whether it is a typosquat of a
  watchlisted brand.
- **Why it's a signal:** `gogole.com`, `microsoftt.com`, `paypal.co` (TLD swap)
  all read as a trusted brand at a glance but resolve to an attacker-controlled
  domain. A domain landing one edit away from a major brand is a deliberate
  look-alike far more often than chance.
- **Detection & precision (SC-2):** the **full registrable domain string**
  (label + public suffix) is compared with a bounded Damerau-Levenshtein (OSA)
  distance against each brand domain in the watchlist (`data/brands.ts`).
  Comparing the full string — not the bare label — is deliberate: TLD-swap
  typosquats (`paypal.co` for `paypal.com`) are real positives only visible with
  the suffix included.
  - A clean digit fold to a real brand is reported as `brand_homoglyph`
    instead (the two codes are mutually exclusive per input).
  - **Exact match never fires** — distance 0 is the real brand.
  - A length guard contains short-domain collisions: distance 1 fires only when
    the matched brand's significant (registrable) label is ≥ 5 characters;
    distance 2 only when it is ≥ 8. So `visa.com`↔`vista.com` and
    `ups.com`↔`usp.com` stay clean here, while `paypal`/`microsoft`-scale brands
    flag.
  - **Non-ASCII (IDN) hosts are skipped** — they belong to the confusable /
    `idna_mapping_ambiguity` detectors, and the all-ASCII watchlist cannot be a
    genuine near-miss of a Unicode domain.
  - IP hosts and inputs with no registrable domain are skipped.
  The detail names the **nearest** brand and the exact distance.
- **Brand list:** the authoritative Epic G watchlist (`BRAND_DOMAINS`),
  version-pinned via `dataVersions.brands`.
- **See also:** `brand_homoglyph` (G2) — the exact-skeleton-fold sibling, higher
  confidence and higher weight.
- **Example:** `https://gogole.com` (distance 1 from `google.com`);
  `https://microsoftt.com`; `https://paypal.co`.
- **Scoring:** scoring, weight 0.4 (provisional — G5 re-tunes).

### `homograph_skeleton_collision` — Epic E (E3) · weight 0.5

- **Meaning:** the **registrable domain's UTS#39 confusable skeleton equals a
  known brand domain exactly.** An all-Cyrillic `сһаѕе.com` — where every letter
  is a Cyrillic homoglyph of the Latin one — reads as `chase.com` to a human but
  is a different, attacker-controlled domain. Its `skeleton()` (each codepoint
  mapped through the confusables table, NFD-normalized) collapses to `chase.com`,
  colliding with a watchlist brand.
- **Why it's a signal:** this is the one documented v1 *detection* hole
  (FR-D-16). A single-script, all-confusable look-alike has **no script mixing**,
  so `mixed_script` never fires, and confusable annotation (`confusable_char`) is
  weight-0 — the homograph would otherwise score nothing. FR-D-16 deferred
  scoring it because penalizing raw confusables would flag every legitimate IDN
  (the SC-2 failure mode); scoring only an **exact skeleton collision against the
  brand watchlist** is the precise signal that became possible once the Epic G
  watchlist existed.
- **Detection & precision (SC-2):** the **full registrable domain string**,
  **canonicalized to its Unicode form first** so a punycode presentation of the
  same host attributes the same brand, is run through the UTS#39 `skeleton()`
  helper (`unicode/skeleton.ts`, built from the already-pinned confusables table)
  and tested for an exact match against the precomputed skeleton of each
  `BRAND_DOMAINS` entry.
  - **Non-ASCII only** — the detector runs solely when the registrable domain
    carries a non-ASCII codepoint **after that decode**. The pure-ASCII digit-fold case (`paypa1.com`)
    is owned by `brand_homoglyph`; this guard makes the two **mutually exclusive
    by construction**, so they never double-fire.
  - **Exact brand never fires** — a real brand domain is all-ASCII and is guarded
    out before any collision test.
  - **Legitimate single-script IDNs** (`пример.com`, `münchen.de`) skeletonize to
    a non-brand string and do not collide — SC-2 holds.
  - IP hosts and inputs with no registrable domain are skipped.
  The detail names the matched brand and the colliding skeleton.
- **Brand list:** the authoritative Epic G watchlist (`BRAND_DOMAINS`),
  version-pinned via `dataVersions.brands`. The skeleton algorithm's only data
  source is the confusables table, pinned via `dataVersions.unicodeConfusables`.
- **See also:** `brand_homoglyph` (G2) — the pure-ASCII digit-fold sibling, same
  weight; `confusable_char` (FR-D-2) — the weight-0 annotation this escalates
  when the skeleton lands on a brand.
- **Example:** `https://сһаѕе.com` (→ `chase.com`); `https://ехреԁіа.com`
  (→ `expedia.com`).
- **Scoring:** scoring, weight 0.5 (provisional — re-tuned with the brand family).

### `brand_locale_collapse` — `LINK-ynsgmybj` · weight 0.5

- **Meaning:** the registrable domain **collapses to exactly a watchlist brand
  domain under a Turkish/Azeri lowercase**, while UTS-46 — and therefore the
  actual request — resolves it somewhere else:

  ```text
  https://tİktok.com/
    validator, ambient tr locale:  tiktok.com          <- exact brand match
    resolver, UTS-46 (mandatory):  xn--tiktok-qyd.com  <- the attacker
  ```

- **Why it's a signal:** nothing non-ASCII survives the validator's view, so
  every downstream "is this an IDN?" heuristic sees a clean ASCII brand and waves
  it through. An allowlist keyed on the normalized host matches the brand; the
  request still reaches a different domain. This is the same bug class as the
  Java `toLowerCase()` / .NET `ToLower()` allowlist-bypass CVEs, and it is
  **client-state-dependent** — it only manifests where the validator's ambient
  locale is `tr` or `az`, so it evades reproduction on the analyst's machine.
- **Why UTS#39 cannot catch it:** neither U+0130 nor U+0307 appears anywhere in
  Unicode `confusables.txt`, so `skeleton("tİktok")` keeps the combining dot,
  stays non-ASCII, and fails `homograph_latin_skeleton`'s all-ASCII requirement.
  The gap is upstream in UTS#39, not in linklint's curation — re-curating the
  table cannot close it. See [`locale-case-mapping.md`](locale-case-mapping.md).
- **Detection & precision (SC-2):** the escalation of `locale_case_ambiguity`.
  The collapsed form must equal a `BRAND_DOMAINS` entry **exactly, byte for
  byte** — the same evidentiary bar as `homograph_skeleton_collision`, hence the
  same weight. The two codes are mutually exclusive per input: a collapse onto a
  brand reports here, everything else falls back to the weight-0 annotation.
- **Brand list:** the Epic G watchlist (`BRAND_DOMAINS`), version-pinned via
  `dataVersions.brands`.
- **See also:** `locale_case_ambiguity` — the weight-0 annotation this escalates;
  `homograph_skeleton_collision` (E3) — the skeleton-keyed sibling at the same
  weight; `idna_mapping_ambiguity` (J9) — the same validate-then-transform shape
  keyed on IDNA standard instead of locale, whose parallel escalation is
  `brand_idna_collapse`.
- **Example:** `https://tİktok.com/` (→ `tiktok.com`).
- **Scoring:** scoring, weight 0.5.

### `brand_idna_collapse` — `LINK-vpajgxxm` · weight 0.5

- **Meaning:** the host maps to **exactly a watchlist brand domain under
  IDNA2003**, while UTS-46/IDNA2008 — and therefore the actual request —
  resolves it somewhere else:

  ```text
  https://wordpreß.com/
    validator, IDNA2003:           wordpress.com          <- exact brand match
    resolver, UTS-46 (mandatory):  xn--wordpre-6va.com    <- the attacker
  ```

- **Why it's a signal:** the same validate-then-transform split as
  `brand_locale_collapse`, keyed on the **IDNA standard** rather than the ambient
  locale. A validator still running transitional processing sees a clean ASCII
  brand and waves it through; the resolver, which must use UTS-46, reaches the
  attacker's punycode domain. It is **stack-dependent** rather than
  client-state-dependent — it manifests wherever some component in the chain
  predates UTS-46.
- **Deviation routes:** both Group A routes reach it — `ß`→`ss`
  (`wordpreß.com` → `wordpress.com`) and dropped ZWJ/ZWNJ (`g<ZWJ>oogle.com` →
  `google.com` vs `xn--google-pf0c.com`).
- **Detection & precision (SC-2):** the escalation of `idna_mapping_ambiguity`.
  The **registrable domain** of the IDNA2003 form must equal a `BRAND_DOMAINS`
  entry **exactly, byte for byte** — the same evidentiary bar as
  `homograph_skeleton_collision` and `brand_locale_collapse`, hence the same
  weight. Comparing on the registrable domain means a subdomain
  (`login.wordpreß.com`) escalates too, since a validator checking the eTLD+1
  still reads the brand. The two codes are mutually exclusive per input.
  - **Group B does not escalate** — both standards fold to the real brand, so
    the request reaches the genuine site (guarded by corpus and unit tests).
  - **IDNA2003-accepted / UTS-46-rejected does not escalate** — the resolver
    rejects the host outright, so no attacker domain is ever reached.
- **Brand list:** the Epic G watchlist (`BRAND_DOMAINS`), version-pinned via
  `dataVersions.brands`.
- **See also:** `idna_mapping_ambiguity` (J9) — the weight-0 annotation this
  escalates; `brand_locale_collapse` — the locale-axis sibling at the same
  weight, same shape; `homograph_skeleton_collision` (E3) — the skeleton-keyed
  sibling.
- **Example:** `https://wordpreß.com/` (→ `wordpress.com`).
- **Scoring:** scoring, weight 0.5.

### `homograph_latin_skeleton` — weight 1.0 (blocker)

- **Meaning:** the **target-less sibling** of `homograph_skeleton_collision`. A
  non-ASCII registrable domain whose UTS#39 confusable skeleton is **pure
  ASCII-Latin** — every character folds to a Latin look-alike, so the whole host
  reads to a human as an ASCII domain — with **no brand list needed**. An
  all-Cyrillic `сһаѕе.com` skeletonizes to `chase.com`; `ехямрӏе.com` to
  `example.com`. Either way the host is Unicode masquerading as Latin.
- **Why it's a signal:** "pure unicode that looks like ASCII" has no legitimate
  use. Where `homograph_skeleton_collision` requires the skeleton to land on a
  watchlist brand, this fires on *any* pure-Latin skeleton, catching look-alikes
  of non-brand strings too.
- **Detection & precision:** the **full registrable domain**, first
  **canonicalized to its Unicode form** so punycode and Unicode presentations are
  treated identically (`xn--80ak6aa92e.com` and `аррӏе.com` are the same host and
  score the same), is run through `skeleton()` (`unicode/skeleton.ts`); the
  detector fires only when the result contains **no non-ASCII codepoint**.
  - **Non-ASCII only**, and skips the NFKC compatibility-fold family (owned by
    `idna_mapping_ambiguity`) — same guards as the collision sibling.
  - **Legitimate IDNs are excluded by construction:** a genuine non-Latin word
    always contains at least one character with no Latin confusable, so its
    skeleton keeps a non-ASCII codepoint and never folds to pure ASCII
    (`пример`→`пpимep`, `россия`→`poccия`, `κόσμος`→`κóoμoς`, `日本語`→`日本語`).
  - **Residual:** a short genuine word built only from the Latin-confusable
    subset (Cyrillic `сор`→`cop`) still folds to ASCII — but such a host is
    visually identical to its Latin reading and is exactly the "looks like ASCII"
    case the block targets. A legitimate owner overrides via `suppressReasons`
    (`[{ code: "homograph_latin_skeleton", host: "сор.com" }]`) — **not** via the
    IDN allow-list, which is scoped to `idn_host` alone and leaves this weight-1.0
    blocker standing. That scoping is deliberate: an IDN exemption must never be
    derivable from the host's ASCII reading, because "the Unicode host reads as a
    legitimate ASCII domain" *is* the homograph signature.
- **See also:** `homograph_skeleton_collision` — the brand-targeted sibling
  (weight 0.5); the two **stack** on a brand homograph (this blocks, the
  collision adds brand attribution).
- **Example:** `https://сһаѕе.com` (all-Cyrillic, → `chase.com`).
- **Scoring:** scoring, **weight 1.0 (blocker)** — saturates the score to
  critical regardless of context.

### `idn_host` — weight 0.7 (policy-gated, default block)

- **Meaning:** the registrable domain is an **internationalized domain name** —
  it carries a non-ASCII label, whether written in Unicode (`münchen.de`) or
  punycode (`xn--mnchen-3ya.de`).
- **Why it's blocked by default:** for a Western-market audience a
  Unicode/punycode domain is almost always accidental, so IDNs are **blocked by
  default** (`idnPolicy: "block"`). The weight lands the verdict at `high` —
  enough to fail the default `--fail-on high` gate (an effective block) — while
  `critical` stays reserved for the unambiguous homograph/script attacks.
- **Gating (a scoring signal, not a weight-0 policy channel):**
  - `idnPolicy: "allow"` suppresses it entirely (the historical, IDN-agnostic
    verdict) — for deployments that legitimately serve IDNs.
  - `idnAllowlist: ["münchen.de", …]` exempts specific registrable domains even
    under `"block"` (compared in Unicode form, so a punycode input matches too).
- **Scope & precision:**
  - Scoped to the **registrable domain** (canonicalized to Unicode), so an ASCII
    domain with a Unicode *path* is unaffected (`confusable_in_path`'s territory).
  - A **malformed** `xn--` label is owned by `punycode_malformed`, not this — they
    never double-flag.
  - The dangerous IDN subset (script-mixing, all-Latin-confusable homographs) is
    already `critical` via `mixed_script` / `homograph_latin_skeleton` regardless;
    `idn_host` simply stacks there and adds the `high` block for genuine IDNs.
  - IP / hostless inputs and pure-ASCII hosts never fire.
- **Example:** `https://münchen.de` → `high` (blocked) by default;
  `inspect(url, { idnPolicy: "allow" })` → `info`.
- **Scoring:** scoring, weight 0.7 (lands `high`).

### `brand_soundsquat` — Epic G (T2, Addendum §4) · weight 0.3

- **Meaning:** the **registrable label is a phonetic homophone of a watchlist
  brand** — it *sounds* like the brand read aloud, even though it is neither an
  edit-distance near-miss nor a digit/confusable fold. `netflicks.com`
  (→ netflix), `dropboks.com` (→ dropbox), `spotifi.com` (→ spotify).
- **Why it's a signal:** soundsquatting (IDEAS-ADDENDUM §4) trades on the *sound*
  of a brand. `netflicks` and `dropboks` read as the brand to a human but are
  **invisible to edit distance** — `ck`→`k` plus `x`→`ks` is two raw edits over a
  7-character label, below G2's distance-2 length gate, so `brand_lookalike` /
  `brand_homoglyph` flag nothing. This detector fills exactly that recall hole.
- **Detection & precision (SC-2):** both the input label and each brand label are
  normalized to a small **phonetic key** via an ordered, static substitution map
  of homophone digraphs/phonemes (`ph`→`f`, `ck`→`k`, `x`→`ks`, `oo`→`u`,
  `y`→`i`, `z`→`s`, hard `c`/`ch`→`k`, silent `gh`→``, …) followed by collapsing
  runs of a repeated letter (`paypall`→`paypal`). It fires only on **whole-label
  phonetic-key equality** against a brand — never a loose substring.
  - **Pure-ASCII registrable label only** — non-ASCII hosts belong to the
    confusable / `homograph_skeleton_collision` (E3) detectors.
  - **Exact brand never fires** — a watchlist brand domain (or a label equal to a
    brand label) is the brand, not a homophone of it.
  - **Short-label guard** — the input label, the matched brand label, **and** the
    resulting phonetic key must each be ≥ 5 characters. Short, key-degenerate
    brands (`x`, `ups`, `dhl`, `ibm`, `n26`, `hsbc`, `dpd`, `wise`, `box`,
    `meta`, `visa`, `cash`) can never collide — short keys are where phonetic
    folding manufactures spurious matches. Phonetic matching is FP-prone, so this
    detector is deliberately conservative.
  - IP hosts and inputs with no registrable domain are skipped.
  The detail names the matched brand and the shared sound key.
- **Lexicon:** a small static homophone-substitution map inline in the detector —
  an intrinsic micro-lexicon (same judgment as the ASCII-confusables table and
  the `bait_tokens` word list), **not** version-pinned via `dataVersions`.
- **See also:** `brand_lookalike` (G2) — the edit-distance sibling this
  complements (soundsquats slip past it); `brand_homoglyph` (G2) — the
  digit-fold sibling. All carry distinct codes and may stack when both apply.
- **Example:** `https://netflicks.com` (→ `netflix.com`); `https://dropboks.com`
  (→ `dropbox.com`).
- **Scoring:** scoring, weight 0.3 — below `brand_lookalike` (0.4) because
  phonetic-key matching is lossier than bounded edit distance, above the low
  band (a whole-label sound-key match against a real brand is a deliberate
  soundsquat far more often than chance). Provisional — re-tuned with the brand
  family.

### `brand_bitsquat` — Epic G (T3, Addendum §4) · weight 0.15

- **Meaning:** the **registrable label is a single-bit-flip neighbor of a
  watchlist brand label** — the bitsquatting / memory-error attack class.
  Flipping one bit of one ASCII byte of a brand label yields the input label.
  `netfliz.com` (netfli**x** → netfli**z**: the byte `x`=0x78 with bit 1 flipped
  is `z`=0x7a), `amazgn.com` (amaz**o**n → amaz**g**n) of `amazon`.
- **Why it's a signal:** bitsquatting (IDEAS-ADDENDUM §4) exploits hardware/
  transmission bit-errors — a flaky DIMM, a cosmic ray, a bad hop flips one bit of
  a brand domain a client meant to resolve, and an attacker who registered that
  one-bit-off domain silently receives the traffic. It is a real but **niche**
  attack: an offline completeness item that **names the specific attack class**
  (and the exact byte/bit) the fuzzy edit-distance check cannot.
- **Detection & precision (SC-2):** every valid single-bit-flip neighbor of every
  watchlist brand label is **precomputed once** at module load into a
  neighbor→brand map; only neighbors whose flipped byte is still a valid DNS
  label character (`a-z`, `0-9`, `-`) are kept. At runtime the input label is an
  O(1) membership test — neighbors of the input are never generated.
  - **Pure-ASCII registrable label only** — non-ASCII hosts belong to the
    confusable / `homograph_skeleton_collision` (E3) detectors.
  - **Exact brand never fires** — a watchlist brand domain (or a label equal to a
    brand label) is the brand, not a bitsquat of it.
  - **Whole-label equality only** — the input label must equal a precomputed
    neighbor exactly; no substring matching.
  - **Short-label guard** — a brand label shorter than 5 characters contributes
    **no** neighbors and a short input label is rejected; short brands (`ups`,
    `dhl`, `box`, `ibm`, `n26`, `dpd`, `x`, `meta`, `visa`, `wise`, `cash`,
    `hsbc`) manufacture spurious 1-bit collisions.
  - **No-op flips excluded**, and a flip that lands on **another** real watchlist
    brand label is dropped (we never fire when the bit-flip is itself a different
    genuine brand). IP / host-less inputs are skipped.
- **Stacking:** a single bit flip is by construction also an edit-distance-1
  neighbor, so this code usually **stacks with `brand_lookalike`** (distinct
  codes); `brand_bitsquat` adds the named attack class and the byte/bit detail.
- **Lexicon:** the bit-flip enumeration is an **intrinsic algorithm** over the
  already-pinned brand watchlist (same judgment as the ASCII-confusables fold or
  the soundsquat key), **not** version-pinned via `dataVersions`.
- **See also:** `brand_lookalike` (G2) — the edit-distance sibling it stacks with;
  `brand_soundsquat` (T2) — the phonetic sibling. All carry distinct codes.
- **Example:** `https://netfliz.com` (→ `netflix.com`); `https://amazgn.com`
  (→ `amazon.com`).
- **Scoring:** scoring, weight 0.15 — intentionally LOW (the `risky_tld` /
  `bait_tokens` / `excessive_subdomain_depth` band): a bit-flip neighbor is a real
  but niche attack and is combination-only, never decisive standalone. Provisional
  — re-tuned with the brand family.

### `bait_tokens` — Epic G (G4) · weight 0.15

- **Meaning:** the host and path **stack multiple distinct phishing-bait
  keywords** — `secure`, `verify`, `account`, `update`, `signin`, `login`,
  `wallet`, `confirm`, `password`, `billing`, `suspended`, `unlock`,
  `authenticate`, `recover` and similar — e.g.
  `secure-account-verify-login.com`, `update-billing.example.tk/confirm/password`.
- **Why it's a signal:** phishing lures pile up reassuring/urgent credential
  words to look official. On its own this is **weak** — a deliberately
  **low-weight** corroborating signal that complements the G2/G3 brand-
  impersonation checks; it is never decisive alone.
- **Detection & precision (SC-2):**
  - Host labels are tokenized (split on `-` and the `.` label boundary) and the
    path/query is tokenized on common separators (`/ - _ .` …); the count of
    **distinct** bait keywords in each region is taken.
  - **A single bait token never fires.** Legitimate login/account pages carry
    one or two of these words routinely (`accounts.google.com/signin`, a bank's
    `/account/login`), so the bar is a **high density**, with host-side bait
    weighted more heavily than path-side (legit sites stack bait words in the
    PATH — `/account/security/signin` — but rarely in the HOST):
    - **≥ 2 distinct bait tokens in the HOST labels**, OR
    - **≥ 3 distinct bait tokens across host + path/query combined**.
  - IP hosts and host-less inputs are skipped. The detail reports the count and
    which bait tokens were found and where, so the score is explainable.
- **Lexicon:** a small static, hand-curated bait-keyword set inline in the
  detector — an intrinsic micro-lexicon (same judgment as the ASCII-confusables
  table), **not** version-pinned via `dataVersions`.
- **See also:** `brand_lookalike` / `brand_homoglyph` (G2) — the
  brand-impersonation checks this density signal corroborates.
- **Example:** `https://secure-account-verify-login.com`;
  `https://update-billing.example.tk/confirm/password`.
- **Scoring:** scoring, weight 0.15 (intentionally low — a weak corroborating
  signal; provisional — G5 re-tunes).

### `suspicious_extension` — Epic I (I1) · weight 0.5

- **Meaning:** the URL **path** ends in a **dangerous executable file extension**,
  or in a **deceptive double-extension** — the high-signal shape of a
  direct-download malware link.
- **Why it's a signal:** a link that ends in `setup.exe` or `update.apk` is a
  direct request to download and run an executable; a double-extension like
  `invoice.pdf.exe` shows a safe-looking `.pdf` to a skimming user while the real,
  trailing extension is the executable.
- **Detection & precision (SC-2):** only the **last path segment** (the filename
  after the final `/`) is inspected, and query/fragment are ignored. Two shapes
  fire:
  - **double extension** — ≥2 dot-separated extension parts after a non-empty
    stem and the LAST part is dangerous (`invoice.pdf.exe`, `report.doc.scr`);
  - **single dangerous extension** — the filename ends in one dangerous extension
    (`setup.exe`, `screensaver.scr`).
  A trailing-dot or extensionless segment, an empty path, or a bare `/` never
  fire, and an extension mid-path is ignored.
- **Dangerous set (case-insensitive):** the named class
  `.exe/.scr/.apk/.iso/.bat/.msi` plus conservative same-class additions
  (`cmd`, `com`, `vbs`, `jar`, `dmg`, `pkg`, `dll`, `msix`, `ps1`, `deb`). A
  `.zip` archive is **not** in the set — an archive download is ordinary and would
  over-flag.
- **Example:** `https://files.example.com/setup.exe`;
  `https://cdn.evil.io/invoice.pdf.exe`.
- **Scoring:** scoring, weight 0.5.

### `open_redirect_param` — Epic I (I2) · weight 0.4

- **Meaning:** a query parameter whose **name** is a known redirect parameter
  (`next`, `url`, `redirect`, `redirect_uri`, `redirect_url`, `dest`,
  `destination`, `return`, `returnUrl`, `continue`, `u`, `goto`, `target`) carries
  a **value that is itself a URL pointing to a different registrable domain** than
  the link host.
- **Why it's a signal:** `https://example.com/login?next=https://evil.com/phish`
  reads as `example.com`, but when the redirect fires the user lands on
  `evil.com`. The cross-host payload is the lexical fingerprint of an
  open-redirect lure.
- **Roadmap relocation (Phase 2 → Layer 1):** the PRD parks open-redirect under
  **Phase 2 (resolution)** because *confirming* an open redirect requires
  following it over the network. But the cross-host PAYLOAD inside the parameter
  is visible **without any network access** — a purely lexical signal — so the
  *detection* belongs in **Layer 1 (lexical)**. Phase 2 still owns the
  resolution-time confirmation of whether the redirect actually fires; this
  detector owns the offline payload detection.
- **Detection & precision (SC-2):** the value is bounded-decoded (seeing through
  single/double percent-encoding) and interpreted as a URL in two shapes:
  - **absolute URL** — scheme + host (`https://evil.com/...`);
  - **protocol-relative** — `//evil.com/...`, a classic payload that omits the
    scheme.

  Fires **only** when the decoded value resolves to a host whose registrable
  domain is non-null and **differs** (case-insensitively) from the link host's.
  A relative/same-host path (`?next=/dashboard`), a same-registrable-domain target
  (`?next=https://app.example.com/home`), a non-redirect param carrying a URL
  (`?ref=https://evil.com`), and a non-URL value (`?url=2`) all stay clean.
  Parsing is fully defensive — a junk value yields no finding and the detector
  never throws.
- **Example:** `https://example.com/login?next=https://evil.com/phish`;
  `https://example.com/?redirect=//evil.com`.
- **Scoring:** scoring, weight 0.4.

### `open_redirect_observed` — Epic L (L3) · resolution layer, weight 0

- **Meaning:** the Layer 2 resolution enricher (`@linklint/online` redirect
  chain) followed a caller-authorized redirect chain and OBSERVED it leave the
  input's registrable domain and land on the exact domain named by an
  `open_redirect_param` payload. It is the resolution-time confirmation the
  lexical detector deliberately leaves to Phase 2.
- **Why it's a signal:** the lexical `open_redirect_param` sees only the payload
  inside the parameter; it cannot know whether the server actually honors it.
  When the observed chain lands on that same registrable domain, the redirect is
  confirmed to fire — a distinct, additive evidence record.
- **Premise:** registrable-domain divergence, NOT full-origin comparison — the
  same premise `open_redirect_param` uses. The observed landing must be on a
  registrable domain that both differs from the input's and matches a decoded
  redirect-parameter payload target.
- **Not a proof of exploitability:** the record states the redirect was observed
  to fire off-site consistent with the payload, not that the open redirect is
  generally controllable by an attacker. Incomplete resolution (a chain cut short
  by a hop cap, transport failure, or denied authorization before reaching the
  payload domain) stays inconclusive and emits nothing.
- **Scoring:** informational, weight 0. It preserves the lexical
  `open_redirect_param` suspicion and NEVER adds a second probabilistic score for
  the same open redirect.

### `content_type_mismatch` — Epic L (L5) · resolution layer, weight 0

- **Meaning:** the Layer 2 resolution enricher (`@linklint/online` redirect
  chain) independently sniffed a resolved hop's response bytes (WHATWG MIME
  Sniffing) and found the byte-derived essence diverges from the declared
  `Content-Type`. Every classifiable hop records a `resolution.mime-evidence`
  record; this finding is raised only for the executable subset.
- **Why it's a signal:** a resource served with a benign declared type (e.g.
  `image/png`) whose bytes actually sniff to an executable type (`text/html` /
  `text/xml`) is the classic content-type-spoofing / MIME-confusion vector — a
  consumer that sniffs rather than trusts the header could execute markup the
  server labelled as inert.
- **Evidence vs. finding:** the mismatch is always recorded as evidence, but is
  marked `active` (and only then carries this finding) when the consuming context
  actually supports execution: `x-content-type-options: nosniff` is absent AND
  the computed essence is `text/html`/`text/xml` while the declared essence is
  neither. A mismatch under `nosniff`, or one that does not sniff to an
  executable type, stays evidence-only with `active: false`.
- **Incomplete classification:** hops that cannot be classified — a HEAD request
  or an empty body with nothing to sniff — record an explicit `status:
  "incomplete"` (`cause: "no-body"`) and emit no finding, so absence of a signal
  is never confused with a clean classification.
- **Scoring:** informational, weight 0, resolution layer. It corroborates a
  content-type spoofing observation without adding a probabilistic score, and is
  not proof of exploitation.

### `young_domain_brand_risk` — Epic M (M1b) · reputation layer, weight 0.5

- **Meaning:** the Layer 3 RDAP registration-age enricher (`@linklint/online`
  `@linklint/online/reputation`) resolved the ICANN registrable domain's
  registration event, computed its age, and found it **below the young-domain
  threshold** (default 90 days) **while the lexical result already carries a
  brand-impersonation signal** — `brand_homoglyph`, `brand_lookalike`,
  `homograph_skeleton_collision`, `homograph_latin_skeleton`, `brand_soundsquat`,
  `brand_bitsquat`, or `api_endpoint_impersonation`.
- **Why it's a signal:** a brand look-alike domain registered very recently is
  the dominant phishing-campaign pattern — a two-axis age × brand check that is
  far more specific than either axis alone.
- **Evidence vs. finding:** the RDAP record (registration/last-changed dates,
  registrar, nameservers, DNSSEC, redaction, computed age) is always emitted as
  a `rdap.domain` evidence artifact. This scored finding is raised **only** when
  the age is young AND a non-suppressed corroborating brand reason is present.
  Age, registrar, nameservers, and country alone stay evidence-only.
- **Shared-hosting safety:** age is computed on the registrable domain, so a
  phishing subdomain under an ancient shared-hosting parent inherits the parent's
  old age and never reads as young. Missing or redacted registration events stay
  unknown and never fabricate a young or old claim.
- **Non-duplication:** the finding uses this distinct reputation code and never
  re-emits the lexical brand reason, so corroboration does not double-count.
- **Scoring:** weight 0.5, reputation layer. It corroborates rather than proves;
  online evidence is additive and never replaces the lexical verdict.

### `malware_url_listed` — Epic M (M4b) · reputation layer, weight 1.0 (blocker)

- **Meaning:** the Layer 3 URLhaus mirror lookup (`@linklint/online/mirrors`)
  found the **exact inspected URL** in a caller-owned URLhaus snapshot, the record
  is currently listed **online**, and the snapshot is **within its declared
  freshness**. URLhaus curates direct malware-distribution URLs, so an exact match
  is authoritative, subject-tied evidence that this specific URL serves malware.
- **Why it's a signal:** unlike a lexical heuristic, an exact-URL match against a
  curated abuse feed is a confirmed listing of that URL — the strongest reputation
  signal linklint carries. Lookup happens against a local snapshot with **no
  network I/O at check time**.
- **Exact-URL only:** the URL is canonicalized (scheme/host lower-cased, IDN to
  A-label, default port dropped, fragment removed) and compared **exactly**,
  including path and query. The match is never broadened to the host, so a
  different path or query is a `no-hit` and a subdomain/parent is never a match —
  broadening cannot manufacture a finding.
- **Evidence vs. finding:** every match emits a `urlhaus.match` evidence artifact
  (record id, URL, status, threat, tags, dateAdded/lastOnline, snapshot time).
  The scored finding is raised **only** when the record is online AND the snapshot
  is fresh. An offline or expired record, or a stale/unknown-freshness snapshot,
  stays evidence-only.
- **Absence is not safety:** a miss is a completed `no-hit` against one feed at
  one time, never a clean-verdict claim. A missing, empty, or stale snapshot
  degrades to `skipped`/evidence, never to safe.
- **Scoring:** weight 1.0 (blocker), reputation layer. Online evidence is additive
  and extends — never replaces — the lexical verdict.

### `verified_phish_listed` — Epic M (M5b) · reputation layer, weight 1.0 (blocker)

- **Meaning:** the Layer 3 PhishTank mirror lookup (`@linklint/online/mirrors`)
  found the **exact inspected URL** in a caller-owned PhishTank *online-valid*
  snapshot, the record is **human-verified** AND currently **online**, and the
  snapshot is **within its declared freshness**. PhishTank verifies phishing URLs,
  so an exact match is authoritative, subject-tied evidence that this specific URL
  is a confirmed phishing page.
- **Why it's a signal:** like `malware_url_listed`, an exact-URL match against a
  human-verified abuse feed is a confirmed listing — the strongest reputation
  signal linklint carries. Lookup happens against a local snapshot with **no
  network I/O at check time**.
- **Exact-URL only:** the URL is canonicalized (scheme/host lower-cased, IDN to
  A-label, default port dropped, fragment removed) and compared **exactly**,
  including path and query. The match is never broadened to the host.
- **Evidence vs. finding:** every match emits a `phishtank.match` evidence artifact
  (phish id, URL, target/brand, verified, online, submission/verification times,
  snapshot time). The scored finding is raised **only** when the record is
  verified AND online AND the snapshot is fresh. An unverified, offline, removed
  (absent), or stale entry stays evidence-only.
- **Absence is not safety:** a miss — including a URL removed after a
  false-positive correction — is a completed `no-hit` against one feed at one
  time, never a clean-verdict claim. A missing or stale snapshot degrades to
  `skipped`/evidence, never to safe.
- **Scoring:** weight 1.0 (blocker), reputation layer. Online evidence is additive
  and extends — never replaces — the lexical verdict.

### `invisible_char` — FR-D-4 · weight 1.0 (blocker)

- **Meaning:** invisible, zero-width, or control characters appear anywhere in
  the URL (excluding bidi controls, which are reported as `bidi_override`).
- **Why it's a signal:** invisible characters hide differences between a
  deceptive host and a legitimate one.
- **Example:** `exa​mple.com` (zero-width space inside the host).

### `bidi_override` — FR-D-5 · weight 1.0 (blocker)

- **Meaning:** bidirectional / RTL override characters (U+202A–U+202E,
  U+2066–U+2069, U+061C, U+200E/U+200F) appear in the URL.
- **Why it's a signal:** bidi overrides visually reorder text — e.g. making a
  path appear to end in a safe extension.
- **Example:** a filename containing U+202E to flip `gpj.exe` to `exe.jpg`.

### `userinfo_present` — FR-D-6 · weight 0.5

- **Meaning:** the authority is hidden behind a userinfo segment (`user@host`).
- **Why it's a signal:** `https://paypal.com@evil.com` reads as PayPal but
  resolves to `evil.com`. The real host is surfaced in `parsed.effectiveHost`.
- **Example:** `https://paypal.com@evil.com/login` → real host `evil.com`.

### `ip_obfuscation` — FR-D-7 (+ J5) · weight 0.4

- **Meaning:** the host is an obfuscated IP address.
  - **IPv4** — decimal, octal, hex, or dotless form.
  - **IPv6 (J5)** — a non-canonical literal (leading zeros, uncompressed zero
    runs like `0::1` / `2001:db8:0:0:0:0:0:1`, or a dotted-quad tail such as
    `[::ffff:127.0.0.1]`, which is never the RFC 5952 spelling of its own bits).
    Pure case differences (`2001:DB8::1`) are tolerated (not a deception
    vector).
- **Why it's a signal:** obfuscated IPs evade human and naive string checks.
- **Detail:** renders the canonical form so the real destination is explained;
  for an IPv4-embedding IPv6 literal it also names the embedded IPv4. Canonical
  dotted-decimal IPv4 and canonical IPv6 literals (`[::1]`) are **not** flagged.
- **Not** flagged: wrapping an IPv4 in a transition prefix is not by itself
  obfuscation. `[::ffff:808:808]` is the exact canonical spelling of its bits
  and hides nothing; what a wrapper changes is *where the host points*, which
  the range buckets below report instead.
- **Example:** `http://2130706433/` (decimal for `127.0.0.1`);
  `https://[::ffff:127.0.0.1]/` (IPv6 literal embedding `127.0.0.1`).

### Literal-IP range buckets — V1a · weights 0.2 / 0.5

A literal-IP host is classified into **exactly one** range bucket, emitting one
code. The classifier runs on **all** IP-literal hosts — canonical or obfuscated
alike — and reuses the already-decoded canonical/embedded address (it does no IP
parsing of its own). IPv4-in-IPv6 embeddings (`::ffff:127.0.0.1`) are classified
by the **embedded IPv4** — the SSRF masquerade where a validator sees IPv6 while
the resolver reaches an internal v4 target.

Most-specific precedence (the first matching bucket wins):

```
ip_cloud_metadata > ip_loopback > ip_link_local > ip_private > ip_reserved
```

An ordinary **public** literal IP (`8.8.8.8`, `2001:db8::1`) matches no bucket
and emits nothing. The detail renders the canonical address so the real
destination is explained.

#### Where the ranges come from

The ranges are **not hand-maintained**. They are generated from the IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv)
and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv)
Special-Purpose Address Registries by `tools/build-ip-ranges.mjs` into
`data/ip-ranges.generated.ts`, version-pinned via `dataVersions.ipRanges`. Each
bucket's detail carries the registry's own name and RFC citation, so a verdict
is checkable against the RFC that defines the block:

```
host '10.0.0.1' resolves to a private (internal) address (10.0.0.1)
— IANA Private-Use, [RFC1918]
```

Matching is **longest-prefix**, not first-match, because the registry expresses
**exceptions inside a block**: `192.0.0.9/32` (PCP anycast) and `192.0.0.10/32`
(TURN anycast) are globally reachable carve-outs inside the non-global
`192.0.0.0/24`, and `2001:1::1/128` is one inside `2001::/23`. A flat range list
cannot represent that — it either loses the block or loses the exception.

Three classes sit deliberately outside the registry mapping:

- **Multicast** (`224.0.0.0/4`, `ff00::/8`) is registered in the separate IANA
  *Multicast Address Space* registries, so it is added as an explicit overlay —
  a registry-only table would silently lose it.
- **Documentation** prefixes (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`) earn **no bucket**. A
  documentation address is inert: not an SSRF target, and naming one is not
  deception.
- **Transition wrapper prefixes** (`::ffff:0:0/96`, `64:ff9b::/96`,
  `64:ff9b:1::/48`, `2001::/32`, `2002::/16`) earn **no bucket** either. They are
  routing envelopes, not destination classes — what matters is the IPv4 inside,
  which is handled below. Bucketing the envelope would flag
  `[64:ff9b::808:808]` (NAT64 doing its ordinary job for public `8.8.8.8`).

#### Transition wrappers: the embedded IPv4 is read from the bits

Three RFC transition prefixes carry an IPv4 in the **low 32 bits** of the IPv6
address, so recovering it is a plain read of the last two hextets:

| Prefix | Mechanism |
| --- | --- |
| `::ffff:0:0/96` | IPv4-mapped (RFC 4291 §2.5.5.2) |
| `::/96` | IPv4-compatible (RFC 4291 §2.5.5.1, deprecated — still parsed) |
| `64:ff9b::/96` | NAT64 well-known prefix (RFC 6052 §2.1) |

The address is recovered from the **decoded bits, never the spelling**. The same
128 bits therefore score the same whichever way they are written:
`[64:ff9b::169.254.169.254]` and `[64:ff9b::a9fe:a9fe]` both classify as
`ip_cloud_metadata`. The detail names the wrapper, so an IPv6 host producing an
IPv4 verdict reads as an explanation rather than a non-sequitur:

```
host '[64:ff9b::a9fe:a9fe]' resolves to the AWS instance-metadata endpoint
(SSRF target) (169.254.169.254, unwrapped from the NAT64 well-known prefix
64:ff9b::/96 (RFC 6052))
```

Two boundaries are deliberate:

- **`::1` and `::` are not wrappers.** Under a naive `::/96` rule they would
  unwrap to `0.0.0.1` and `0.0.0.0`; they are their own addresses, so low-32
  values `0` and `1` are excluded from the IPv4-compatible form and `[::1]`
  stays `ip_loopback`.
- **That exclusion is NOT extended to the NAT64 prefixes** (LINK-vwehpsdv).
  `[64:ff9b::]`, `[64:ff9b::1]` and `[64:ff9b:1::]` unwrap to `0.0.0.0` /
  `0.0.0.1` and report `ip_reserved` (low, 0.20). The carve-out above works
  because RFC 4291 gives `::` and `::1` a **competing assignment**, so excluding
  them *redirects* to a different verdict; the NAT64 prefixes have no competing
  assignment — their range rows carry `bucket: null` — so the same edit would
  *silence* all three to `info` 0.00 with zero reasons. Measured, not assumed:
  applying `excludeLow: [0, 1]` to the well-known row fails 5 tests with
  `score 0, expected > 0; severity info`. RFC 6052 §3.1 also forbids the
  well-known prefix from representing a non-global IPv4, which `0.0.0.0` is, so
  these are *prohibited* addresses and the strict reading keeps the flag. All
  three are pinned by corpus rows and by a mutation guard in
  `ip-classification.test.ts`.
- **A wrapper never manufactures a verdict.** `[64:ff9b::808:808]` is NAT64
  doing its ordinary job for public `8.8.8.8` — no bucket, no reason.

Four further transition mechanisms were evaluated (LINK-evooubiz). One is
unwrapped; the other three are declined, for reasons that differ per mechanism.

- **RFC 8215 local-use `64:ff9b:1::/48` — unwrapped, at its base `/96` only.**
  The whole /48 is reserved for translation and the embedded IPv4 is the
  *destination*, exactly as under the well-known prefix, so
  `[64:ff9b:1::a9fe:a9fe]` is `ip_cloud_metadata`. Only `64:ff9b:1::/96`
  matches. RFC 6052 also permits /48, /56 and /64 layouts inside that /48, and
  those put the IPv4 elsewhere — a blanket low-32 read of the whole /48 would
  decode a /64 deployment's all-zero suffix as `254.0.0.0`, inside `240/4`, and
  manufacture `ip_reserved`. Requiring hextets 2-5 to be exactly `1:0:0:0`
  excludes every such form.
- **6to4 `2002::/16` and Teredo `2001::/32` — not unwrapped, because the
  embedded IPv4 is not the destination.** 6to4's V4ADDR is the *encapsulating
  router*: a request to `[2002:a9fe:a9fe::1]` sends protocol-41 traffic to
  169.254.169.254, it does not make an HTTP request to it. Teredo carries two
  candidates — a *server* after the prefix and a bit-complemented *client* at
  the tail — and neither is unambiguously the target. Unwrapping either would
  assert something false about where the request goes. Both mechanisms are also
  deprecated (RFC 7526, RFC 8190).
- **RFC 6052 network-specific prefixes — not unwrapped, because they cannot be
  recognized.** They are drawn from operator address space and have no registry,
  so unwrapping one means speculatively decoding *every* IPv6 address at all six
  permitted prefix lengths. Measured over 20 000 random addresses, that hands a
  spurious bucket to **59.2%** of them; enforcing the reserved u-byte at octet 8,
  which must be zero, cuts it to **14.0%**. The residue is almost entirely the
  `/96` layout, which has no u-byte to check and reads the low 32 bits directly —
  so the u-byte is what makes the *other* five lengths tractable, not what rules
  them out. Against a `precision === 1` corpus gate, 14% is disqualifying.

#### Declined: a malformed-6to4 anomaly code (LINK-gxwyxkyg)

A **narrower and weaker** follow-up to the 6to4 decline above was evaluated
separately and is also declined. It is recorded here because the two are easy to
confuse, and because the argument that kills it is *not* the argument that kills
unwrapping.

The proposal: RFC 3056 §2 requires a 6to4 V4ADDR to be a globally routable
unicast IPv4, so `2002:a9fe:a9fe::` (V4ADDR `169.254.169.254`) is a **malformed**
6to4 address, as are `2002:a00:1::` (`10.0.0.1`) and `2002:7f00:1::`
(`127.0.0.1`). That is an *anomaly* claim about the literal's well-formedness,
not a *destination* claim about where the request goes — so it sidesteps the
objection that sank unwrapping. Teredo has the analogous property (RFC 4380
requires a globally routable server address), so it would be both or neither.

Declined for two reasons, neither of which is "6to4 is rare":

- **It is not reachable, so it is not a threat.** With the anycast relay
  deprecated (RFC 7526) and 6to4 disabled by default across mainstream stacks, a
  malformed 6to4 literal does not resolve to the embedded address or anywhere
  else. It is an oddity, not a target — the same reachability argument that
  declined unwrapping, which is why both dispositions agree.
- **The cheap implementation path is closed.** Folding this into
  `ip_obfuscation` would contradict that code's documented carve-out — *"wrapping
  an IPv4 in a transition prefix is not by itself obfuscation"* (see
  `ip_obfuscation` above). So the only route is a **new reason code**, with the
  registry, docs-validation, acceptance-coverage and corpus work that implies,
  plus a deliberate update to the existing benign corpus row for
  `https://[2002:a9fe:a9fe::]/` — whose `forbidReasons` list does not name a new
  code and so would **not** have caught the change automatically.

**The counterargument is real and was not overlooked.** Because legitimate 6to4
usage is negligible, the false-positive cost is close to zero, and nobody writes
`[2002:a9fe:a9fe::]` by accident — a URL containing one was hand-crafted, which
makes it a fair *intent* signal. Note that low usage argues **for** this code
(cheap precision), not against it; an argument of the form "6to4 is dead, so skip
it" is inverted and should not be reused. The decline rests on reachability and
implementation cost, not on rarity.

**Do not re-propose without new evidence.** What would change the answer: field
evidence of malformed 6to4 or Teredo literals used in real phishing or SSRF-filter
bypass, or a redesign that lets an anomaly of this shape reuse an existing code
instead of minting one. Absent either, this stays closed.

### `ip_cloud_metadata` — V1a · weight 0.75 (high)

- **Meaning:** the host is a cloud instance-metadata endpoint, matched against a
  curated per-provider table (`data/cloud-metadata.ts`) rather than a single
  hardcoded address:

  | Endpoint | Provider |
  | --- | --- |
  | `169.254.169.254/32` | AWS / Azure / GCP / DigitalOcean / OpenStack (shared) |
  | `fd00:ec2::254` | AWS (IPv6 IMDS) |
  | `192.0.0.192` | Oracle Cloud |
  | `100.100.100.200` | Alibaba Cloud |
  | `168.63.129.16` | Azure (WireServer host channel) |
  | `169.254.170.2` | AWS (ECS task credentials) |
  | `169.254.170.23` | AWS (EKS Pod Identity) |
  | `fd00:ec2::23` | AWS (EKS Pod Identity, IPv6) |
  | `169.254.0.23` | Tencent Cloud |

  An IPv4-mapped equivalent (`::ffff:169.254.169.254`) matches through the same
  table via its embedded IPv4. The emitted detail **names the provider**, so the
  reader learns whose credentials are at stake. This table is checked against
  `CLOUD_METADATA_ENDPOINTS` by `docs-validation.test.ts`, so it cannot drift
  silently.

  `168.63.129.16` and `192.0.0.192` are the rows **not** carved out of a
  special-use range. Microsoft presents the former as a "virtual public IP"
  reachable only from inside a VM, so it is ordinary public space to every range
  rule — it scored `info` 0.00 with **zero** reasons before the row existed,
  where endpoints nested in link-local or CGNAT were at least visible as a
  weaker bucket. A hostname is deliberately never a row (Tencent documents
  `metadata.tencentyun.com`, GCP `metadata.google.internal`): resolving one is a
  network call, and `inspect()` is zero-network by contract.
- **Matching:** on the **parsed** address, never on the literal text. Every table
  row and every host are decoded by the same IPv4/IPv6 parser and compared as
  bits, so `fd00:0ec2::254`, `FD00:EC2::254`, and `fd00:ec2:0:0:0:0:0:254` all
  match the AWS row — a string prefix test on `fd00:ec2:` would let the second
  spelling of the identical 128 bits through.
- **Precedence:** the table is consulted **before** the range buckets, so an
  endpoint nested inside a broader special-use range still classifies as
  metadata — `169.254.169.254` over link-local `169.254.0.0/16`, and
  `100.100.100.200` over the CGNAT `100.64.0.0/10` reserved range. The rest of
  those ranges is unaffected (`169.254.10.20` stays `ip_link_local`).
- **Data source:** vendor documentation, **not** an IANA registry — IANA
  registers the ranges, not which single address inside them a given cloud
  answers metadata on. The table therefore carries its own provenance stamp,
  version-pinned via `dataVersions.cloudMetadata`, independent of any registry
  pin.
- **Why it's a signal:** the canonical SSRF credential-theft target; a URL naming
  it literally is a near-unambiguous exfiltration attempt. Weighted to land
  **high** on its own (it fails the default `--fail-on high` gate) — well above
  the generic private/loopback buckets, but short of `critical`, which is left to
  the agentMode escalation (`ssrf_cloud_metadata`) where a fetch is in flight.
  Dual-use (cloud-init, IaC legitimately name it), so not a hard block in the
  default verdict.
- **Example:** `http://169.254.169.254/latest/meta-data/`.

### `ssrf_cloud_metadata` — weight 1.0 (blocker, agent-gated)

- **Meaning:** the agentMode escalation of `ip_cloud_metadata` — the host is the
  cloud instance-metadata endpoint **and** `InspectOptions.agentMode` is on.
- **Why it blocks:** in an agent / tool-use context, fetching the metadata
  endpoint is an in-flight SSRF credential-theft attempt with no defensible
  purpose, so it **blocks** (weight 1.0 → saturates the score to `critical`). It
  **stacks** on the always-on `ip_cloud_metadata` (0.75): the classifier states
  the fact, this states the agent-context verdict.
- **Gating:** emits only under `agentMode`. Default (non-agent) callers — log
  scanners, cloud-ops tooling that legitimately names the endpoint — never see it
  and keep the high, `--fail-on`-overridable `ip_cloud_metadata` verdict.
- **Example:** `inspect("http://169.254.169.254/", { agentMode: true })` →
  `critical`.

### `ip_loopback` — V1a · weight 0.2

- **Meaning:** a literal loopback IP — `127.0.0.0/8` or `::1`.
- **Why it's a signal:** an internal target a public-facing URL has no legitimate
  reason to name — the lexical fingerprint of an SSRF lure. Low weight
  (suspicious-in-context, not decisive alone).
- **Example:** `http://127.0.0.1:3000/`, `https://[::1]:8080/`.

### `ip_private` — V1a · weight 0.2

- **Meaning:** a literal private/internal IP — the registry's `Private-Use`
  blocks, i.e. RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or
  IPv6 `Unique-Local` `fc00::/7`.
- **Why it's a signal:** names an internal target. Same low band as
  `ip_loopback`.
- **Example:** `http://192.168.1.1/`, `https://[fc00::1]/`.

### `ip_link_local` — V1a · weight 0.2

- **Meaning:** a literal link-local IP — `169.254.0.0/16` or `fe80::/10`.
- **Why it's a signal:** an unrouteable internal target. Same low band.
- **Example:** `http://169.254.0.1/`.

### `ip_reserved` — V1a · weight 0.2

- **Meaning:** a literal reserved / special-use IP — every registry block that is
  **not** globally reachable and not one of the more specific buckets above.
  Includes `0.0.0.0/8`, `100.64.0.0/10` (CGNAT), future-use `240.0.0.0/4`,
  `198.18.0.0/15` (benchmarking), the IETF protocol-assignment blocks
  (`192.0.0.0/24`, `2001::/23`), `100::/64` (discard-only), `5f00::/16` (SRv6
  SIDs), the IPv6 unspecified address `::`, and multicast (`224.0.0.0/4`, IPv6
  `ff00::/8`) via the non-registry overlay.
- **Why it's a signal:** not a normal public destination. Same low band.
- **Example:** `http://0.0.0.0/`, `https://[ff02::1]/`.

### `ambiguous_numeric_host` — FR-D-7b (P3) · weight 0.3 (medium)

- **Meaning:** the host's last label is numeric/hex/octal, so a browser tries to
  read the **whole host as IPv4** and rejects it when that parse fails — but the
  host has no valid canonical IP. RFC 3986 has no "ends in a number" rule, so
  `curl` / `requests` / other non-browser clients accept it as a literal hostname
  and resolve it. The readers disagree; this is the malformed-IPv4 corner of the
  *yoU-aRe-a-Liar* (SecWeb '22) allow-list-bypass class.
- **Why it's a signal:** no legitimate site is shaped like this, and it is
  unvisitable in a browser yet resolvable by a fetcher — an equivocation at the
  one scope where it is the only signal. Distinct from `ip_obfuscation`
  (a *decodable* obfuscated IP handed to `ip_classification`): these hosts have
  no valid canonical IP, so they must not pollute that handoff. Two sub-shapes,
  same medium band: **pure-IP-attempt** (every label numeric/hex/octal —
  `256.0.0.1`, `0x100.2.3.4`, dotless overflow `0x100000000`) and
  **name-with-numeric-tail** (a name with a numeric/hex terminal label —
  `foo.09`, `foo.0x4`, `foo.1.2.3.4`).
- **Example:** `http://256.0.0.1/`, `http://1.2.3.4.5/`, `http://0x100000000/`,
  `http://foo.09/`. A single trailing root dot is normalized first, so
  `http://foo.09./` behaves identically. Valid IPs (`8.8.8.8`), obfuscated-but-
  decodable IPs (`0x7f.0.0.1` → `ip_obfuscation`), and numeric-adjacent names
  (`3.pool.ntp.org`) do **not** trip it.

### `embedded_domain_in_subdomain` — FR-D-8 · weight 0.5

- **Meaning:** a domain-looking label sequence appears left of the real
  registrable domain.
- **Why it's a signal:** `paypal.com.spoof.info` puts `paypal.com` in the
  subdomain; the real registrable domain is `spoof.info`. Purely lexical in v1
  (no DNS resolution of the embedded domain — FR-D-14). All contiguous windows
  of the subdomain labels are scanned (not just suffixes), so a brand domain with
  filler labels after it — `paypal.com.login.evil.com` — is still caught.
- **Example:** `https://paypal.com.spoof.info/` → real domain `spoof.info`;
  `https://paypal.com.login.evil.com/` → real domain `evil.com`.

### `excessive_subdomain_depth` — Epic I (I3) · weight 0.15

- **Meaning:** the host has an abnormally large number of **subdomain labels**
  (≥ 5 labels left of the registrable domain), e.g.
  `a.b.c.d.paypal.com.evil.tk`.
- **Why it's a signal:** stacking many subdomain labels buries the real
  registrable domain far to the right of the visible host, a known phishing
  structure. A low-weight contextual signal — it never flags on its own and only
  matters in combination with other signals.
- **Relationship to `embedded_domain_in_subdomain`:** that detector (FR-D-8)
  fires only when a window of the subdomain is itself a registrable domain;
  I3 fires on raw subdomain **depth** regardless of whether any window looks like
  a registrable domain, catching deep-burial hosts the embedded check misses.
- **Detection & precision (SC-2):** counts only the subdomain labels (everything
  left of the registrable domain) — the registrable-domain and public-suffix
  labels are excluded — and fires at the threshold of **5**. IP hosts and hosts
  with no subdomain never fire. Legitimate deep-subdomain hosts
  (`cdn.assets.eu-west-1.example.com`, 3 labels) stay clean.
- **Example:** `https://a.b.c.d.paypal.com.evil.tk/` (5 subdomain labels).
- **Scoring:** scoring, weight 0.15 (low-weight combination signal).

### `risky_tld` — FR-D-9 · weight 0.15

- **Meaning:** the registrable domain uses a high-abuse / free-registration TLD
  (e.g. `.tk`, `.ml`, `.xyz`).
- **Why it's a signal:** a low-weight contextual signal — these registries
  correlate with abuse. Low weight so it never flags on its own.
- **Relationship to `file_extension_tld`:** the extension-confusable TLDs
  `.zip` / `.mov` are **owned by `file_extension_tld`** (J6) and were removed from
  the `risky_tld` set, so the two never double-count.
- **Example:** `https://promo.tk/` (free-registration abuse TLD).

### `file_extension_tld` — Epic J (J6) · weight 0.4

- **Meaning:** the registrable domain uses a **file-extension TLD** (`.zip`,
  `.mov`) and is structured to masquerade as a downloadable file rather than a
  website. A sharper, higher-weight successor to `risky_tld` for these TLDs.
- **Why it's a signal:** `invoice.zip` reads as an archive and `setup.mov` as a
  video, yet both are live domains — a lure that pairs naturally with the J1/J2
  authority tricks and `userinfo_present`.
- **Masquerade structure** (fires only on one of these, so a real site does not
  flag — SC-2):
  - **bare filename** — the host is exactly `stem.<ext>` with no subdomain
    (`https://invoice.zip/`);
  - **hidden behind userinfo** — a `…@stem.<ext>` authority (`github.com∕x@update.zip`,
    where a J2 slash-look-alike pushes the brand into userinfo and the real host
    is the file-looking `.zip`).
- **Not flagged:** a `.zip` in the **path** (`/archive.zip` — a real file), or a
  deep-subdomain `.zip` host with no userinfo (`cdn.assets.acme.zip`).
- **Example:** `https://invoice.zip/`; `https://github.com∕x@evil.zip`.
- **Scoring:** scoring, weight 0.4.

### `encoding_obfuscation` — FR-D-10 · weight 0.35

- **Meaning:** percent-encoding hides structural characters or is multiply
  nested (double-encoding).
- **Why it's a signal:** encoded `/`, `@`, `:` or repeated `%25` chains hide the
  true structure of a URL. Recursive decoding is bounded (no decode-bomb).
- **Example:** `https://example.com%2F@evil.com` or `%252e%252e`.

### `dangerous_scheme` — FR-D-11 · weight 0.9

- **Meaning:** the scheme can execute or embed content: `javascript:`, `data:`,
  `blob:`, `file:`, `vbscript:`.
- **Why it's a signal:** these schemes are almost never legitimate in a link an
  agent or user is about to follow; highest single weight.
- **Example:** `javascript:fetch('//evil')`.

### `punycode_malformed` — E5 · weight 0.2

- **Meaning:** the host has an `xn--` (ACE) label that does not decode to a valid
  U-label under UTS-46 / Punycode.
- **Why it's a signal:** a low-weight lexical anomaly — such a host is not a
  registrable IDN and never appears in legitimate links, but it is not inherently
  an attack on its own, so it flags only at `low`. Valid IDNs are unaffected,
  including uppercase ACE (`XN--CAF-DMA` → `café`), which round-trips after
  UTS-46 case-folding.
- **Failure taxonomy (P1):** the reason code is stable, but the **detail** names a
  specific RFC 3492 sub-code (mirroring the punycoder taxonomy), so consumers see
  *why* a label is malformed:
  - `empty_ace_payload` — `xn--` with nothing to decode.
  - `invalid_punycode_digit` — a non-base-36 digit in the payload (reachable only
    via a direct label; the URL parser strips non-LDH chars before the detector).
  - `truncated_punycode_input` — a generalized-integer sequence ends early.
  - `punycode_overflow` — delta/bias arithmetic overflowed during decode.
  - `decoded_code_point_out_of_range` — a decoded scalar is a surrogate or above
    `U+10FFFF`.
  - `non_canonical_encoding` — decodes but is **not** the canonical encoding
    (fails the A-label decode→re-encode round-trip, RFC 5891 §5.4).
  - `invalid_idna_label` — decodes and round-trips, but the U-label fails a UTS-46
    validity rule (bidi, combining-mark-initial, hyphen position, …).
  Firing is unchanged (still gated by tr46), so scoring never changes.
- **Example:** `https://xn--abc.com/` (`invalid_idna_label`), `https://xn--.com/`
  (`empty_ace_payload`), `https://xn--99999999a.com/` (`punycode_overflow`),
  `https://xn--a-.com/` (`non_canonical_encoding`).

### `ambiguous_authority` — Epic J (J1) · weight 0.65

- **Meaning:** the authority is structurally ambiguous enough that two URL
  parsers would resolve it to a **different host or port** — the parser-vs-
  requester disagreement class (Orange Tsai, _A New Era of SSRF_; Snyk/Claroty,
  _Exploiting URL Parsing Confusion_).
- **Why it's a signal:** deception by construction, not a soft heuristic — a high
  weight. A flagship fit for the MCP "check before you fetch" surface: an agent
  is warned the string is ambiguous _before_ the request fires.
- **Sub-signals** (named in `detail`; one reason code regardless of how many fire):
  - `multiple_userinfo` — more than one `@` (`foo@evil.com:80@google.com`).
  - `fragment_in_authority` — a `#@…` tail (`google.com#@evil.com`).
  - `whitespace_in_authority` — whitespace inside the authority
    (`foo@127.0.0.1 @google.com` — the "curl won't fix it" bypass).
  - `multiple_port` — more than one `:` port separator (`127.0.0.1:11211:80`);
    IPv6 `[::1]:8080` is unaffected.
  - `backslash` — a `\` browsers fold to `/` (`http:\\google.com`, `https:/\…`).
  - `slash_confusion` — empty authority / 3+ slashes after the scheme
    (`http:///`, `http://///`) or a network-path reference in the path
    (`http://target.com/////evil.com`, CVE-2021-23435).
  - `protocol_relative` — a scheme-relative `//` authority (`//evil.com`).
- **Scope:** fires only when the input declares itself a URL (explicit scheme or
  `//` form). Bare scheme-less input (`google.com/abc`) is out of scope — it
  would over-trigger on benign typos (SC-2).
- **Result shape:** a parseable-but-ambiguous URL stays `status: "ok"` and adds
  this scoring reason; an unresolvable-but-ambiguous one is `status: "invalid"`
  yet now carries this reason instead of a bare `parse_error`.
- **Scoring:** scoring, weight 0.65.

### `separator_lookalike` — Epic J (J2) · weight 0.5

- **Meaning:** the authority contains a character that a downstream layer
  (browser, IDNA/NFKC normalization) maps to a **structural ASCII delimiter** — a
  dot or a slash — so the real host hides from a parser that does not normalize.
- **Why it's a signal:** `evil。com` (ideographic full stop, U+3002) resolves to
  `evil.com` in a browser but reads as one opaque label to a naive validator;
  `github.com／x@evil.zip` (fullwidth solidus) fakes a path boundary while the
  real host is `evil.zip`. Distinct from `confusable_char` (visual similarity) —
  this is about a character that becomes a *delimiter*.
- **Detected look-alikes:** dot → `.` (U+3002, U+FF0E, U+FF61, U+2024);
  slash → `/` (U+FF0F, U+2215).
- **Scope & precision (SC-2):** scanned in the **authority only** — an ideographic
  full stop is ordinary CJK punctuation inside a path (`/記事。html`) and is not
  flagged. The authority must also contain an ASCII alphanumeric, so a Latin brand
  glued by a look-alike dot fires while a pure-CJK host typed with an ideographic
  dot (normal domain entry) does not.
- **Scoring:** scoring, weight 0.5.

### `control_char` — Epic J (J3) · weight 0.6

- **Meaning:** the URL carries ASCII control or whitespace characters — **raw or
  percent-encoded** — positioned to **smuggle a protocol** or **terminate the
  host** (Orange Tsai, _A New Era of SSRF_, protocol-smuggling + glibc-NSS).
- **Why it's a signal:** a CR/LF lets the component that fires the request speak a
  second protocol on the wire (Redis `SLAVEOF`, SMTP `HELO`, Memcached `set`); a
  TAB or whitespace truncates the host so the validator and `getaddrinfo()` reach
  different destinations. A flagship MCP pre-fetch signal — the payload attacks a
  service sitting behind the server that fires the request.
- **Sub-signals** (named in `detail`; one reason code regardless of how many fire):
  `crlf` (CR/LF), `tab` (TAB), `null` (NUL), `control` (other C0/DEL), and
  `whitespace_in_host` (bare space inside a host-shaped authority). The `detail`
  also tags the encoding form: `[raw]`, `[percent-encoded]`, `[double-encoded]`.
- **Relationship to `invisible_char` (FR-D-4):** `invisible_char` already catches
  **raw** control characters (they are Unicode `Cc`) — the two co-fire there. The
  non-overlapping value of `control_char` is the **percent-encoded** (`%0D%0A`,
  `%09`) and **double-encoded** (`%250D%250A`, `%2509`) forms, which are plain
  ASCII text that `invisible_char` never sees, plus bare whitespace inside the
  authority (`Zs`, not `Cc`). Double-decoding reuses the bounded recursive decoder
  (no decode-bomb).
- **Scope & precision (SC-2):** an encoded **space** (`%20`) is not a control
  character and never flags; `whitespace_in_host` is scoped to host-shaped
  authorities (a dot plus an alphanumeric) so a space in a path or in non-URL
  prose does not flag.
- **Example:** `http://127.0.0.1:6379/%0D%0ASLAVEOF` (Redis smuggling),
  `http://127.0.0.1%09foo.google.com` (TAB host terminator).
- **Scoring:** scoring, weight 0.6.

### `prompt_injection_url` — V4a · weight 0.5 · **agent-gated**

- **Meaning:** the URL carries an LLM-agent **prompt-injection payload** — text
  positioned to hijack a model's instructions when the link is fetched and fed
  to an agent. Three shapes: a **prompt-control query parameter** whose name
  addresses the model's control plane (`role=`, `system=`, `prompt=`,
  `instruction(s)=`, `assistant=`, `system_prompt=`, `jailbreak=`, …) with a
  non-empty value; an **override phrase carried in a query value** — the
  realistic agent-fetch shape, where the payload rides in an ordinary parameter
  (`?q=ignore+previous+instructions`, `?text=disregard+all+prior+rules`); or an
  **instruction-override path segment** whose normalized text reads as an
  override (`/ignore-previous-instructions`, `/disregard-all-prior-prompts`,
  `/you-are-now`, `/act-as`).
- **Why it's a signal:** in agent / tool-use contexts a fetched URL can smuggle
  instructions into the model. This is a real attack class but also the **highest
  false-positive surface** of any detector — these tokens occur in legitimate
  apps — which is exactly why it is **gated**.
- **Agent-gated (opt-in):** this detector emits **only** when `inspect()` is
  called with `{ agentMode: true }` (CLI: `--agent`). With agent mode off it is
  not evaluated and never appears in `checksSkipped`; with it on, the `agent`
  channel token is added to `checksRun` (order `["lexical", "policy", "agent"]`).
  The default verdict is byte-identical to before this detector existed.
- **Conservative by construction:** parameter-**name** matching is on **exact
  decoded names** (set membership, never a substring scan), so `userrole=` /
  `payroll=` stay clean. Query-**value** and path matching look for a **delimited
  override phrase** that still requires a verb (`ignore`/`disregard`/`forget`/
  `override`) **plus** a trailing instruction noun (`instructions`/`prompts`/
  `rules`/…): a bare `/ignored/` directory or a `?q=ignore the noise` search lacks
  that noun and does not trip it. The phrase is delimited (start/space … space/
  end), not whole-string anchored, so trailing text
  (`/ignore-previous-instructions-and-export-secrets`) does not let a payload
  escape.
- **Example:** `https://example.com/agent?role=system&prompt=ignore%20all%20rules`,
  `https://example.com/?q=ignore%20previous%20instructions`,
  `https://example.com/ignore-previous-instructions` (all only under `agentMode`).
- **Scoring:** scoring, weight 0.5.

### `api_endpoint_impersonation` — V4b · weight 0.5 · **agent-gated**

- **Meaning:** the host **masquerades as a known API provider's endpoint**. A
  token from the SEPARATE **api-brands tier** (`openai`, `anthropic`,
  `googleapis`, `cohere`, `mistral`, `huggingface`, `stripe`, `twilio`,
  `sendgrid`, `github`) appears as an exact, separator-delimited **host label**
  while the **registrable domain (eTLD+1) is NOT** one of that provider's
  legitimate domains — the `api.openai-com.io` shape (label `openai-com` →
  token `openai`, but the eTLD+1 is `openai-com.io`, not `openai.com`).
- **Escalation:** when the **path** also matches a known API route prefix
  (`/v1/messages`, `/v1/chat/completions`, `/v1/completions`, `/v1/responses`)
  the detail notes that the host looks like a real API endpoint **and** the path
  looks like a real API call. Same code, same weight — only the detail sharpens.
- **Why it's a signal:** in agent / tool-use contexts an API client pointed at a
  look-alike endpoint leaks requests (and any keys) to an impostor. It is a
  separate tier from the curated brand watchlist because the match shape is an
  exact label-token membership test plus an exact eTLD+1 legitimacy check, not
  the curated list's edit-distance / keyword machinery.
- **Agent-gated (opt-in):** emits **only** when `inspect()` is called with
  `{ agentMode: true }` (CLI: `--agent`). With agent mode off it is not
  evaluated and never appears in `checksSkipped`. The default verdict is
  byte-identical to before this detector existed.
- **Conservative by construction:** the real provider on its own domain never
  fires (exact eTLD+1 skip); matching is set membership over separator-split
  labels (no substring scans, no regex backtracking). A brand-token match also
  requires a **corroborating API-endpoint signal** before firing — either an
  `api`-ish host label (an exact `api`/`apis` token in some label) **or** a path
  that matches a known API route prefix. This keeps `api.openai-com.io` firing
  while sparing brand-owned platform hosts on sibling eTLD+1s
  (`myproject.github.io`) and hosts that merely contain a brand word in an
  unrelated subdomain (`openai.example.com`).
- **Example:** `https://api.openai-com.io/v1/chat/completions`,
  `https://api.anthropic-com.co/v1/messages` (both only under `agentMode`). The
  real `https://api.openai.com/v1/chat/completions` does **not** fire.
- **Scoring:** scoring, weight 0.5.

### `credential_harvesting` — V4c · weight 0.35 · **agent-gated**

- **Meaning:** the URL has an **OAuth / token-flow shape** on a host that is
  **not** a known OAuth / identity provider — the lexical fingerprint of a
  credential-phishing or token-exfiltration endpoint. Two signal classes: an
  **OAuth path marker** (`/oauth/authorize`, `/oauth/token`, `/oauth2/authorize`,
  `/login/oauth/authorize`, `/connect/authorize`, …), or a **token-flow query
  marker** (`redirect_uri=`, `access_token=`, `client_secret=`,
  `response_type=token`, or `code=` combined with `client_id=` — the
  authorization-code callback pair).
- **Why it's a signal:** an agent that follows such a link can be walked through
  an OAuth handshake on an impostor host, leaking the code / token / secret to an
  attacker. It is a **separate** code from brand / API impersonation and **stacks**
  with them: the scoring is a probabilistic OR, so an OAuth shape on a brand
  look-alike host compounds both reasons on its own — the detector never
  special-cases stacking.
- **Critical precision constraint — non-allowlisted hosts only:** these markers
  are **perfectly legitimate** on real providers
  (`accounts.google.com/oauth/authorize`, `github.com/login/oauth/authorize`).
  The detector therefore fires **only** when the OAuth/token shape is present
  **AND** the registrable domain (eTLD+1) is **NOT** on a small, conservative
  OAuth-provider allowlist (`google.com`, `github.com`, `microsoft.com` /
  `microsoftonline.com`, `okta.com`, `auth0.com`, `facebook.com`, `apple.com`, …).
  The real provider, on any of its subdomains, never fires.
- **Agent-gated (opt-in):** emits **only** when `inspect()` is called with
  `{ agentMode: true }` (CLI: `--agent`). With agent mode off it is not
  evaluated and never appears in `checksSkipped`. The default verdict is
  byte-identical to before this detector existed.
- **Conservative by construction:** path matching is on **segment-anchored**
  marker phrases (so `/myoauth/authorizenow` does not trip it); query matching is
  on **exact parameter names** (set membership, never a substring scan of
  values).
- **Example:** `https://account-verify.example.com/oauth/authorize?redirect_uri=…`,
  `https://login.evil.tk/oauth/token?client_secret=…` (both only under
  `agentMode`). The real `https://github.com/login/oauth/authorize` does **not**
  fire.
- **Scoring:** scoring, weight 0.35.

### `data_exfiltration` — V4d · weight 0.3 · **agent-gated**

- **Meaning:** the URL query carries a **data-exfiltration shape** — the lexical
  fingerprint of context, secrets, or conversation contents being smuggled out to
  an attacker endpoint via the query string. Two signal classes: an **exfil-marker
  parameter name** (`data=`, `exfil=`, `beacon=`, `dump=`, `leak=`, `payload=`)
  carrying a non-empty value, or **any parameter whose value is an abnormally long,
  opaque base64/hex-style token** (the shape of a stolen-data dump, e.g.
  `?token=<2KB base64>`).
- **Why it's a signal:** an agent that follows (or is induced to construct) such a
  link beacons data out in the URL itself — no response body required. It is a
  **separate** code and **stacks** with the other detectors: the scoring is a
  probabilistic OR, so reasons compound on their own — the detector never
  special-cases stacking.
- **Precision — the overlong-token threshold + opaqueness gate:** long query
  values exist in legitimate flows (search strings, signed JWTs, encoded redirect
  targets). The overlong-token path therefore pairs a conservative **length floor
  (decoded value ≥ 200 chars)** with an **opaqueness gate**: the value must have
  **no spaces**, be drawn almost entirely from the base64/hex/url-safe alphabet
  (`A-Za-z0-9 + / - _ . = ~`), and have an **alphanumeric density ≥ 0.9**. A
  natural-language `q=` search string has spaces and punctuation and fails the
  gate; a base64/hex blob passes. A **JWT-shaped value** (three base64url
  dot-segments) is **excluded outright** — a signed `id_token` / `access_token`
  is a legitimate long opaque value in OAuth/OIDC URLs, so keying on its length
  would mis-flag it; OAuth/credential misuse is `credential_harvesting`'s job.
  The exfil-marker path is an **exact decoded parameter-name** match (set
  membership, never a substring scan).
- **Agent-gated (opt-in):** emits **only** when `inspect()` is called with
  `{ agentMode: true }` (CLI: `--agent`). With agent mode off it is not
  evaluated and never appears in `checksSkipped`. The default verdict is
  byte-identical to before this detector existed.
- **Example:** `https://collect.example.com/p?exfil=<value>`,
  `https://log.example.net/?token=<200+ char base64 blob>` (both only under
  `agentMode`). A benign long natural-language `?q=how+do+i+reset+my+password…`
  search string does **not** fire.
- **Scoring:** scoring, weight 0.3.

## Policy codes (caller-configured, layer "policy", weight 0)

These are **caller-configured** via `InspectOptions` — a separate channel from
the built-in deception detectors. They surface in `reasons[]` with
`layer: "policy"` and `weight: 0`, so they **never change the deception `score`
or `severity`**: they annotate the result with a policy verdict and the consumer
enforces it. When no policy field is set they do not fire and `checksRun` stays
exactly `["lexical"]`.

### `tld_denied` — policy (TLD deny-list)

- **Meaning:** the host's **TLD** (the last label of the public suffix, e.g.
  `co.uk` → `uk`) is on the caller's `denyTlds` list (default-allow: everything
  not listed passes).
- **Why it's surfaced:** a caller-owned policy decision, not a deception
  heuristic — e.g. an organization that refuses links under `.ru` / `.cn`.
  Distinct from the built-in `risky_tld`, which is a low-weight *scoring*
  deception signal over a curated abuse-TLD set; `tld_denied` is whatever the
  caller chose, advisory only.
- **Matching:** TLD values are compared case-insensitively and bare (a leading
  dot is tolerated and stripped). IP / hostless inputs have no public suffix and
  never match.
- **Example:** `inspect("https://promo.ru/", { denyTlds: ["ru", "cn"] })` →
  `tld_denied` with detail `TLD '.ru' is on the caller deny-list`.
- **Scoring:** policy, weight 0 (advisory; never moves the score).

### `tld_not_allowlisted` — policy (TLD allow-list)

- **Meaning:** the host's **TLD** is **not** on the caller's `allowTlds` list
  (default-deny lockdown: only the listed TLDs pass).
- **Why it's surfaced:** a caller-owned policy decision — e.g. an organization
  that only permits links under `.com` / `.de`. Independent of the `denyTlds`
  axis: when both are configured, a denied TLD emits `tld_denied` and the same
  input also emits `tld_not_allowlisted` if its TLD is not in `allowTlds`.
  Distinct from the built-in `risky_tld` deception heuristic.
- **Matching:** TLD values are compared case-insensitively and bare (a leading
  dot is tolerated and stripped). IP / hostless inputs have no public suffix and
  never match.
- **Example:** `inspect("https://example.org/", { allowTlds: ["com", "de"] })` →
  `tld_not_allowlisted` with detail
  `TLD '.org' is not on the caller allow-list ([com, de])`.
- **Scoring:** policy, weight 0 (advisory; never moves the score).

### `host_denied` — policy (host deny-list)

- **Meaning:** the host's **registrable domain** (eTLD+1) is on the caller's
  `denyHosts` list (default-allow: everything not listed passes).
- **Why it's surfaced:** a caller-owned policy decision, not a deception
  heuristic — e.g. an organization that refuses links to a known-bad vendor or
  competitor domain. Advisory only; a separate channel from the deception
  detectors.
- **Matching:** entries are compared case-insensitively and bare (a leading dot
  is tolerated and stripped) against the host's **registrable domain**. Because
  the match key is the registrable domain, listing `example.com` covers
  `example.com` **and every subdomain** (`sub.example.com` shares registrable
  domain `example.com`). IP / hostless inputs have no registrable domain and
  never match.
- **Example:** `inspect("https://sub.evil.com/", { denyHosts: ["evil.com"] })` →
  `host_denied` with detail
  `Host 'sub.evil.com' (registrable domain 'evil.com') is on the caller deny-list`.
- **Scoring:** policy, weight 0 (advisory; never moves the score).

### `host_not_allowlisted` — policy (host allow-list)

- **Meaning:** the host's **registrable domain** (eTLD+1) is **not** on the
  caller's `allowHosts` list (default-deny corporate lockdown: only the listed
  domains and their subdomains pass).
- **Why it's surfaced:** a caller-owned policy decision — e.g. an organization
  that only permits links to its own company and approved vendor domains.
  Independent of the `denyHosts` axis: when both are configured, a denied
  registrable domain emits `host_denied` and the same input also emits
  `host_not_allowlisted` if its registrable domain is not in `allowHosts`.
- **Matching:** entries are compared case-insensitively and bare (a leading dot
  is tolerated and stripped) against the host's **registrable domain**. Listing
  `mycompany.com` allows `mycompany.com` **and every** `*.mycompany.com`. IP /
  hostless inputs have no registrable domain and never match (so they never pass
  an allow-list).
- **Example:**
  `inspect("https://example.org/", { allowHosts: ["mycompany.com"] })` →
  `host_not_allowlisted` with detail
  `Host 'example.org' (registrable domain 'example.org') is not on the caller allow-list ([mycompany.com])`.
- **Scoring:** policy, weight 0 (advisory; never moves the score).

### `scheme_denied` — policy (scheme allow/deny)

- **Meaning:** the input's **scheme** (lower-cased, no colon) is on the caller's
  `denySchemes` list, **or** is **not** on the caller's `allowSchemes` list
  (default-deny lockdown — e.g. `allowSchemes: ["https"]` for an https-only
  policy). Both lists map to this single code; the detail string distinguishes a
  deny-list hit from a not-allow-listed one.
- **Why it's surfaced:** a caller-owned policy decision — e.g. an organization
  that only permits `https` links, or that blocks `ftp`. **Distinct from the
  built-in `dangerous_scheme`** deception detector, which is a high-weight
  *scoring* heuristic over execute-or-embed schemes (`javascript:`, `data:`…);
  `scheme_denied` is whatever the caller chose, advisory only, on a separate
  channel.
- **Matching:** scheme values are compared case-insensitively and bare (a
  leading/trailing colon is tolerated and stripped) against the input's parsed
  scheme. Opaque / hostless inputs still carry a scheme (e.g. `javascript`,
  `data`), so scheme policy applies to them. Inputs with **no scheme** are exempt
  — the axis is skipped, so a schemeless input never emits `scheme_denied` (an
  allow-list cannot fire when there is no scheme to judge).
- **Example:** `inspect("http://example.com/", { allowSchemes: ["https"] })` →
  `scheme_denied` with detail
  `scheme 'http' is not on the caller allow-list ([https])`. And
  `inspect("ftp://example.com/", { denySchemes: ["ftp"] })` → `scheme_denied`
  with detail `scheme 'ftp' is on the caller deny-list`.
- **Scoring:** policy, weight 0 (advisory; never moves the score).

### `port_denied` — policy (port deny / non-standard)

- **Meaning:** the input's **explicit** port is on the caller's `denyPorts`
  list, **or** — when `denyNonStandardPorts: true` — is not the standard default
  for its scheme. Only an explicit port is evaluated; an input with no explicit
  port never emits this code.
- **Why it's surfaced:** a caller-owned policy decision — e.g. blocking known
  exfil/phishing ports (`:8080`, `:31337`) by enumeration, or refusing any
  non-standard port without listing them. Advisory only; a separate channel from
  the deception detectors.
- **Standard-port map (`denyNonStandardPorts`):** `http`→80, `https`→443,
  `ftp`→21, `ws`→80, `wss`→443. A port equal to its scheme's default is
  "standard"; any other explicit port — or any explicit port on a scheme not in
  this map — is "non-standard".
- **Dedup:** when both `denyPorts` and `denyNonStandardPorts` would flag the same
  port, exactly one `port_denied` is emitted (the deny-list reason takes
  precedence).
- **Example:** `inspect("https://example.com:8080/", { denyPorts: [8080] })` →
  `port_denied` with detail `port 8080 is on the caller deny-list`. And
  `inspect("https://example.com:8080/", { denyNonStandardPorts: true })` →
  `port_denied` with detail
  `port 8080 is non-standard for scheme 'https' (expected 443)`.
- **Scoring:** policy, weight 0 (advisory; never moves the score).

## Meta

### `parse_error`

- **Meaning:** the input is not a parseable URL or hostname.
- **Non-string input:** a caller-contract failure (`null`, `undefined`, a number,
  an object) resolves here too, rather than throwing a `TypeError` — the
  never-throws guarantee is unconditional. The `detail` is sharpened to name the
  offending type (`input is not a string (got null)`), and `input` echoes the
  coerced value (`""` when the value cannot be coerced at all). No separate
  reason code is minted, so the registry and its documented count are unchanged.
- **Result shape:** `status: "invalid"`, `parsed/score/severity: null`. An
  invalid result is **not benign** — a fail-closed consumer must reject it
  (FR-IN-4, SC-2a). An invalid result may instead carry an `ambiguous_authority`
  reason when the input is structurally ambiguous (see above); `parse_error` is
  the fallback when no detector explains the failure.
- **Scoring:** weight 0.
