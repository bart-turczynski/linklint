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
- **See also:** `brand_in_path` (J7) — the scoring counterpart for a brand
  *keyword* in the path (vs. confusable *characters* here).

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
  is registrable), so the base signal must not raise severity (SC-2). **Epic G**
  adds the scoring escalation: when the alternate IDNA2003 mapping equals a known
  brand (`wordpreß` → `wordpress`), it becomes an impersonation signal. (Decision
  on the brainstorm's OQ-J9b: informational until the brand list lands.)
- **Scoring:** informational, weight 0.

## Scoring codes

These contribute to the risk score via probabilistic OR (`docs/scoring.md`).

### `mixed_script` — FR-D-3 · weight 0.4

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

### `brand_in_path` — Epic J (J7) · weight 0.2

- **Meaning:** a **brand reference is planted in the path/query** of an unrelated
  host. The scoring counterpart to the info-only `confusable_in_path`: that flags
  confusable *characters* in the path, this flags a brand *keyword*.
- **Why it's a signal:** `https://evil.com/paypal.com/login` resolves to
  `evil.com`, but a skimming user sees `paypal.com` in the URL and trusts it.
- **Detection & precision (SC-2):** fires only on two phishing-shaped patterns,
  and only when the brand does **not** appear in the host:
  - **domain-shaped** — a path/query token `<brand>.<tld>` (`/paypal.com/`,
    `?next=paypal.com`);
  - **credential flow** — a bare `<brand>` path segment together with a
    credential-flow word (`login`, `signin`, `verify`, …): `/paypal/login`.
  So a brand's own site (`paypal.com/login`), a brand word in prose
  (`/blog/netflix-review`), and a bare brand path without credential context
  (`github.com/paypal/repo`) all stay clean.
- **Brand list:** a small **seed** set (`data/brands.ts`, version-pinned via
  `dataVersions.brands`). Epic G replaces it with the authoritative, expandable
  list and adds the host-side brand escalations.
- **Example:** `https://evil.com/paypal.com/login`; `https://phish.io/google/signin`.
- **Scoring:** scoring, weight 0.2.

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
- **Detection & precision (SC-2):** the **full registrable domain string** is run
  through the UTS#39 `skeleton()` helper (`unicode/skeleton.ts`, built from the
  already-pinned confusables table) and tested for an exact match against the
  precomputed skeleton of each `BRAND_DOMAINS` entry.
  - **Non-ASCII only** — the detector runs solely when the registrable domain
    carries a non-ASCII codepoint. The pure-ASCII digit-fold case (`paypa1.com`)
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

### `brand_combosquat` — Epic G (G3) · weight 0.4

- **Meaning:** a **watchlist brand keyword is glued to an additive (non-brand)
  token inside a single host label** — `paypal-secure.com`, `login-paypal.com`,
  `secure-paypal-login.net`, `paypal-verify.evil.com`. The host is not a typo of
  the brand domain; it pairs the brand name with a reassuring extra word.
- **Why it's a signal:** combosquatting is *more* common than character
  typosquatting and is **invisible to edit distance** — the string is not a
  near-miss of the brand domain, so the G2 look-alike checks never see it. This
  detector complements them with pure string operations over the host.
- **Detection & precision (SC-2):**
  - **Token boundary is the key precision lever** — a brand keyword counts only
    when it is a **separator-delimited token**. Host labels are split on `-` and
    the `.` label boundary; `paypal-secure` → `[paypal, secure]`. This is *not*
    bare substring matching, which is what keeps `amazonaws.com` (the single
    concatenated token `amazonaws`, legitimate AWS) quiet.
  - **A genuine combination is required** — within one hyphenated label, a brand
    keyword token **plus** at least one additive non-brand token. A lone label
    that is exactly a brand keyword (e.g. `paypal` as a subdomain of `evil.com`)
    is *not* a combosquat; that is `embedded_domain_in_subdomain` /
    `brand_in_path` territory. The hyphen-glued case is the unambiguous,
    high-precision combosquat — that is the documented boundary choice.
  - Both the registrable label and subdomain labels are inspected, so
    `paypal-secure.com` and `paypal-verify.evil.com` both fire.
  - **The real brand never fires** — if the input's registrable domain is itself
    a watchlist brand domain (`paypal.com`, and its own subdomains like
    `login.paypal.com`), the brand legitimately uses its own keyword and is
    skipped. IP hosts and host-less inputs are skipped.
- **Brand list:** the authoritative Epic G watchlist keywords (`BRAND_KEYWORDS`),
  version-pinned via `dataVersions.brands`.
- **See also:** `brand_lookalike` (G2) — the edit-distance sibling that
  combosquats slip past, and `brand_in_path` (J7) — the same brand-keyword idea
  in the *path/query* rather than the host. All three are complementary, with
  distinct codes; stacking with `embedded_domain_in_subdomain` is acceptable when
  both genuinely apply.
- **Example:** `https://paypal-secure.com`; `https://login-paypal.com`;
  `https://secure-paypal-login.net`; `https://paypal-verify.evil.com`.
- **Scoring:** scoring, weight 0.4 (provisional — G5 re-tunes).

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
- **See also:** `brand_lookalike` / `brand_homoglyph` / `brand_combosquat`
  (G2/G3) — the brand-impersonation checks this density signal corroborates.
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

### `invisible_char` — FR-D-4 · weight 0.5

- **Meaning:** invisible, zero-width, or control characters appear anywhere in
  the URL (excluding bidi controls, which are reported as `bidi_override`).
- **Why it's a signal:** invisible characters hide differences between a
  deceptive host and a legitimate one.
- **Example:** `exa​mple.com` (zero-width space inside the host).

### `bidi_override` — FR-D-5 · weight 0.6

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
    runs like `0::1` / `2001:db8:0:0:0:0:0:1`) or an **IPv4-embedding** form
    (`[::ffff:127.0.0.1]`): the validator sees an IPv6 address while the resolver
    reaches the embedded IPv4 — an SSRF masquerade. Pure case differences
    (`2001:DB8::1`) are tolerated (not a deception vector).
- **Why it's a signal:** obfuscated IPs evade human and naive string checks.
- **Detail:** renders the canonical form so the real destination is explained;
  for an IPv4-embedding IPv6 literal it also names the embedded IPv4. Canonical
  dotted-decimal IPv4 and canonical IPv6 literals (`[::1]`) are **not** flagged.
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

### `ip_cloud_metadata` — V1a · weight 0.5

- **Meaning:** the host is the cloud instance-metadata endpoint —
  `169.254.169.254/32`, `fd00:ec2::254`, or an IPv4-mapped equivalent
  (`::ffff:169.254.169.254`).
- **Why it's a signal:** the canonical SSRF credential-theft target; a URL naming
  it literally is a near-unambiguous exfiltration attempt. Weighted **above** the
  generic private/loopback buckets.
- **Example:** `http://169.254.169.254/latest/meta-data/`.

### `ip_loopback` — V1a · weight 0.2

- **Meaning:** a literal loopback IP — `127.0.0.0/8` or `::1`.
- **Why it's a signal:** an internal target a public-facing URL has no legitimate
  reason to name — the lexical fingerprint of an SSRF lure. Low weight
  (suspicious-in-context, not decisive alone).
- **Example:** `http://127.0.0.1:3000/`, `https://[::1]:8080/`.

### `ip_private` — V1a · weight 0.2

- **Meaning:** a literal private/internal IP — RFC 1918 (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`) or IPv6 unique-local `fc00::/7`.
- **Why it's a signal:** names an internal target. Same low band as
  `ip_loopback`.
- **Example:** `http://192.168.1.1/`, `https://[fc00::1]/`.

### `ip_link_local` — V1a · weight 0.2

- **Meaning:** a literal link-local IP — `169.254.0.0/16` or `fe80::/10`.
- **Why it's a signal:** an unrouteable internal target. Same low band.
- **Example:** `http://169.254.0.1/`.

### `ip_reserved` — V1a · weight 0.2

- **Meaning:** a literal reserved / special-use IP — `0.0.0.0/8`, `100.64.0.0/10`
  (CGNAT), multicast (`224.0.0.0/4`, IPv6 `ff00::/8`), future-use `240.0.0.0/4`,
  or the IPv6 unspecified address `::`.
- **Why it's a signal:** not a normal public destination. Same low band.
- **Example:** `http://0.0.0.0/`, `https://[ff02::1]/`.

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
- **Example:** `https://xn--abc.com/` or `https://xn--.com/` (undecodable ACE).

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
  to an agent. Two shapes: a **prompt-control query parameter** whose name
  addresses the model's control plane (`role=`, `system=`, `prompt=`,
  `instruction(s)=`, `assistant=`, `system_prompt=`, `jailbreak=`, …) with a
  non-empty value, or an **instruction-override path segment** whose normalized
  text reads as an override (`/ignore-previous-instructions`,
  `/disregard-all-prior-prompts`, `/you-are-now`, `/act-as`).
- **Why it's a signal:** in agent / tool-use contexts a fetched URL can smuggle
  instructions into the model. This is a real attack class but also the **highest
  false-positive surface** of any detector — these tokens occur in legitimate
  apps — which is exactly why it is **gated**.
- **Agent-gated (opt-in):** this detector emits **only** when `inspect()` is
  called with `{ agentMode: true }` (CLI: `--agent`). With agent mode off it is
  not evaluated and never appears in `checksSkipped`; with it on, the `agent`
  channel token is added to `checksRun` (order `["lexical", "policy", "agent"]`).
  The default verdict is byte-identical to before this detector existed.
- **Conservative by construction:** query matching is on **exact decoded
  parameter names** (set membership, never a substring scan); path matching is on
  **whole, anchored segments** so an unrelated `/ignored/` directory does not
  trip it.
- **Example:** `https://example.com/agent?role=system&prompt=ignore%20all%20rules`,
  `https://example.com/ignore-previous-instructions` (both only under `agentMode`).
- **Scoring:** scoring, weight 0.5.

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
- **Result shape:** `status: "invalid"`, `parsed/score/severity: null`. An
  invalid result is **not benign** — a fail-closed consumer must reject it
  (FR-IN-4, SC-2a). An invalid result may instead carry an `ambiguous_authority`
  reason when the input is structurally ambiguous (see above); `parse_error` is
  the fallback when no detector explains the failure.
- **Scoring:** weight 0.
