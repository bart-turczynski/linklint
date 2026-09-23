# linklint architecture

## 1. Intent

linklint is an offline-first URL inspection engine: synchronous, deterministic, zero-network, never throws. Every verdict is explainable — each `InspectResult` carries named reason codes with weights and human-readable `detail` strings.

The core architectural rule: **channels do not implement detectors.** `packages/core` owns everything that affects a verdict; `packages/mcp` and `packages/cli` are thin adapters that call `inspect()` and present or enforce the result.

### 1.1 Scope of claim — the structural claim and the name-never-create rule (canonical)

This is the canonical statement of what linklint asserts. Everything downstream
— the README's "What linklint does not do", `SECURITY.md`'s scope section, the
`KNOWN_AND_ACCEPTED` list in `test/corpus/embarrassment.ts`, and the decision
records below (notably §6.1.1 and §6.1.2) — restates or applies this section
and must not contradict it. If they diverge, this section wins.

**The claim.** linklint commits to exactly one:

> **(a) STRUCTURAL.** The string is not what it presents itself to be.

It explicitly **rejects** the other:

> **(b) SEMANTIC.** "We detect impersonation of high-value brands."

Claim (a) is settleable from the string alone, offline, deterministically, and
for all time — it names a property of the input, not a property of the world.
Claim (b) requires knowing which words are brands, which brands are worth
impersonating, and what the site at the other end does. linklint has none of
that and does not pretend to.

**The three settled forms of claim (a).** These are one claim in three shapes,
not three claims. Each is a demonstrable property of the string:

1. **Normalization delta** — `normalize(input) !== input`. The string reads one
   way and resolves another, so something is hiding. This is the original and
   most common form: `separator_lookalike`, `invisible_char`, `brand_homoglyph`.
2. **Reader disagreement** — `read_A(input) !== read_B(input)`. Two conforming
   readers resolve the same string to different destinations, so at most one of
   them reaches where the reader thinks it does. `ambiguous_authority` (0.65,
   "parsers disagree on the host"), `ambiguous_numeric_host` (0.3, "a browser
   rejects it, non-browser clients may resolve it"), `idna_mapping_ambiguity`
   and `locale_case_ambiguity`. §6 states the same rule from the other end:
   **"the discriminator is *disagreement between standards*, not exotic input."**
3. **False self-description** — the string declares its own type and the
   declaration does not hold. `xn--` announces "I am an ACE-encoded IDN"; when it
   does not decode, `punycode_malformed` fires at 0.2.

Form 2 and form 3 are why linklint **does** make protocol-validity claims, and
saying otherwise contradicts the shipped registry. What makes them claim (a) is
not that the string is invalid — it is that the invalidity is a false claim the
string makes about itself, or a fork in how the string will be read.

**What this excludes: well-formed but unusable.** A string that every reader
agrees on, that makes no false claim about itself, and that merely fails, is
**not** a claim-(a) finding. The worked case is host length: a 64-character DNS
label is syntactically a hostname, is read identically by every parser, and is
simply too long to resolve. Nothing is hidden and nobody disagrees. It is pinned
benign in `test/corpus/vectors.ts` and a *scoring* implementation of DNS length
caps was written and reverted on exactly this reasoning (`LINK-ygglwkuy`,
`LINK-tukbqyjg`). "Malformed" and "deceptive" are not the same claim, and only
the second is chartered.

The scope test did not change, but the reporting obligation did: the same fact is
now announced at weight 0 by `host_length_unresolvable`, per the fourth rule
below. Failing to score it was always correct; failing to *mention* it was not.

**A fourth rule, settled: report what you can determine, never silently pass.**
A string that linklint cannot fully analyze, or that is analyzable but
non-conforming, must still be *explained* to the caller. Returning `0.00` with no
reasons asserts "there is nothing to say about this URL", and that assertion is
false whenever there is something definite to say — that a hostname cannot
resolve, that an escape is malformed, that a component could not be parsed. This
does **not** widen claim (a): a fact that is not a deception finding is reported
at **weight 0**, annotating without moving the score, exactly as
`normalization_delta` and `confusable_in_path` already do. The distinction the
earlier draft left unwritten is therefore settled this way: *scoring* is reserved
for the three forms above, *reporting* is not. Where a `parse_error` is
unavoidable, it names what failed rather than standing in for the whole verdict.

The worked case is the one immediately above: an over-long hostname stays
`benign` and scores `0.00`, and now also carries the weight-0
`host_length_unresolvable`, which says why it will never work. Nothing is hidden,
nobody disagrees, no score moves — and the caller is no longer told that linklint
had no opinion.

**The path layer, settled: standards enumeration is the line** (`LINK-uorcqwnm`).
Every worked case above is host-side — host length here, `xn--` in form 3, the
brand cases below — so the path had the principle stated at it and no
application of it anywhere. That is an absence a proposer cannot read: someone
arriving with a path trick finds a rule they must re-derive, and re-derives it
differently each time. The question that decides a path proposal is this one:

> Is the divergence enumerated by the URL standards themselves, or introduced by
> application code **below** the URL layer?

Divergence the standards enumerate is a property of the string, settleable
offline by anyone holding the spec. Divergence introduced beneath the URL layer
— by a servlet container, a reverse proxy, a CDN's cache key — is a property of
one deployment. That is the world, not the string, and claim (a) does not reach
it.

*In scope — encoded double-dot segments.* The WHATWG URL Standard enumerates a
**double-dot path segment** by name: `..`, `.%2e`, `%2e.`, `%2e%2e`, ASCII
case-insensitive. Every conforming parser therefore pops the parent for all
four, and Node does — `https://example.com/a/b/.%2e/admin` resolves to
`/a/admin`. A segment that reads as literal text and resolves as a traversal is
form 1, `normalize(input) !== input`; against a reader that implements only the
unencoded spelling it is form 2. No assumption about any server is needed,
because the standard supplies the spellings. `encoding_obfuscation` matches all four
spellings the standard enumerates, each anchored to a whole path segment
(`LINK-dpahotkg`). The anchoring is part of the boundary rather than a tuning
choice: `%2e%2e` inside a longer segment is a traversal to no conforming reader,
and becomes one only if something decodes the escape and then re-splits the
path — application code below the URL layer, which is the far side of the line
this section draws.

*Out of scope — `..;/` and bare path parameters.* Node leaves
`https://example.com/a/..;/admin` at `/a/..;/admin`, and every conforming reader
agrees the segment is `..;` — a name, not a traversal. RFC 3986 §3.3 permits `;`
inside a segment as a sub-delimiter with **no** generic meaning; path parameters
were dropped when RFC 3986 replaced RFC 2396. The traversal appears only once a
servlet container strips the parameter first, which is application code below
the URL layer, and the same holds for a bare `;` segment. A **stated non-goal
and not a gap**.

*Out of scope — an extension after a dynamic segment (web cache deception).*
`https://example.com/api/user/123/x.css` is well-formed, every reader agrees on
it, and it makes no false claim about itself. It becomes an attack only in front
of a cache configured to key on a suffix and to store what it is handed — one
deployment's rule-set. That is the **well-formed but unusable** exclusion above,
applied to the path: nothing is hidden and nobody disagrees. Also a **stated
non-goal and not a gap**.

*Why the line is not "consumer-agnostic".* The tempting phrasing — flag only
what holds for every consumer — is recorded here as **rejected**, because it is
the one a re-derivation lands on and it is falsified by shipped code. `/` is a
reserved gen-delim under RFC 3986 §2.2, and a percent-encoded octet of a
reserved character is not equivalent to the character it encodes, so `%2F` in a
path is data by spec; `encoding_obfuscation`'s encoded-separator signal really
does lean on some servers decoding it anyway. A consumer-agnostic line condemns
that shipped rule. The standards-enumeration line keeps it and still excludes
`..;`: §2.2 *names* the reserved-versus-encoded distinction the string is
playing on, while no standard assigns `;` in a segment any meaning at all.

**Agent mode, settled: a declared context re-weights, it does not re-charter**
(`LINK-uyoocslu`). The four `agentGated` detectors — `prompt_injection_url`,
`credential_harvesting`, `data_exfiltration`, `ssrf_cloud_metadata` — shipped
with a gate, a weight and no scope note. This section did not name the family,
§5 listed it without one, and `docs/reason-codes.md` argues each entry from
consumer consequence ("an agent that follows such a link can be walked through
an OAuth handshake on an impostor host") where its neighbours cite this section
by number. A family that cites no boundary has whatever boundary its next author
assumes. The question that decides an agent-gated proposal is this one:

> Does the finding name a property of the string, or a property of what one
> consumer does with the bytes **after** every reader has agreed where they came
> from?

*Form 2 is destination-scoped, and stretching it is the failure mode.* The
tempting move — reading `read_A(input) !== read_B(input)` as "a browser and an
LLM behave differently" — is recorded here as **rejected**. Form 2's
disagreement is about *where the string resolves*: `ambiguous_authority` has two
parsers reaching two hosts, `ambiguous_numeric_host` has one reader refusing
what another dials. A browser and an agent both fetching
`https://example.com/?q=ignore+previous+instructions` reach the same destination
and receive the same bytes; they diverge in what they do with the text
afterwards. Widening form 2 to "any two consumers behave differently" does not
admit one detector, it dissolves the section — combosquatting, `..;/`, web cache
deception and a 64-character label can each be restated as one consumer
behaving differently from another, and claim (b) walks back in through the door
claim (a) was built to hold.

*The three forms do not reach a reader-consumption property; the fourth rule
does.* An override phrase in a query value is not hidden
(`normalize(input) === input`), is not disputed (every conforming parser agrees
where the URL goes), and is not a false self-description (the string is exactly
the parameter it says it is). It is still **determinable from the string**,
which is what the fourth rule above exists for: report it at **weight 0** and
let the caller — who declared the context — act on it. That makes agent mode a
**reporting** channel by charter and a scoring one only by exception, and puts
the burden on the proposal that wants to score.

*What justifies a consequence-weighted escalation.* One shape carries that
burden, and `ssrf_cloud_metadata` is its only instance. Three conditions, all
required:

1. **The fact is settled with the gate off.** The firing condition is a fact
   determinable from the string alone and already reported without `agentMode`
   — here a whole-host equality test against an IANA-reserved literal and the
   vendor-published names for it, reported by `ip_cloud_metadata` in either
   mode. What the condition needs is that the fact is *settled*, not that it
   *scores*: since §6.1.10 `ip_cloud_metadata` reports at weight 0, because
   where an address points is not a claim-(a) deception, and the escalation's
   grounding is unchanged by that. The escalation inherits that grounding; it
   does not supply one.
2. **The gate moves the weight, not the finding set.** Both modes state the same
   fact about the same string, and the gate says how hard an already-settled
   fact should land. A detector that *exists only* under the gate fails this
   condition, and the failure is diagnostic: there the gate is doing the
   epistemic work, and the caller's declaration is being spent to license a
   finding claim (a) does not support.
3. **The declaration, not an inference, fixes the consequence.** `agentMode` is
   asserted by the caller, so the dual-use population — cloud-init, IaC, a log
   scanner naming the endpoint — is separated by what the caller said about
   itself rather than by linklint guessing what a URL is for. Escalating on a
   guess about the consumer is claim (b) pointed at the caller instead of at the
   site.

*The per-code ruling* (`LINK-uyoocslu`), **shipped** in schema `1.10` /
weights `1.19` (`LINK-brsntven`). The Weight column below is the shipped weight,
read from the registry by the drift guard in
`packages/core/test/docs-validation.test.ts`, so this table now describes the
code rather than owing it something. A weight is a scoring surface with its own
version stamp (§6.4) and moved under its own decision, in its own change.

| Code | Weight | Ruling | Disposition |
|---|---|---|---|
| `ssrf_cloud_metadata` | 1.00 | **Grounded** — meets all three conditions above | kept as shipped |
| `prompt_injection_url` | 0.00 | none of the three forms — a post-resolution reader property | reports at **weight 0** |
| `data_exfiltration` | 0.00 | none of the three forms; the overlong-token branch flags a string that is well-formed, agreed-upon and honest about itself | reports at **weight 0** |
| `credential_harvesting` | 0.00 | fired on an OAuth shape **and** the host's absence from a list of real identity providers — an inverse watchlist | **re-grounded**: the list is deleted, and the flow shape reports at **weight 0** for every host |

The consequence is worth stating plainly, because it is the charter in one
sentence: **agent mode can no longer raise a score above what plain mode gives,
except through `ssrf_cloud_metadata`.** A declared context re-weights a settled
fact; it does not license a finding claim (a) does not support.

`credential_harvesting` is the one the deletion record already decided, and
§6.1.5 is where the drop of `OAUTH_PROVIDER_DOMAINS` is written down.
`api_endpoint_impersonation` was deleted in schema `1.9` (`LINK-eurtxkit`)
because its firing condition was `API_BRAND_DOMAINS.get(token)` — a contingent
commercial fact — corroborated only by ordinary syntax. Inverting the list does
not change what it is: a set of registrable domains whose *complement* creates
the finding is a watchlist creating findings, and the name-never-create rule
below forbids that in either polarity. Incompleteness cuts the other way here,
too. DynaPhish's finding that any fixed reference list is inherently incomplete
is a precision argument for the watchlist and a false-positive argument against
an allowlist, because a self-hosted Keycloak, a Gitea instance and a corporate
`login.acme.com` all carry the shape and are all off the list — and whether
`auth0.com` is an identity provider next year is a fact about the world. What
survives the cut is the string fact underneath: this URL carries an
authorization-code or token-flow shape. That is true of `github.com` as well,
and saying so at weight 0 costs nothing.

`data_exfiltration` carries a demonstrated false positive rather than a
predicted one: `https://blog.example.com/download?data=report2024` read
`0.30`/`medium` under agent mode on nothing but the ordinary English word `data`
in a parameter name — the spelling Microsoft's own link rewriter puts into every
URL it touches. That marker is dropped here (`LINK-uyoocslu`); the weight is
not, and the marker fix is not a substitute for the ruling above.

**Reserved special-use names, settled: report, never score** (`LINK-mgnbgicq`).
`svc.internal`, `foo.invalid`, `home.arpa` and the rest of the RFC 6761 set make
no false claim and provoke no disagreement, so they satisfy **none** of the three
forms and they do **not** score. The framing that left this open — "the same
string names different machines on different networks", i.e. context-dependence —
was the wrong axis, and it is recorded here as rejected: it is false of
`.invalid` and `.alt`, which name nothing on any network anywhere, and it is
false in the other direction of `.localhost`, which RFC 6761 §6.3 MANDATES to
resolve to loopback and which is therefore the least context-dependent name in
the set. Context-dependence was never the property they share.

What they do share is a fact fixed by a naming authority, uniform across the
whole set, and settleable offline for all time: each is **reserved, never
delegated in the global DNS root, never publicly resolvable**. That puts them
under the fourth rule, not under the three forms. `foo.invalid` is exactly the
shape the fourth rule's worked case has — well-formed, universally agreed, honest
about itself, and guaranteed never to work — so staying silent on it was the same
inconsistency `host_length_unresolvable` was written to close. The sharpened
form, as it stood when this was decided: `192.168.1.1` scored `0.20` because a
literal addressing a private network is worth mentioning, while `svc.internal`
scored `0.00` — a name reserved for that exact purpose, saying nothing at all.
Since §6.1.10 the literal reports at weight 0 as well, so the two now say their
piece the same way: `ip_private` and `special_use_name`, both at `0.00`.

`special_use_name` therefore reports at **weight 0** (schema `1.11`; `WEIGHTS_VERSION`
does not move, because a weight of 0 adds no scoring surface). Three boundaries
travel with it:

- **Suffixes only; the example DOMAINS are excluded.** RFC 6761 §6.5 reserves
  `.example` *and* `example.com`/`.net`/`.org`, but those are second-level
  reservations under a **delegated** TLD and they resolve — `example.com`'s
  public suffix is `com`. The line is "TLD-level reservation, never delegated"
  versus "second-level reservation under a delegated TLD", and it is not
  fastidiousness: roughly a quarter of the labeled corpus uses one of those hosts
  as a neutral stand-in.
- **Where a cloud-metadata code already names the host, the informational one
  suppresses itself.** `metadata.google.internal` sits under `.internal` and
  already carries `ip_cloud_metadata` (at `0.75` when this was decided, at weight
  0 since §6.1.10). The fourth rule's trigger is a
  `0.00` with no reasons, so a host that already carries a finding is owed
  nothing — and the predicate would be false where it landed, since that host's
  whole hazard is that it *does* resolve. The suppression reads the same table
  the metadata codes read, so the two cannot drift.
- **`.onion` label syntax is a separate, still-open question.** A v3 address is a
  56-character base32 pubkey plus checksum, so `ab.onion` announces a Tor
  identity it cannot be — form 3, and therefore **scoring**-eligible. Deciding it
  inside a weight-0 code would settle a scoring question by smuggling. Not
  decided here.

This also does **not** decide `LINK-qqwfpxvu` sideways. The axis rejected there
was *authority-fixed content licenses SCORING*. Nothing here scores: weight 0
defeats the deception objection and RFC-fixed content defeats the durability
objection, **both** are required, and neither suffices alone. `LINK-qqwfpxvu`
was later decided head-on, on this same line, and §6.1.10 records it: the
IANA-fixed address buckets report at weight 0 too.

**Handing back a modified URL, settled: the list doing the editing is a claim
about the world** (`LINK-sarsncoh`). The recurring request is a `sanitize()` —
return the URL with `utm_*`, `fbclid`, `gclid` and `msclkid` taken out. It is
declined, and the reason is *not* that the return value would be a string
instead of a verdict. It is that the list doing the removing asserts something
linklint cannot settle from the string: **that those query keys do not affect
the resource the URL addresses.** No standard says that. `utm_*` is a prefix
glob over a namespace no registry owns, and three literals plus a wildcard is an
opinion about whose analytics are worth dropping, not an enumeration — the same
distinction §6.1.5 draws when it deletes `bait_tokens` for reading a lexicon
rather than a standard. It is claim (b), pointed at the query string.

*The repo had already ruled this in code, silently.* `canonicalizeUrl` — a
public export of the declared `@linklint/online/mirrors` subpath — records that
"a different path or query is a different URL" and that it "preserves path and
query verbatim", and driven live it returns `?utm_source=nl&fbclid=abc&id=42`
unedited. `decodeEmbeddedWrapper`, the one public surface that returns a URL at
all, carries `utm_source` through into the destination it recovers. Query
content is already part of a URL's identity wherever linklint touches one, and a
sanitizer needs it to stop being that in exactly one place. §8 supplies the
other half: enforcement is the consumer's job and linklint reports the verdict,
so editing the caller's URL is acting on the caller's behalf.

*The weight-0 fallback is foreclosed with it.* A `tracking_parameters_present`
reason at weight 0 reads like the fourth rule applied, and it is not. §6.1.5's
procedure is to strip the world-claim and ask what string fact remains; what
remains here is "the query carries a key beginning `utm_`", which is the list
re-emitted with the score taken off — verbatim the move that deletion refused.

*What is declined is the class, not the proposal.* Any surface that returns a
URL a curated list has edited lands here whatever shape it arrives in: a second
field on the result, a `{ status, url, removed[] }` record, a parameter table
with its own version stamp. Versioning the list and documenting the losses
answers none of it, because the objection is not that the transform is
undeclared — it is that the transform is not settleable from the string. A
**stated non-goal and not a gap**. It is also one the mechanical gate does not
catch: `packages/core/test/public-api-contract.test.ts` pins the `metadata`,
`experimental` and `data` subpaths to exact key sets but checks root only as a
superset of `experimental`, so a new root export reddens nothing there and a
catalog held in a local `const` moves no `SCHEMA_VERSION`. This paragraph is the
guard, which is why it argues the class rather than the API shape.

Nothing in this section is open. What this section settles, and what
should therefore not be re-filed: well-formed-but-unusable strings, the path
layer, the agent-mode layer, the reserved special-use names and the cleaned-URL
output, all above (with the address destination codes applied in §6.1.10); the watchlist's name-never-create rule, combosquatting, and
the reading of a clean result, all below.

**The rule.** The brand watchlist (`data/brands.ts`) may only be consulted to
**NAME** a structural anomaly that was already detected independently. It may
**never CREATE** a finding. A detector whose firing condition depends on a
watchlist hit is claim (b) wearing claim (a)'s clothes; a detector that fires on
a structural precondition and then reads the list to say *what* the string folds
onto is claim (a).

This is the test — not list size, not tuning — that authorized deleting
`brand_lookalike`, `brand_soundsquat`, and `brand_bitsquat` (`LINK-cphogucn`,
schema `1.4` / weights `1.13`) while keeping `brand_homoglyph`,
`homograph_skeleton_collision`, `brand_idna_collapse`, and
`brand_locale_collapse`. The deleted three satisfied **none of the three forms**
— `normalize(input) === input`, no reader disagreed, and the string described
itself accurately; the only thing wrong with `paypai.com` is that a human might
misread it, which is claim (b). The survivors each carry a structural
precondition — a demonstrated fold, a demonstrated UTS#39 confusable, a
demonstrated disagreement between two standards' readings of the same host —
that is satisfied *before* the list is read. See §6.1.2 for the per-code record.

**The stated limitation.** linklint does not catch `paypal-login.com` or
`apple-id-verify.com`. Every label in both is a real, correctly spelled word in
a normal arrangement; nothing about either string is malformed, disguised, or
inconsistent. They score `0.00`/`info` and **that is the correct answer for what
linklint claims**. They read as suggestive only to a reader who already knows
PayPal and Apple are brands worth impersonating — which is claim (b).

**This is a scope boundary, not a bug and not a backlog item.** No issue should
be opened to "fix" it, and if either string ever starts scoring, that is a false
positive to investigate rather than a win. The distinction is visible in code:
`test/corpus/embarrassment.ts` carries genuine misses in
`EMBARRASSMENT_CORPUS` (asserted red until fixed) and these two in
`KNOWN_AND_ACCEPTED` (deliberately unasserted). The neighbouring case shows the
line is structural and not a matter of degree: since `LINK-lippdgpn`,
`paypa1-login.com` scores `0.80`/`high` because `paypa1` contains a digit that
folds to a letter, while `paypal-login.com` — the same shape, same pretext
token, no fold — stays at `0.00`.

**That limitation has a name and a measured shape** (`LINK-pralkaeo`).
`paypal-login.com` is not an arbitrary example: it is a textbook **combosquat** —
a correctly spelled brand token joined to an additive word, with no typo and no
homoglyph anywhere in the string. Kintis et al. (CCS 2017) measured the class
across six years of DNS data and found it **~100× more prevalent than
typosquatting** and, decisively, **largely benign** — the bulk of it is defensive
registration, partner and reseller sites, fan pages, and regional variants owned
by the brand itself.

That pairing is why combosquatting is a **stated non-goal and not a gap**. It is
invisible to every mechanism linklint has, by construction: there is no
misspelling for edit distance to measure, no confusable for the UTS#39 skeleton
to collapse, and `normalize(input) === input` so nothing folds. Detecting it
would require deciding that `paypal` is a brand worth protecting *and* that
`-login` is hostile where `-community` or `-developer` are not — claim (b) in
both halves. The base rate then makes it worse than merely out of scope: a
detector for this class is wrong most of the time it fires, on a class two orders
of magnitude larger than the one linklint does catch.

This is recorded history rather than a prediction. `brand_combosquat` shipped as
G3 (`LINK-phghrnqc`), was investigated (`LINK-cqdrdvfu`), and was deleted
outright with `brand_in_path` (`LINK-blgvypxk`) on exactly this reasoning; §6.1.2
applied the same rule to the three edit-distance detectors. Like the boundary
above, it should not be re-filed, and a proposal to restore the class has to
argue with Kintis' base rate first.

**The list's role.** The watchlist is **not a coverage mechanism and never will
be.** It is a bounded precision instrument that upgrades "this string is
structurally odd" to "this string is impersonating PayPal". Its charter is
therefore bounded, it is hard-capped, and additions are gated on measured
fold-reachability rather than on brand prominence (`LINK-stnruoge`). Growing it
buys sharper explanations of anomalies already found — never new findings.

**Why the literature ratifies this rather than merely permitting it.**

- **Liu et al., PhishIntention (USENIX Sec 2022)** — false alerts fell **86.5%**
  (1,033 → 139) at comparable recall, and the entire reduction came from adding
  a credential-taking check on top of brand resemblance. A URL-string detector
  has the resemblance half and none of the intent half, so it must not emit a
  phishing verdict from brand-lookalike strings.
- **Szurdi et al. (USENIX Sec 2014)** — "about half of the possible typo domains
  identified by lexical analysis are truly typo domains." **~50% is the ceiling
  for pure lexical squatting detection**, before malice is even asked about.
- **Tian et al. (IMC 2018)** — 657,663 lexical squatting candidates yielded
  **1,175 verified phishing domains (≈0.18%)**. The base rate of a claim-(b)
  string detector is catastrophic.
- **DynaPhish (USENIX Sec 2023)** — any fixed reference list is **inherently
  incomplete**. This is why the watchlist's hard cap is a correct posture and
  **not a defect**: an uncapped list would still be incomplete, while trading
  away the precision that is the list's only justification.

**A clean result is not a safety claim** (`LINK-vwjtdtzn`). The fail-closed
doctrine has always covered `invalid` — `score: null`, contract-tested, never a
fallback to a second parser — and the clean case needs the same discipline for a
stronger reason: it is the one that gets read as an endorsement. Turn the two
measurements above around. Szurdi puts the ceiling for pure lexical squatting
detection at **~50%**, and Tian finds that only **0.18%** of lexical candidates
are verified malicious. The first number says a structural detector misses about
half of what it is *chartered* to catch; the second says the chartered category
barely overlaps with malice in the first place. Together: **the absence of a
structural flag carries essentially no information about safety.**

So `0.00`/`info` means exactly one thing — *no structural anomaly was found in
this string* — and it must never be rendered, described, or field-named as
"safe", "clean", "OK", or "passed". This is not a caveat to attach where
convenient; it is a property of every surface that shows a result, and the CLI,
the MCP tool description, and the README each carry it. The L3 enrichment layer
already states the same rule for its own quiet outcome — "a no-match is not a
safety claim" ([`enrichment-outcomes.md`](enrichment-outcomes.md)) — and this is
that rule for L1.

The consumer-side consequence: a fail-closed integration must not treat a low
score as clearance. It composes linklint with other signals, or it treats
"unknown" as its default and lets linklint move a URL only in the *deny*
direction. `enforcement/` ships both wrappers this way — they deny on a
deceptive verdict and on invalid input, and a clean verdict merely fails to
trigger a denial rather than granting one.

**Offline-first is a correctness property, not only a privacy one**
(`LINK-riupozbo`). The zero-network core is described everywhere else in this
repo as a privacy, determinism, and latency property — no telemetry, nothing
leaving the machine, the same answer for the same string for all time. Those are
true, and they are the weaker half of the argument. The stronger half: **a
detector that never fetches cannot be served a decoy.**

Cloaking is the standard evasion against anything that does fetch. CrawlPhish
(Zhang et al., S&P 2021) documents **eight distinct client-side evasion types**
in deployed phishing kits — fingerprint the visitor, serve benign content to
anything that looks like a crawler, serve the attack to everyone else. PhishFarm
(Oest et al., S&P 2019) measured what that is worth: trivial cloaking cut
blocklisting by **more than 55%**. Every fetch-based detector is exposed to this
by construction, because the attacker controls the response and can tell the
detector and the victim apart.

linklint's input is the string the victim was actually handed. There is no
response for an attacker to vary, no visitor to fingerprint, and no
crawler-versus-victim divergence to exploit. This is **structural immunity, not
resistance** — not that cloaking linklint is hard, but that cloaking has no
surface to act on. It buys nothing against claim (b): a detector that never
fetches still cannot know what a site does, which is the same limit stated
throughout this section. Within claim (a), though, what linklint reads is
exactly what the victim was given.

**Where a denylist legitimately sits** (`LINK-riupozbo`). linklint is regularly —
and fairly — asked why the watchlist is not an allowlist. The answer is not that
denylists are underrated. It is that MITRE already positions them exactly where
linklint sits. CWE-20 (*Improper Input Validation*), verbatim:

> Do not rely exclusively on looking for malicious or malformed inputs. This is
> likely to miss at least one undesirable input [...] However, denylists can be
> useful for detecting potential attacks or determining which inputs are so
> malformed that they should be rejected outright.

Both halves are load-bearing, and quoting only the second would be the same
overclaim this section exists to prevent. The first half is why linklint is not
a gate, and it is the consumer-side consequence above restated by the authority
everyone cites when they say denylists do not work. The second half is the
charter: a **supplementary detection layer**, composing with an allowlist rather
than substituting for one. The two answer different questions — an allowlist
answers *may I go here*, which is a policy the caller owns and which §8 exposes;
linklint answers *is this string what it presents itself to be*, which no
allowlist can settle, because a string that folds onto an allowed host is
precisely the case an allowlist gets wrong.

## 2. Repository layout

```
linklint/
  packages/
    core/           # linklint npm package — inspect(), 40 checks, scoring, policy, schema
    mcp/            # @linklint/mcp — local-only MCP server (check_url / check_domain)
    cli/            # @linklint/cli — offline CLI (linklint check / batch)
    online/         # @linklint/online — Node/server safe transport + deterministic fixtures
  docs/
    architecture.md
    online-runtime-boundary.md # Accepted ownership/packaging decision for online work
    safe-transport.md # L0 authorization, pinning, budget, and outcome contract
    redirect-chain-resolution.md # L1 redirect/refresh authorization and evidence
    reason-codes.md # Full reason-code registry with detection logic and examples
    scoring.md      # Scoring model, severity bands, weights table (v1.3)
    locale-case-mapping.md # Locale-tailored case mapping audit (the Turkish-I class)
  features/         # Cucumber behavioral specs (critical path + acceptance criteria)
  tools/            # Data-build scripts (confusables table generation)
```

## 3. Core package

`packages/core` is the source of truth. Public entry points:

| Export | What |
|--------|------|
| `linklint` | Stable `inspect()`, schema types, `InspectOptions`; legacy advanced compatibility re-exports |
| `linklint/metadata` | Reason-code metadata, scoring weights, and data-version stamps |
| `linklint/experimental` | Unstable detector, policy, parser, and unicode APIs |
| `linklint/data` | Version-pinned reference data (risky TLDs, brands, confusables) |

All exports are synchronous and side-effect-free. No network, no filesystem I/O at runtime.
New advanced consumers should prefer the secondary entry points over root
compatibility exports.

Runtime dependencies: `tldts` (Public Suffix List) and `tr46` (IDNA/UTS-46).

## 4. Inspection pipeline

`packages/core/src/inspect.ts` orchestrates these stages in order:

1. **Input preparation** — trim whitespace, preserve original input, accept full URLs or bare hostnames. Bound all recursive decoding to prevent decode-bomb CPU paths.

2. **Structural scans** — control chars, invisible chars, bidi overrides, separator lookalikes are checked before parsing (these can't rely on the parser to surface them).

3. **Parsing** — produce canonical components: scheme, userinfo, host (labels, registrable domain, public suffix), port, path, query, fragment. Use PSL for eTLD+1. Return `status: "invalid"` instead of throwing for unparseable input.

4. **Normalization** — IDNA/UTS-46 normalization via `tr46`. Record deltas as informational findings (`normalization_delta`).

5. **Detector execution** — run 40 independent lexical checks: 4 structural scans ahead of parsing, then 36 parsed-context detectors. The 4 agent-gated parsed detectors run only under `agentMode`. A detector failure adds `lexical:<id>` to `checksSkipped` rather than aborting the inspection. Any skipped scoring detector means the score is a lower bound, not a complete verdict.

6. **Policy layer** (optional) — apply caller-configured allow/deny rules. Policy reasons carry `weight: 0` and never change `score` or `severity`.

7. **Scoring** — aggregate scoring reasons with probabilistic-OR: `score = 1 − ∏(1 − wᵢ)`. Weights are version-pinned.

8. **Serialization** — return the stable `InspectResult` schema with `checksRun`, `checksSkipped`, `schemaVersion`, and `dataVersions`.

## 5. Detectors

`packages/core/src/detectors/` contains 40 lexical checks: 4 structural scans and 36 parsed-context detectors. Parsed detectors implement:

```ts
interface Detector {
  id: string;
  layer: 'lexical' | 'resolution' | 'reputation';
  run(context: InspectionContext): DetectorFinding[];
}
```

Detectors emit findings only — they never read weights. The core attaches weights from the version-pinned table (`packages/core/src/scoring/weights.ts`) keyed by reason code.

The 40 checks group into six families (listed by **check id**; a single check
may emit several reason codes):

| Family | Detectors |
|--------|-----------|
| **Authority spoofing** | `userinfo_present`, `embedded_domain_in_subdomain`, `ambiguous_authority`, `ip_obfuscation`, `ip_classification`, `ambiguous_numeric_host`, `separator_lookalike`, `excessive_subdomain_depth`, `host_length_unresolvable`, `special_use_name`, `fqdn_root_label` |
| **Homographs & confusables** | `mixed_script`, `confusable_char`, `ascii_homoglyph`, `punycode_malformed`, `normalization_delta`, `idna_mapping_ambiguity`, `idna_protocol_violation`, `locale_case_collapse`, `homograph_latin_skeleton`, `idn_host` |
| **Brand impersonation** | `brand_homoglyph`, `homograph_skeleton_collision` |
| **Dangerous payloads** | `dangerous_scheme`, `file_extension_tld`, `suspicious_extension`, `open_redirect_param`, `header_shaped_token` |
| **Hidden characters** | `invisible_char`, `bidi_override`, `control_char`, `encoding_obfuscation`, `percent_encoding_malformed`, `low_byte_truncation`, `confusable_in_path`, `best_fit_mapping` |
| **Agent-gated** | `prompt_injection_url`, `credential_harvesting`, `data_exfiltration`, `ssrf_cloud_metadata` |

**Agent-gated is a caller-declared context, not a sixth kind of evidence.**
Those four run only when `InspectOptions.agentMode` is set, and §1.1 settles what
they may claim: a property of what one consumer does with the bytes after every
reader has agreed where they came from is reportable but not chartered to score,
and a consequence-weighted escalation requires a fact that is already settled
with the gate off. The per-code ruling lives in §1.1 (`LINK-uyoocslu`) and
shipped in schema `1.10` / weights `1.19` (`LINK-brsntven`): three of the four
report at weight 0, and `ssrf_cloud_metadata` is the only one that scores.

The **Contextual signals** family — `risky_tld` and `bait_tokens` — was deleted
whole in the same change (§6.1.5). Both created a scoring finding from curated
membership alone, which is the one thing the name-never-create rule forbids, and
neither left a string fact to re-ground at weight 0.

Informational detectors (`confusable_char`, `confusable_in_path`, `normalization_delta`, `idna_mapping_ambiguity`, `locale_case_ambiguity`, `host_length_unresolvable`, `special_use_name`, `fqdn_root_label`) have weight 0 — they annotate without raising severity. `idna_mapping_ambiguity` and `locale_case_ambiguity` each escalate to a weight-0.5 scoring code (`brand_idna_collapse`, `brand_locale_collapse`) when the alternate reading lands on a watchlist brand exactly.

**How `ip_classification`'s three data-backed pieces were decided.** Three
historical worklogs record the method behind the literal-IP surface — why the
bucket taxonomy is shaped as it is, which judgment calls sit on top of the
mechanical mapping, and what was measured rather than assumed:

- [`docs/worklog-qvsrmrzv-iana-ip-ranges.md`](./worklog-qvsrmrzv-iana-ip-ranges.md)
  — generating the range table from the IANA special-purpose registries, the
  bucket mapping, and why longest-prefix-match is load-bearing.
- [`docs/worklog-yyqnmipb-cloud-metadata.md`](./worklog-yyqnmipb-cloud-metadata.md)
  — the cloud-metadata endpoint table, and why both sides are canonicalized
  through the same parser instead of compared as text.
- [`docs/worklog-oficsfiw-embedded-ipv4-unwrap.md`](./worklog-oficsfiw-embedded-ipv4-unwrap.md)
  — unwrapping IPv4 embedded in the low-32 transition prefixes, and the split
  between "written non-canonically" and "points somewhere else".

Each is dated to the commit that shipped it and describes how a decision was
reached, not what the code does today; `packages/core/src/data/` and
`docs/reason-codes.md` are the current authority.

## 6. Result schema

Every channel returns the same `InspectResult` (schema version `1.14`):

```ts
interface InspectResult {
  schemaVersion: '1.14';
  status: 'ok' | 'invalid';
  input: string;
  parsed: ParsedUrl | null;
  score: number | null;            // [0,1] when ok; null when invalid
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | null;
  confidence: number;              // [0,1]; 1.0 for deterministic lexical, min-aggregated across enrichers (FR-SCORE-2b)
  reasons: Reason[];               // { code, layer, detail, weight, suppressed? }
  confusables: Confusable[];
  checksRun: string[];             // e.g. ['lexical', 'policy']
  checksSkipped: string[];         // e.g. ['resolution', 'reputation']
  dataVersions: DataVersions;      // PSL, confusables, scripts, IDNA, brands, weights versions
  pslSnapshot: PslSnapshot;        // { date, stale } — provenance + advisory staleness of the PSL trust boundary (schema 1.2)
  enrichment?: EnrichmentReport;  // inspectAsync with configured work; versioned outcomes/evidence (schema 1.3)
}
```

Key invariants:

- `status: "invalid"` → `score: null` and `severity: null`, always. Invalid input is **not** benign: `null` means *unscoreable*, never `0`. What `invalid` does **not** fix is the reason list or `checksRun` — those report whatever was determined before the parse failed, per §1.1's fourth rule. When a detector produced findings, `reasons` carries them and `checksRun` is `["lexical"]` (`checksSkipped`: `["resolution", "reputation"]`); the weight-0 `parse_error` is the **fallback** for when no finding explains the failure, and only that fallback shape has `checksRun: []` (`checksSkipped`: `["lexical", "resolution", "reputation"]`). `buildInvalidResult` in `src/schema/serialize.ts` is the contract.
- **What an invalid result may carry.** Any reason code at its full registry weight, scoring codes included — `https:///evil.com` is `invalid` and carries `ambiguous_authority` at **0.65**. So neither reading of the old silence holds: an invalid result is not restricted to weight-0 reports, and its weights are not inert decoration. The rule is that they are *evidence, not arithmetic*: `aggregate()` runs on the `ok` path only, so a weight here is the registry severity of that one finding and nothing more. Never sum them, re-derive a `score`, or infer a `severity` from them — `status`, not `score`, is the field a gate reads (`docs/scoring.md` §"Gating on results").
- `score: 0` → `severity: "info"`. A parsed URL with zero scoring weight is benign even when informational reasons are present.
- `dataVersions` is present on both valid and invalid results for reproducibility.
- `pslSnapshot` (schema 1.2) is present on both valid and invalid results. `date` is the deterministic provenance date of the bundled PSL snapshot (the pinned `tldts` release date — a packaging proxy, so the true list is that date **or older**); `stale` is an **advisory, time-relative, one-directional** verdict — the one field on the result that reflects wall-clock time — `true` only when the snapshot is provably past the 180-day window, and `null` (undetermined) both when the date is unknown and while the proxy bound is still inside the window. See §6.1.
- `enrichment` (schema 1.3) is present only when `inspectAsync()` receives configured enrichers. It contains independently versioned source outcomes/evidence and is absent from synchronous and empty-plan output.
- A non-empty `confusables[]` requires a corresponding `confusable_char` or `confusable_in_path` reason, and vice versa.
- If a lexical scoring detector fails, its ID appears in `checksSkipped` as `lexical:<id>`. The layer stays in `checksRun`; the score is a lower bound. Fail-closed consumers should treat results with `lexical:*` in `checksSkipped` as untrusted rather than benign.
- If a policy axis fails, it appears in `checksSkipped` as `policy:<axis id>` (`tld`, `host`, `scheme`, `port`) and the other axes still report. The channel token `policy` stays in `checksRun`, and the score is unaffected — policy findings are weight 0, so a skipped axis is a gap in the **policy** verdict, not in the deception verdict. Bare `policy` in `checksSkipped` is the rarer case: the dispatcher itself failed, no axis verdict exists, and `policy` is correspondingly absent from `checksRun`. The two lists never carry the same token.
- If the caller supplies an option key `inspect()` does not recognize, that key appears in `checksSkipped` as `options:<key>`; if the options argument itself is not a usable object, it appears as bare `options`. The namespace is deliberately `options:` and not `policy:` — an unrecognized key is not attributable to an axis (`maxDecodeDeph` is not a policy typo), and `policy:<axis id>` is pinned to the four axis ids above. As with the policy channel, the bare and qualified forms never describe the same run. Absent an unrecognized key neither token appears, so the default path is byte-for-byte unchanged. This closes a **fail-open** that only a runtime caller could hit: TypeScript rejects an unknown key on an object literal, but options arriving as JSON — MCP tool input, a config file, plain JS — silently lost the whole channel, and `{ allowHost: [...] }` was indistinguishable from configuring no policy at all (`LINK-sjsxfqoo`).
- `confidence` is `1.0` for every deterministic lexical result (sync `inspect()`, including `status: "invalid"`). It is **independent** of `score`/`weight` and never feeds score aggregation; `inspectAsync()` lowers it to the **minimum** over the lexical base (`1.0`) and each successful probabilistic enricher finding's `confidence` (default `1.0`). With no enrichers it stays `1.0`, so `inspectAsync(url)` remains deep-equal to `inspect(url)`.
- `Reason.suppressed` is an OPTIONAL marker, present and `true` only when the caller's `suppressReasons` escape hatch (§8) matched that reason. With no `suppressReasons` option every result is byte-for-byte identical to the pre-existing `1.1` output. Byte-identity on the default path is **not** the bump test, though (§6.4): an optional field is still a serialized field, so this addition owed a `SCHEMA_VERSION` bump and did not get one — it entered the contract at `1.1`. `CHANGELOG.md` records the miss instead of baselining it in silence; it is not retro-bumped only because no package has ever been published.

### 6.1 PSL snapshot provenance & staleness

linklint's core claim — "the real host is `evil.com`" — is computed from the
Public Suffix List bundled inside `tldts` (pinned via
`dataVersions.publicSuffixList`). A silently stale bundled PSL degrades
embedded-domain / brand-homoglyph / ambiguous-authority reasoning with no signal
to callers, so the trust boundary carries its own provenance:

- **Provenance record** (`src/data/psl-provenance.ts`, `PSL_PROVENANCE`): a
  hand-captured `{ tldtsVersion, pslListDate, dateKind, retrievedAt }` verified
  at dependency-pin time. `tldts` publishes no snapshot timestamp of any kind, so
  `pslListDate` is the pinned `tldts` npm-release date and `dateKind` records
  what that date is: `"release-proxy"`. `tldts` regenerates its bundled list from
  upstream *at or before* release-build time (`S ≤ R`), so the age computed from
  it is a **lower bound** — a *minimum* age, not the age. Bump the fields
  together with `dataVersions.publicSuffixList` on every `tldts` pin; a
  `dateKind: "exact"` record (none exists today) would make the age exact.
- **`pslOutdated(maxAgeDays = 180)`**: a **pure, offline** check reading only the
  provenance record → `{ stale, ageDays }`. The verdict is *one-directional*,
  because the evidence is: a minimum age past the window proves staleness
  (`true`); an unknown/unparseable date gives `{ stale: null, ageDays: null }`;
  and a proxy bound still inside the window also gives `stale: null` —
  undetermined, never assumed either way. Only an `"exact"` date returns `false`.
- **`result.pslSnapshot`**: `{ date, stale }` surfaced on every result so
  consumers learn the provenance of the boundary they were handed.
- **Freshness-corpus CI** (`test/freshness-corpus.test.ts`): pins the IMC '23
  (McQuistin et al., Table 2) multi-tenant eTLDs so a stale bundled PSL can never
  silently reintroduce the paper's tenant-collapse harm — two distinct tenants
  of `myshopify.com` etc. must not collapse to one registrable domain.

**Documented tradeoff — `allowPrivateDomains: false`.** `analyzeHost()`
(`parse/psl.ts`) resolves under ICANN-only rules **deliberately**, so an embedded
`github.io` is still seen as a registrable domain by FR-D-8. The consequence,
from the same IMC '23 paper, is that at the linklint layer private-suffix tenants
*do* collapse onto the ICANN registrable domain (`good.myshopify.com` and
`evil.myshopify.com` both resolve to `myshopify.com`). This is a conscious
tradeoff, **not** changed here; the freshness gate probes `tldts` with
`allowPrivateDomains: true` (the view where these eTLDs live) to test the bundled
*data's* freshness independently of that policy.

**Upstream conformance corpus (U2).** The freshness gate above answers "is the
bundled list recent?"; it does not answer "does the list still resolve the way it
did?". `test/psl-conformance.test.ts` closes that gap by running the **entire**
upstream `tests/tests.txt` (78 rows, vendored at
`test/data/psl-tests.txt` and pinned by `sha256`) against `analyzeHost()` on
every check — wildcards (`*.mm`, `*.ck`), exceptions (`!www.ck`, `!city.kobe.jp`),
deep nesting (`k12.ak.us`), uppercase, unlisted TLDs, and IDN labels in both
U-label and A-label form. **71 of 77 host rows match upstream verbatim (92.2%).**
The 6 that do not are enumerated in an exact ledger — an undeclared divergence
*and* a ledger entry that stopped diverging both fail — in two classes, each with
a positive proof rather than an allowlist entry:

1. **PRIVATE-section suffixes** (4 rows, the `uk.com` family). Upstream exercises
   the full list; linklint is ICANN-only per the tradeoff above. Proven to be
   exactly that flag: re-running those rows with `allowPrivateDomains: true`
   reproduces every upstream expectation.
2. **Leading empty label** (2 rows, `.example.com` / `.example.example`). `tldts`
   tolerates a leading dot; linklint's parser rejects an empty label first
   (`parse/raw-parts.ts`), so the input never reaches the PSL layer. Proven by
   asserting `inspect()` returns `status: "invalid"` for both — while a single
   *trailing* root dot still parses.

Neither class is a defect, and neither is silently allowlisted. A `tldts` pin
bump that moves any other row fails here, before it can surface downstream as an
unexplained scoring change.

**Decision — the boundary stays global, and the brand family stays ICANN-only.**
A per-detector boundary choice was investigated and **declined**. Three findings,
in order of weight:

1. **Switching the brand family to the PRIVATE-inclusive view fires nothing.**
   `brand_homoglyph` requires the digit-folded registrable domain to be an exact
   `BRAND_DOMAINS` member. Handed the PRIVATE-inclusive view, `paypa1.vercel.app`
   folds to `paypal.vercel.app`, which is not a watchlist domain. The widening on
   its own is inert — it would only *look* like coverage. (At the time this was
   measured, `brand_lookalike` — a bounded edit distance over the whole
   registrable domain — was also inert here, at distance far above 2 from
   `paypal.com`. It has since been deleted outright; see §6.1.2.)
2. **Making it fire means comparing the tenant label, which reopens a closed
   decision.** Reducing to the tenant label (`paypa1` → `paypal`) does match, but
   the same mechanism matches *any* tenant whose label is a brand label — and
   roughly two dozen of the 106 entries in `BRAND_LABEL_SET` are ordinary English
   words: `apple`, `amazon`, `visa`, `chase`, `oracle`, `uber`, `ledger`,
   `discord`, `telegram`, `blockchain`, `kraken`, `ups`, `stripe`, `slack`,
   `zoom`, `box`, `cash`, `live`, `meta`, `target`, `booking`, `wise`, plus the
   single character `x`. On platforms whose whole purpose is cheap tenant
   namespaces, `target.myshopify.com` and `cash.github.io` are unremarkable. That
   is the false-positive surface `LINK-blgvypxk` closed by deleting
   `brand_in_path` and `brand_combosquat` outright, and it would return by
   another route. Note that the generic-word guard which used to live in the
   `keywords` field of `data/brands.ts` was deleted alongside `BRAND_KEYWORDS`,
   while `BRAND_DOMAINS` kept those brands — so nothing currently prevents this.
3. **The exclusion list that would make it safe is itself a judgment call.**
   Which labels count as "ordinary words" cannot be settled by reading the list;
   it needs an adversarial corpus of unseen tenant labels, because a
   hand-curated benign set is self-confirming — precisely how the
   `brand_combosquat` false-positive surface stayed hidden until it was probed
   against unseen hosts (`LINK-cqdrdvfu`).

**Accepted limitation.** A brand-impersonating tenant on a PSL PRIVATE-section
platform is **not** detected: `paypal.myshopify.com` scores `0.00`/`info`, where
`paypa1.com` scores `0.84`/`critical`. (The *digit-folded* half of this limitation —
`paypa1.vercel.app` at `0.20`/`low` — is **no longer true**: it now scores
`0.80`/`high`, one band below `paypa1.com`, which stacks `ascii_homoglyph` on top. See §6.1.1 and `LINK-lippdgpn`.)
This is the same accepted-limitation class as `paypal-login.com`
scoring `0.00` — deliberate, and preferred over a detector that flags legitimate
tenants. The IMC '23 multi-tenant rows in `test/corpus/vectors.ts` (which forbid
`embedded_domain_in_subdomain` and `ambiguous_authority` on legitimate tenants)
are the standing tripwire against reintroducing this by another route.

> **Partly superseded — see §6.1.1 (`LINK-pblqdrco`).** The `paypal.myshopify.com`
> half of this limitation stands unchanged and permanently: exact-label matching
> stays rejected, and findings #2 and #3 above were re-tested and **confirmed**.
> The `paypa1.vercel.app` half — the *digit-folded* case only — was reopened with
> the unseen-tenant corpus finding #3 asked for, and **adopted**. Read the two
> entries together: what changed is not the boundary and not exact matching, only
> that a label whose digits fold to a brand label is now treated as the same
> disguise on both sides of the PRIVATE boundary.

**Unchanged:** FR-D-8 / `embedded_domain_in_subdomain` keeps ICANN-only
semantics, which is what the tradeoff above exists to protect.

**Declined (`LINK-mfpwgspt`).** Exposing *both* boundaries on `HostFacts` is
mechanically easy, but adds a second PSL lookup to every `inspect()` against the
sub-5 ms budget, plus a permanently wider type surface on which every future
detector picks between two similarly-named fields with a subtle correctness
difference and no compiler help. It was held open on the rule "build the seam
when a detector needs it" — the same rule applied to the `parse.ts` split — and
then the only candidate consumer was removed by the decision recorded above, so
the seam has no call site to serve. The PRIVATE-inclusive view is already
computed directly where it is genuinely needed — for a long time in test code
only (`test/boundary-baseline.ts`, `test/freshness-corpus.test.ts`,
`test/psl-conformance.test.ts`), and since `LINK-vycgfumd` in one **production**
module as well (`src/compare/compare-urls.ts`, §6.1.9) — none of which this seam
was blocking. If a detector ever does need it, refile: compute both views in
`analyzeHost()`, share once per `inspect()`, keep the existing field bound to
the ICANN-only value, and add no caching (pslr D19).

The production call site added in §6.1.9 does **not** meet that refile
condition, and the seam therefore stays declined. It is not a detector, it is
not on the `inspect()` path, and it reads the other view through a separate
`privateRegistrableDomain()` in `parse/psl.ts` rather than through `HostFacts` —
so the sub-5 ms budget is untouched and no future detector is handed a second
similarly-named field to pick between. Read the condition as "a **detector**
needs it", which is how it was written.

Note for anyone arriving from the accepted limitation above: escalating
`paypa1.vercel.app` does **not** require this seam. That question was
`LINK-pblqdrco`, now **decided and adopted** in §6.1.1 — and it was adopted on
exactly the path described here, joining the skeleton `ascii_homoglyph` already
computes to `BRAND_LABEL_SET` over the host labels: a set membership test, with
no PSL boundary involved. This seam stays declined; the adopted mechanism needs
no call site for it.

#### 6.1.1 Digits in labels — fold-gated brand escalation (adopted) and a general digits signal (declined)

Two independent questions, recorded together because they were raised together
(`LINK-pblqdrco`). The trigger was the 3x score gap in §6.1's accepted
limitation: `paypa1.com` → `0.84`/`critical`, `paypa1.vercel.app` → `0.20`/`low`,
same disguise, same reading. `ascii_homoglyph` fires in both cases and its detail
already names the reading (`paypa1` reads as `paypal`); the whole delta is
`brand_homoglyph`, which never gets a look because it tests the *registrable
domain* and `paypa1.vercel.app`'s registrable domain is `vercel.app`.

**(a) Label-level fold-gated brand escalation — ADOPTED.**

The mechanism: for each host label that already passes `ascii_homoglyph`'s gates,
if folding its digits yields a `BRAND_LABEL_SET` member, escalate. A set
membership test over `ctx.hostLabels`. **No PSL boundary change** — the
`LINK-mfpwgspt` seam declined above is not a prerequisite and was not revived.

§6.1's finding #3 set the evidence bar: reasoning over our own brand list is
self-confirming, so this needs a corpus of *unseen* tenant labels. Four
measurements, in order of weight:

1. **The firing surface is finite, enumerable, and small.** Because the gate
   requires `fold(label) !== label` *and* an exact hit in `BRAND_LABEL_SET`, the
   complete set of labels that can ever fire is the set of valid pre-images of a
   brand label under the fold. Enumerated at adoption: **65 of 106** brand
   labels fold-reachable, giving a surface of **192 labels**. The watchlist has
   grown since; today it is **68 of 111** brand labels, yielding **exactly 197
   labels**, pinned member by member in `test/brand-fold-surface.test.ts`, which
   re-derives both the membership and this paragraph's numbers from the shipped
   detectors. This is the decisive structural difference from every
   previously-rejected brand widening — it is not a heuristic with an open-ended
   surface but a list that can be read.
2. **Zero false positives on 36,200 unseen real tenant labels.** A GitHub login
   *is* the tenant label for `<login>.github.io`, so the login list is an
   unfiltered corpus of real multi-tenant labels. 7.3% contain a digit; **427
   (1.18%) pass `ascii_homoglyph`'s gates and already score `0.20`/`low` today**;
   **none folds to a `BRAND_LABEL_SET` member.** The reason is structural, and it
   is the crux: the common benign digit-in-label pattern is a *numeric
   suffix or counter* — `mwalker1`, `haru01`, `jramirez00` — which folds to
   gibberish (`mwalkerl`, `haruol`, `jramirezoo`). Firing requires a digit
   *mid-word, standing in for the letter that spells a brand*, which is the
   attack signature itself. Length equality under the fold also means no
   `shop1`-style label can ever reach a shorter brand label.
3. **Live probe of the entire surface: no legitimate tenants.** All 192 labels
   of the surface as it then stood probed against `github.io`, `vercel.app`,
   `myshopify.com` (576 probes) — 25 live. Classified by fetched title:
   impersonation (`app1e` → "Apple iPhone", `bank0famerica` → "Bank of America",
   `faceb0ok` → "Facebook", `paypa1` → "Paypal", `robl0x` → "Roblox Cookie
   Capture"), platform-suspended (`402`), or
   **legally taken down** (`bl0ckchain.vercel.app` → `451`). **Not one is a
   legitimate business operating under an unrelated name.** The ordinary-word
   brands that drove finding #2 — `apple`, `amazon`, `booking`, `telegram`,
   `blockchain` — appear here only as `app1e`, `amaz0n`, `b00king`, `te1egram`,
   `bl0ckchain`, and every live one of those is impersonation, suspended, or
   taken down.
4. **Control group — finding #2 was right, and this is not the same mechanism.**
   The identical probe against the 106 **unfolded** labels returns **127 live
   `200`s**, including the brands' *own official* orgs (`microsoft.github.io`,
   `google.github.io`, `adobe.github.io`, `cloudflare.github.io`,
   `netflix.github.io`, `oracle.github.io`, `stripe.github.io`,
   `salesforce.github.io`) and the ordinary-word tenants finding #2 named
   (`target.github.io`, `cash.github.io`, `box.github.io`, `uber.github.io`),
   plus 14 more at `451`. Exact-label matching has a ~40% live-tenant surface
   dominated by legitimate use — flagging it would flag brands impersonating
   themselves. The fold-gated surface is 4.3% and dominated by abuse. **That
   ~10x gap is the argument the standing "document-and-stop" rule required to be
   won rather than assumed:** the fold gate is a structural property of the
   input, not a curated exclusion list of the kind §6.1 finding #3 rejected.

**Residual risk, stated plainly.** Roughly 4–6 of the 25 live hits are
benign *by content* while being a brand look-alike *by name*:
`sa1esforce.vercel.app` and `salesf0rce.vercel.app` serve an unrelated "Brunch"
template, `g0ogle.github.io` is a personal page, `sh0pify.github.io` is Shopify
tutorial content. Escalating these to `high` is accepted, on consistency: the
ICANN-side `brand_homoglyph` already scores `paypa1.com` `critical` without any
content evidence, because the claim it makes is *"this host's name is a
digit-disguised brand"* — which is true in 25 of 25 cases here — not *"this is
phishing"*. The alternative is to keep scoring the same disguise 3x differently
based on which side of a boundary the attacker rented space on.

**Tripwire gap found while testing this.** The IMC '23 multi-tenant rows named as
§6.1's standing tripwire contain **no digits** (`myshop.myshopify.com`,
`docs.readthedocs.io`, …), so they cannot fire under this mechanism either way
and provide **no protection against it**. Implementation must add rows that
actually bind: benign digit-bearing tenant labels that fold to gibberish
(`pete1.github.io`, `haru01.github.io` — both `0.20`/`low` today and must stay
there) alongside the positive `paypa1.vercel.app` case, plus a test asserting the
enumerated surface is unchanged so a brand-watchlist addition cannot silently
widen it.

**Implemented (`LINK-lippdgpn`).** Filed as `LINK-tbqeqqvv` and delivered by
`LINK-lippdgpn`, which chose the **hyphen token** — not the whole host label —
as the unit of analysis, so one mechanism covers both `paypa1.vercel.app` and
`paypa1-login.com`. `brand_homoglyph` now runs two tiers, deduped so a host
matching both still emits exactly one reason: tier 1 the registrable domain
against `BRAND_DOMAIN_SET` (unchanged), tier 2 every `-`-separated token of
every host label against `BRAND_LABEL_SET` under the identical fold gate. It
reuses the existing `brand_homoglyph` reason code and changes no weight, so
neither `SCHEMA_VERSION` nor `WEIGHTS_VERSION` moved. The tripwire rows this
entry demanded (`pete1.github.io`, `haru01.github.io`) are in
`test/corpus/vectors.ts`, and the surface pin is
`test/brand-fold-surface.test.ts`. One behavioural difference from the mechanism
as sketched above: the escalation is **not** gated on the label first passing
`ascii_homoglyph`, so leading-digit folds (`0racle-support.com`) also fire — at
`0.80`/`high` rather than `0.84`/`critical`, exactly as `0racle.com` already did
on the registrable-domain tier.

**(b) A general digits-in-label signal — DECLINED, including as an optional knob.**

The premise — legitimate brands rarely put digits in domains, and digits are a
classic SEO-spam marker — does not survive contact with the corpus. **1.18% of
real tenant labels pass these gates**, roughly 1 in 85 hosts, and measurement 2
shows what they are: ordinary developer usernames with a counter (`pete1`,
`number5`, `snoozer05`, `jcoppedge1`, `testapi11`). Only 5.2% of them fold to
even a dictionary word. There is no precision floor to build on — the gates
select for *digit-in-word shape*, which is a necessary condition for the
disguise but nowhere near sufficient, and that is exactly why `ascii_homoglyph`
is weighted `0.2` and documented to "only matter in combination". Those 427
labels scoring `0.20`/`low` is the correct outcome, not a missed escalation.

Declined as an optional policy knob too, for a different reason: "digits in the
domain" is a ranking-quality preference, not a deception verdict, and belongs to
whatever consumer holds that preference rather than to a URL-deception linter.
The benign classes cited in the original request are already spared without any
new policy — `z100` and `kiss108` fail the letters-outnumber-digits and
unmapped-digit gates respectively, and `987fm` fails the leading-letter gate — so
a knob would buy no coverage the existing gates withhold. Revisit only if a
concrete consumer asks for it, and then as consumer-side policy over the
`ascii_homoglyph` reason code, which already carries the skeleton in its detail.

**How the evidence above was obtained:**
[`docs/worklog-pblqdrco-digits-in-labels.md`](./worklog-pblqdrco-digits-in-labels.md)
— a historical worklog recording the enumerate-then-probe method, the control
group that won the argument, and the scripts needed to redo the measurement
rather than trust its numbers. Its counts are dated; this section and
`packages/core/test/brand-fold-surface.test.ts` are the current authority.

#### 6.1.2 Structurally-clean brand near-misses — deleted (`LINK-cphogucn`)

**Decision — `brand_lookalike`, `brand_soundsquat`, and `brand_bitsquat` are
deleted outright.** Removed in schema `1.4` / weights `1.13`. This is a
scope-of-claim correction, not a tuning change, and it is not about list size.

The claim and the rule this decision applies are stated canonically in
**§1.1** — claim (a) STRUCTURAL over claim (b) SEMANTIC, and the
name-never-create rule. Read that section for the reasoning and the supporting
literature; this section records only what the rule did to these three codes.

The three deleted detectors broke the rule. They fired on inputs where
`normalize(input) === input`:

| Deleted code | Example | Structural state of the input |
|--------------|---------|-------------------------------|
| `brand_lookalike` | `paypai.com` | pure ASCII, single script, no digits, no fold |
| `brand_soundsquat` | `netflicks.com` | pure ASCII, single script, no digits, no fold |
| `brand_bitsquat` | `netfliz.com` | pure ASCII, single script, no digits, no fold |

Nothing about these strings is anomalous. They are suspicious only relative to
knowing that `paypal` and `netflix` exist and are worth money — brand
intelligence, not URL structure. And they cannot be made to generalize: each
works for exactly the N hand-picked domains on the list and no others, forever.
This is the same disposition `LINK-blgvypxk` gave `brand_in_path` and
`brand_combosquat`, for the same reason.

**Survivors, and why they are different.** `brand_homoglyph` fires only when
`skel !== raw` — a digit demonstrably folded to a letter — and
`homograph_skeleton_collision` only when UTS#39 confusables are demonstrably
present. Both carry a structural precondition that is satisfied *before* the
watchlist is read; the list only names the target. Neither can fire where
`normalize(input) === input`. `brand_idna_collapse` and `brand_locale_collapse`
sit on the same footing: a divergence between two standards' readings is the
structural fact, and the brand match is the name for it.

**Accepted, deliberate loss of coverage.** `paypai.com`, `gogole.com`,
`netflicks.com`, `netfliz.com`, and `amazgn.com` all score `0.00`/`info`. That is
the intended outcome, asserted directly in `test/brand-homoglyph.test.ts` and
carried as *benign* rows in the corpus so a future widening has to argue with
them. A free consequence: `anthropics.com` — Anthropics Technology Ltd, a real UK
business that sat at edit-distance 1 from `anthropic.com` — stops reading
`medium`/`0.40`.

**Consequence for the watchlist charter.** Fold-reachability is now the *only*
structural route onto `data/brands.ts`. The charter's former escape hatch ("a
stated non-fold justification — edit-distance or soundsquat coverage, say") no
longer names anything that exists; a brand label with no pre-images under the
ASCII digit fold buys nothing and should be declined.

**Naming debt (closed, `LINK-hyezxjda`).** The surviving check carried the id
`brand_lookalike` in `detectors/brand-lookalike.ts` while emitting only
`brand_homoglyph` — a legacy name for a step whose only reason for that name had
been deleted. The check id is now `brand_homoglyph`, the module is
`detectors/brand-homoglyph.ts`, and the exported detector is `brandHomoglyph`.
Check id and reason code now coincide, as they already did for
`confusable_in_path`, `dangerous_scheme`, and most of the registry.

**The compat question, and why it did not force a schema note.** The check id is
public surface in three places, and each was checked rather than assumed:

| Surface | Exposure | Disposition |
|---|---|---|
| `checksSkipped` | `lexical:<id>`, written only when the check *throws* at runtime | Not the shape of the contract — `checksSkipped` is typed `string[]` with no enumerated domain, and the entry appears only on a should-not-happen fault path |
| Exported symbol `brandLookalike` | `linklint/experimental` (documented **Unstable**) plus the root's legacy advanced-compatibility re-export | Renamed outright; no deprecated alias |
| Families table (§ above) | Lists check ids | Updated in the same change |

No `SCHEMA_VERSION` bump: the result shape is unchanged and no field gained or
lost a documented value. No deprecated alias export either — both packages are
`0.1.0-dev.0` and unpublished (the npm publish decision is still open under
`LINK-reilfhac`), so there is no released consumer holding the old symbol, and
shipping an alias would preserve a name for nobody at the cost of keeping the
deleted detector's vocabulary alive in the public surface. Reverse the alias
decision only if a first release ships before this lands — it has not.

#### 6.1.3 External domain lists as a watchlist source — declined (`LINK-gruclwmr`)

**Decision — no external domain list is imported into `data/brands.ts`, in whole
or in part.** The watchlist stays hand-curated under the §6.1.2 charter: harm in
one step, fold-reachability, ~150-entry cap. This entry records the evaluation so
the recurring "Chrome ships a list, just use it" proposal arrives already
answered.

**What Chrome actually ships.** Three distinct assets, and only the third is an
allowlist:

| Asset | Role | Availability |
|-------|------|--------------|
| `spoof_checks/top_domains/domains.list` + `.skeletons` | spoof **target** list — an IDN whose UTS#39 skeleton collides with an entry renders as punycode | BSD-3, in the open-source tree |
| `top_bucket_domains.h` (~top 500) | same, plus edit-distance and keyword checks; drives the "Did you mean…?" interstitial | BSD-3, in the open-source tree |
| Lookalike Warning Allowlist | the actual **allowlist** — suppresses known false positives | component-updated, not in the tree, not extractable |

The first is what the proposal usually means, and it is not a trust list. Its
header reads `generated from chrome-ux-report.all.202309 by
fetch_crux_domains.py` — a **popularity** list (CrUX), ~3 years stale as shipped,
filling exactly the role `BRAND_DOMAINS` already fills in
`homograph_skeleton_collision`. Chrome's protection against over-firing is not
the list; it is site-engagement scoring, redirect-chain checks for defensive
registrations, and that third asset — none of which an offline linter has.

**Measured against the code (2026-07-27), 8,462 CrUX entries:**

1. **It loses coverage where the harm is.** 33 of the 108 curated
   `BRAND_DOMAINS` are absent from it — `venmo`, `visa`, `mastercard`,
   `revolut`, `monzo`, `hsbc`, `santander`, `metamask`, `ledger`, `trezor`,
   `okta`, `cloudflare`, `anthropic` — while it adds thousands of news,
   regional-media, torrent and adult domains where deception costs a wasted
   click. Popularity is the wrong axis; charter test 1 is harm.
2. **It detonates the fold surface.** `brand_homoglyph` pre-images go from
   **608 → 69,392** (domain tier) and **252 → 30,906** (label tier), ~120×.
   §6.1.1 cleared the standing document-and-stop rule *because* its surface is
   197 strings and therefore exhaustively probable. At 30,906 that argument does
   not exist.
3. **Tier 2 becomes the `LINK-blgvypxk` regression again.** `BRAND_LABEL_SET`
   would absorb 7,761 labels, **448 of them ordinary dictionary words, 320 of
   those fold-reachable** — `code`, `fast`, `news`, `list`, `live`, `mail`,
   `mobile`, `service`, `public`, `action`, `auto`, `author`, `index`,
   `people` — plus 901 labels ≤ 4 characters including literal `com`, `it`,
   `co`, `as`. Since tier 2 joins every `-`-separated token of every host label
   against that set, `c0de-review.example`, `mai1-relay.corp.net` and
   `serv1ce-auth.acme.io` would all score `0.80`/`high`. That is the
   unbrowsable-internet failure at roughly 4× the density that caused it.
4. **Recorded in the list's favour, for fairness.** The list is internally
   clean: **0** intra-list skeleton collisions, and only **2** intra-list fold
   collisions (`sport5`→`sports`, `tf1`→`tfl`). The objection is fitness for
   purpose, not data quality.
5. **Size.** 113 KB raw / **47 KB gzip** — about 6× the entire generated
   confusables table and roughly 2× the 25 KiB gzip threshold in
   `docs/bundle-size-budget.md`.

**The narrow slice, and why it is declined too.**
`homograph_skeleton_collision` is gated to non-ASCII registrable domains, so its
firing surface is independent of the digit fold, and measurement 4 says the list
does not self-collide. Widening *only* that detector's skeleton table —
decoupled from `BRAND_DOMAINS` so `brand_homoglyph` never sees it — is
defensible and is literally what Chrome does; it also satisfies §1.1's
name-never-create rule, since a skeleton collision is a demonstrated fold.
Declined anyway on two grounds: it adopts Chrome's firing side without Chrome's
suppression side (see the table above), and §6.1.1's evidence bar —
enumerate, probe an unseen corpus, run a control group — is not dischargeable
here, because there is no unseen-IDN corpus to probe 8,462 skeletons against.
Precision would be asserted rather than measured.

**Reverse-engineered component lists (`think.resoneo.com/chrome-classification`).**
A separate family: a ~30,000-domain "Gemini AI restriction" list (banks, crypto,
tax authorities, central banks, healthcare), a ~30,000 semantic-memory list, and
merchant classification, all partially extracted from component payloads. The
first is classified by **sensitivity**, which is genuinely better aligned with
charter test 1 than CrUX popularity — that much of the idea is sound, and it is
why this family gets its own paragraph rather than the same one. It still fails,
for different reasons:

- **Provenance.** Every entry in `DATA_VERSIONS` is a citable, redistributable,
  version-pinned standard — UTS#39, the IANA special-purpose registries, the PSL
  via `tldts`, vendor-documented metadata endpoints. This is an unlicensed
  payload extracted from a proprietary binary, silently mutated by the component
  updater, with **no version identifier to pin**. Importing it would make
  `brands: "<date>-watchlist"` a stamp that means nothing.
- **Partial and unverifiable.** 11,277 of ~30,000, with no way to know which
  19,000 are missing and no way to re-derive the extraction.
- **The tier-2 surface is unchanged.** Sensitivity-classified is not the same as
  structurally distinctive: a finance/health corpus is dense with `health`,
  `care`, `pay`, `bank`, `secure`, `trust`, `credit`, `fund`, `medical`.

One correction the framing needs in both cases: "too sensitive for a model to
act on" is a **caution** classification, not a trust assertion, and `domains.list`
is a target list. A popular phishing clone sits on the same side of both lines as
the real bank. Neither is the allowlist the "prefer whitelists to blocklists"
argument asks for.

**What survives.** The idea worth keeping is that the watchlist is curated on a
*harm* axis, which it already is. A published classified list could serve as a
**candidate generator for human review** — filtered to fold-reachable labels,
diffed against the current entries, accepted or rejected one line at a time under
the existing cap. That is not an import and would not change any mechanism.
Offered and not taken up on 2026-07-27; expected yield was judged low, because
the watchlist already covers the major banks, card networks, crypto custody and
tax software, and additions are gated on fold-reachability rather than fame.
Reopen only against a concrete named gap — never by importing a list wholesale.

#### 6.1.4 `api_endpoint_impersonation` — deleted (`LINK-eurtxkit`)

**Decision — `api_endpoint_impersonation` and its `data/api-brands.ts` tier are
deleted outright.** Removed in schema `1.9` / weights `1.18`. Like §6.1.2 this
is a scope-of-claim correction, not a tuning change, and it was carried 2–1.

The rule is §1.1's: claim (a) STRUCTURAL over claim (b) SEMANTIC, under which a
watchlist may only NAME a structural anomaly and may not manufacture one on its
own. The detector's firing condition was
`API_BRAND_DOMAINS.get(token)` — a lookup into a hand-kept watchlist of ten
commercial API providers — with corroboration from either an exact `api`/`apis`
token in some host label or one of four fixed route prefixes. Both corroborating
signals are ordinary URL syntax that any site is free to use, so neither
supplies a structural precondition; they narrow *how often* the watchlist is
consulted without changing *what the watchlist is doing*. The lookup was the
finding. That is claim (b) wearing claim (a)'s clothes.

The control makes it checkable. `api.openai-login.com` and `api.acme-login.com`
are the same string shape — pure ASCII, single script, no fold, no digit, an
`api` label and a hyphenated `<word>-login` label on a `.com` eTLD. The first
read `0.50`/`medium` under `agentMode` and the second read `0.00`, and the only
difference between them is that `openai` is on the list. Nothing a URL parser
can see separates the two.

**The double-score it removes.** `api.openai.com.evil.io/v1/chat/completions`
scored `0.50`/`medium` in plain mode from `embedded_domain_in_subdomain` — a
real registrable domain parked in another's subdomain, a structural fact stated
once. Under `agentMode` the api detector read the SAME `openai` label and
stacked a second `0.50` on it, taking the row to `0.75`/`high` with no
additional evidence observed. Both modes now agree at `0.50`.

**Accepted, deliberate loss of coverage.** `api.openai-com.io/`,
`api.openai-com.io/v1/chat/completions`, `api.anthropic-com.co/v1/messages` and
`openai-api.io` all score `0.00`/`info`. The first two are carried as *benign*
rows in the corpus, alongside `api.openai-login.com` and its `acme` control, so
a future widening has to argue with them. The V4e false-positive guards
(`myproject.github.io`, `storage.googleapis.com`, `openai.example.com`, …) were
converted from `forbidReasons` rows to plain benign rows rather than dropped —
the claim they make is unchanged, and it no longer names a code that cannot be
emitted.

**What survives, and why it is different.** `brand_homoglyph` still reads
`api.0penai.com/v1/chat/completions` at `0.80`/`high` in PLAIN mode, with no
agent gate, because a digit demonstrably folds to a letter (`skel !== raw`)
before the watchlist is consulted — the list only NAMES the target. That is the
same survivor test §6.1.2 applied, and the same reason `brand_idna_collapse` and
`brand_locale_collapse` stand.

**Consequence for `data_exfiltration`.** It is NOT covered by this decision and
was deliberately excluded from it. It consults no data table, so the argument
above does not reach it; its disposition is `LINK-uyoocslu`.

**Implemented (`LINK-eurtxkit`).** The detector module, `data/api-brands.ts`,
the registry entry, the reason code, the weight, the docs entry and the corpus
positives are all removed; the mechanical `REASON_CODES` pin in
`packages/core/test/docs-validation.test.ts` was confirmed to redden on the
REMOVAL before the bumps were applied, which had previously only been
demonstrated for an addition.

#### 6.1.5 The contextual-signal tier — deleted (`LINK-brsntven`)

**Decision — `risky_tld` and `bait_tokens` are deleted outright, and the three
agent-gated dispositions §1.1 recorded as owed are shipped.** Removed and
re-weighted in schema `1.10` / weights `1.19`. Like §6.1.2 and §6.1.4 this is a
scope-of-claim correction, not a tuning change, and it was carried 3–0 on scope.
§5's **Contextual signals** family is gone whole: seven families become six.

**What both detectors were.** `risky_tld` was a public-suffix presence check
followed by `RISKY_TLDS.has(tld)` — a lookup into a hand-kept set of sixteen
high-abuse registries — and nothing else. `bait_tokens` counted distinct members
of a seventeen-word English lexicon (`secure`, `verify`, `account`, `login`, …)
across the host and the path and fired above a density threshold. Each emitted
`0.15`. `mycompany.tk` read `0.15`/`low` and
`secure-account-verify-login.com` read `0.15`/`low`, in both cases from
membership alone.

**Why the rule reaches them.** §1.1's name-never-create rule says a curated
table may NAME a structural anomaly and may never CREATE a finding. `RISKY_TLDS`
is such a table and the lookup WAS the finding. `bait_tokens` reads a lexicon
rather than a domain list, which changes what is being looked up and not what is
being done with the answer: `normalize(input) === input`, every conforming
parser agrees where `secure-account-verify-login.com` goes, and the string
describes itself accurately — none of the three forms. The only thing wrong with
it is that a reader who already knows what phishing looks like finds it
suggestive, which is verbatim the argument §1.1 makes about `paypal-login.com`.
The two strings scored differently only because one carried more suggestive
words, and §1.1 records that the line is structural rather than a matter of
degree.

**Why deletion rather than weight 0, and the test that decides it.** §6.1.4
supplies the procedure: strip the world-claim and ask what string fact remains.
For `credential_harvesting` the OAuth flow shape remained, so it is re-grounded
at 0 rather than deleted. For `api_endpoint_impersonation` nothing remained, and
it was deleted. Here nothing remains either — the residue of `risky_tld` is "the
public suffix is `tk`", which `parsed` already carries, and the residue of
`bait_tokens` is "the host contains English words". Reporting either at weight 0
would not be applying the fourth rule; it would be re-emitting the world-claim
with the score removed.

And the weight-0 slot for the TLD judgment **already belongs to the caller**:
`denyTlds` emits `tld_denied` at weight 0, `allowTlds` emits
`tld_not_allowlisted`. That answer was only half true in practice, because
`packages/cli/src/args.ts` shipped ZERO policy flags — a `linklint check` user
lost the signal with no lever at all. `--deny-tld` and `--allow-tld` are added
in this change so the answer holds on the tool's main surface, and both policy
summaries in `schema/reason-codes.ts`, which named the deleted detector, are
rewritten.

**The three agent-mode dispositions, applied.** `prompt_injection_url` `0.50` →
`0`, `data_exfiltration` `0.30` → `0`, and `credential_harvesting` `0.35` → `0`
with `data/oauth-providers.ts` deleted: the flow shape is now reported for every
host, `github.com` included. The inverse allowlist was the same claim-(b)
structure as the api-brands watchlist run backwards, and §1.1 forbids it in
either polarity. Their §1.1 ruling table is restated from *owed* to shipped, and
its drift guard is unchanged and still bites — it reads each ruled code's weight
from `REASON_CODES` and compares it to the number in the table, so all three
rows now have to read `0.00`.

**The `DataVersions` field is RENAMED, not deleted.** `FILE_EXTENSION_TLDS`
lives in the same module and `dataVersions.riskyTlds` is its only pin. Dropping
the field would strand a live, exported, weight-`0.4` scoring table with no
version stamp, against NFR-DATA-1. The module becomes
`data/file-extension-tlds.ts` and the stamp becomes
`dataVersions.fileExtensionTlds`, carrying its value forward unchanged.
`SCHEMA_VERSION` owns the rename because `DataVersions` is part of the
serialized result (§6.4).

**Measured cost.** Every row of the labeled corpus, the embarrassment corpus
and the accepted-out-of-scope list was inspected THREE ways before and after —
under the row's own declared options, with `agentMode` forced OFF, and with it
forced ON — and every verdict diffed. That is 1 040 verdicts on the before side
and 1 055 after, and the forced variants are the point: an agent-family row
carries `{ agentMode: true }` of its own, so a diff that only honours row
options leaves those inputs unobserved with the gate off. **41 verdicts change: 6
with the gate forced off, 35 with it on or declared.** Precision and recall are
`1.000` / `1.000` on each side. `risky_tld` appeared on 3 distinct inputs,
`bait_tokens` on 3.

The 6-versus-35 split is itself the result worth reading. With the gate off, the
ONLY thing that moved is the deletion of the two membership-only detectors, and
it moved exactly the six rows below. Everything else in this change is confined
to a mode the caller has to ask for.

*Six rows move band on the deletion,* identically in every mode:

| Input | Before | After |
|---|---|---|
| `https://promo-login.tk/` | `0.150`/`low` | `0.000`/`info` |
| `https://secure-account-verify-login.com` | `0.150`/`low` | `0.000`/`info` |
| `https://a.b.c.d.paypal.com.evil-login.tk/` | `0.639`/`high` | `0.575`/`high` |
| `https://paypa1-secure-login.com` | `0.830`/`critical` | `0.800`/`high` |
| `https://login.paypal.com.account.evil.com/` | `0.575`/`high` | `0.500`/`medium` |
| `https://login.paypal.com.evil.tk` | `0.575`/`high` | `0.500`/`medium` |

The last two cross the shipped `--fail-on high` default. Both are
`embedded_domain_in_subdomain` at `0.50` — which sits EXACTLY on the medium/high
edge — plus a `0.15` companion. `paypa1-secure-login.com` changes band without
crossing that default, and is now carried entirely by the `brand_homoglyph`
fold, which is the right reading: the fold is the structure, and the pretext
words were not.

*Two further rows move band on the agent dispositions,* under `agentMode` only,
where `credential_harvesting`'s `0.35` had been stacking on
`open_redirect_param`:
`https://example.com/login?redirect_uri=http://169.254.169.254/&client_id=x` and
`https://idp.example.org/authorize?client_id=x&redirect_uri=https://myapp.io/cb&next=https://evil.com`,
both `0.610`/`high` → `0.400`/`medium`. That is the ruling working as written —
the open-redirect finding is the structural one and still stands at its own
weight; what is gone is a second `0.35` charged for the same bytes on the
strength of a list.

*Eight agent rows drop to `0.000`/`info`* and keep their reason with weight 0.
*Four provider rows gain a weight-0 `credential_harvesting`* they were
previously suppressed on. Every other verdict in both modes is byte-identical.

One test fixture moved too, and is worth recording because it shows how thin the
old `high` was: `packages/cli/test/policy.test.ts` and `run.test.ts` used
`https://www.gооgle.com@bad.tk/login` as their `high` case. The Cyrillic
homoglyphs are in the USERINFO, not the host, so the only structural finding was
`userinfo_present` at `0.50` and the band came entirely from `risky_tld`. It now
reads `0.500`/`medium`, and both fixtures move to a deep-subdomain phish that
reaches `high` from two structural findings and no membership lookup.

The corpus also gains four benign rows on free-registry TLDs (`mycompany.tk`,
`.ml`, `.xyz`, `.top`). It had **none** before, which is why `risky_tld`'s
false-positive surface was invisible to the harness and the measured cost of
deleting it read as zero for the wrong reason.

**`embedded_domain_in_subdomain` stays at `0.50`. Decided, not defaulted.** The
alternative was to raise it above the edge so those two rows keep failing a
default run. It is refused on three grounds.

*It is not a targeted repair.* Eleven distinct inputs across the corpora carry
the code, and after this change **nine** of them read exactly `0.500`/`medium`
with no companion at all. (`LINK-vuqdzmzy` later took `metadata.google.internal.evil.com`
out of that set, so the live count is eight — §6.1.6. The count moved; the
argument below did not.) `0.500` is the medium/high boundary, so ANY raise
above it moves all nine into `high` at once — the weight is a single number and
cannot be applied to two rows. Two of the nine are the rows this change dropped;
the other seven were `medium` before this change too, and would newly fail a default
`--fail-on high` run. That is **seven new failures to restore two**, in the
direction (precision) that §1.1's cited literature says is the instrument's only
justification. The seven are ordinary embedded-domain shapes —
`paypal.com.spoof.info`, `paypal.co.uk.evil.com`, `www.eu.paypal.com.evil.info`
and the rest — which the corpus already labels `deceptive` at `medium`, and
which no evidence in this change touches.

*There is no new evidence about embedded domains.* Nothing about the detector
moved in this change; what moved is that a companion signal was deleted. Raising
this weight to preserve a band the companion produced would launder the deleted
world-claim into a different code, which is the move §1.1 refuses for
`credential_harvesting`'s allowlist — inverting or relocating a claim does not
change what it is. If the `high` was reachable only via a curated list, the
`high` was borrowed and not earned.

*The tier is coherent as it stands.* `0.50` is the shipped "medium alone, high
in combination" band, shared with `userinfo_present`, `separator_lookalike`,
`suspicious_extension`, `brand_idna_collapse`, `brand_locale_collapse` and
`homograph_skeleton_collision`. The one authority code above it,
`ambiguous_authority` at `0.65`, earns the gap with a strictly stronger fact —
two parsers reaching two hosts (form 2). `embedded_domain_in_subdomain` already
needs two false-positive carve-outs to stay quiet on ordinary naming: the
ICANN-suffix gate for `sub.domain.example.co.uk` and the region-code gate for
`www.eu.playstation.com` (`LINK-pbilvjuv`). A signal needing two carve-outs does
not belong in the band above that one.

Nothing is lost from the finding itself: both rows still emit
`embedded_domain_in_subdomain` with its full detail at `0.500`/`medium`, and
`--fail-on` is a caller threshold — the caller who wants embedded-domain hosts
to fail sets `--fail-on medium`, which is the same shape of answer as
`--deny-tld` above. Both rows are pinned at their NEW bands in
`test/corpus/corpus.ts` and in
`packages/core/test/semantic-tier-retirement.test.ts`, so a future re-raise has
to argue with them rather than discover them.

**Accepted, deliberate loss of coverage.** `mycompany.tk`, `promo-login.tk`,
`secure-account-verify-login.com` and `update-billing.example.tk/confirm/password`
all score `0.00`/`info`. The first three are carried as benign corpus rows, and
the `bait_tokens` false-positive guards (`accounts.google.com`,
`login.microsoftonline.com`, `example.com/account/login`) were converted from
`forbidReasons` rows to plain benign rows rather than dropped — the claim they
make is unchanged, and it no longer names a code that cannot be emitted. That is
the disposition §6.1.4 gave the V4e guards, applied again.

**Implemented (`LINK-brsntven`).** Both detector modules,
`data/oauth-providers.ts`, the two registry entries, the two reason codes, the
two weights, the docs entries, the `RISKY_TLDS` / `isRiskyTld` public exports
and the two corpus positives are removed; `data/risky-tlds.ts` is renamed
`data/file-extension-tlds.ts` and `dataVersions.riskyTlds` renamed
`dataVersions.fileExtensionTlds`; the three agent-gated weights are `0`; the CLI
gains `--deny-tld` / `--allow-tld`. The mechanical `REASON_CODES` pin in
`packages/core/test/docs-validation.test.ts` was confirmed to redden on this
two-code REMOVAL before the bumps were applied, reporting
`{ added: [], removed: ["bait_tokens", "risky_tld"] }` — previously demonstrated
for an addition and for a single-code removal.

#### 6.1.6 FR-D-8's window suffix class — narrowed to two measured classes (`LINK-vuqdzmzy`)

`embedded_domain_in_subdomain` fires on any contiguous window of subdomain
labels that is itself an ICANN registrable domain. Which *suffix* the window
ends in was not part of the firing condition, so `console.cloud` under
`google.com` was read exactly like `paypal.com` under `spoof.info`. Measured
over four external corpora, those are not the same kind of string.

**The measurement — ADOPTED.** Corpora, retrieved 2026-08-25 and re-retrieved
for this change: Cisco Umbrella top-1M (DNS resolver traffic, 998,065 hosts),
CrUX top-1M origins snapshot `202605` (browsed pages, 998,066), Phishing.Database
`phishing-domains-ACTIVE` (386,177) and PhishTank `online-valid` (38,754). Two
structurally different benign corpora and two phishing corpora, because a single
pair proves nothing about robustness. Benign hosts appearing in either phishing
list were removed first (519 from Umbrella, 563 from CrUX).

Nothing external was imported. These lists were read from gitignored scratch
space, and no byte of any of them reached `data/`, the test corpus, or any
committed file — the prohibition in `data/brands.ts` is scoped to *import into
shipped data*, and §6.1.3 reached its own decline of CrUX by measuring CrUX,
which is the precedent this follows.

The rule can only fire on a host with **≥ 2 subdomain labels**, and the corpora
differ enormously in depth (Umbrella 40.6% at-risk, CrUX 3.0%), so a
whole-corpus rate mixes "how deep are these hostnames" with "does the rule
discriminate". Every rate below is conditioned on that at-risk population.

Likelihood ratio per host, `P(fire | phishing) / P(fire | benign)`, by the
public-suffix class of the winning window:

| window suffix class | benign CrUX vs phishDB | benign Umbrella vs phishDB | operator-deduplicated |
|---|---|---|---|
| multi-label ccTLD (`co.uk`, `co.jp`) | **57.87** | **10.30** | 25.78 – 117.11 |
| bare legacy gTLD (`com`, `gov`) | **7.33** | 0.86 | 3.85 – 14.37 |
| 2012-round gTLD (`cloud`, `news`, `apple`) | **0.26** | **0.29** | 0.44 – 0.52 |
| pre-2012 expansion gTLD (`info`, `travel`, `post`) | **0.21** | **0.08** | 0.55 – 0.64 |
| multi-label under a legacy gTLD (`in-addr.arpa`) | n/a | 0.00 | 0.00 |

The expansion-era ratio sits below 1 in all eight benign × phishing × counting-unit
combinations, range 0.26 – 0.52, and the class ordering is the same in all
eight. A finding 2–4× more common on a benign host than on a phishing one is
not evidence of deception, and under probabilistic-OR its `0.50` was dragging
real URLs up a band.

**The cut is by DELEGATION ERA, not by word.** That is what makes it shippable.
It is not a curated list of infrastructure-looking TLDs: no per-word sub-class
survived the measurement — of the 26 words the original report named, only
`.host` cleared LR 1 against CrUX, and every one of its phishing hits is GoDaddy
shared-hosting reverse DNS (`0.232.205.92.host.secureserver.net`), where the
attacker chose nothing. A word list is the self-confirming trap this section
warns about (`LINK-cqdrdvfu`). Nor is it "legacy gTLD only", which is what the
original ticket proposed: `.info`, `.travel`, `.post`, `.jobs` and `.asia`
predate the 2012 round and measure with it rather than with `.com`, so a cut
drawn at "the 2012 round" lands in the wrong place. Delegation era is closed
registry history — a fact that does not move with the world, which is what makes
it admissible where a judgment call is not.

**Not derivable offline, stated plainly.** Neither `tldts`'s compiled PSL nor
anything else vendored in this repository carries a delegation date, so the
legacy set is written down as the eight-element constant `LEGACY_GTLDS` (RFC 920
plus `int`). It is a hand-typed list, and calling it anything else would be
false. What keeps it out of §6's trap is not its size but its provenance: it was
copied from delegation history, not selected by looking at which TLDs produced
false positives, and it is finished — no future delegation can join it. The
ccTLD half needs no list at all, reusing the two-letter IANA reservation
`LINK-pbilvjuv` already relies on.

**What it buys, measured on the shipped binary before and after.** On the
at-risk population:

| corpus | fires before | fires after | at-risk fire rate |
|---|---|---|---|
| Umbrella (benign) | 74,722 | 28,335 | 18.47% → 7.00% |
| CrUX (benign) | 4,222 | 210 | 14.00% → 0.70% |
| Phishing.Database | 5,848 | 4,286 | 11.44% → 8.38% |
| PhishTank | 113 | 16 | 4.71% → 0.67% |

The whole-rule likelihood ratio moves from 0.82 to **12.04** (CrUX vs phishDB)
and from 0.62 to **1.20** (Umbrella vs phishDB). Against PhishTank it stays
below 1 (0.96 and 0.10) and that is reported rather than dropped: PhishTank is
URL-level, 78.3% of its hostnames have a single subdomain label because most of
its entries are phishing *pages* on compromised legitimate sites, and after the
change its firing cell holds 16 hosts. It is the instrument that disagrees, and
it is the weakest one here.

Before the change, 2,188 distinct registrable domains in the CrUX top-1M — real,
browsed sites — owned at least one host scoring `0.50`/`medium` on this rule
alone, among them `console.cloud.google.com`, `www.tax.service.gov.uk`,
`n.news.naver.com`, `www.post.japanpost.jp` and Amazon's real Belgian
storefront. Afterwards, 110 do.

**Accepted recall cost, stated as `LINK-pbilvjuv` stated its own.** 1,656
phishing hosts across the two feeds stop being scored — 3.05% of at-risk
Phishing.Database hosts and 4.04% of at-risk PhishTank hosts — spread over 803
distinct registrable domains. Roughly a third sit under bulk hosting whose
naming the attacker did not choose: `windows.net` (204 hosts, Azure Static
Websites' own `z13.web`), `duckdns.org` (113), `secureserver.net` (96, GoDaddy),
`ovh.net`, `fastly.net`, `cprapid.com`. The rest is a long tail, and part of it
*is* attacker-chosen: `id.security` (57), `mail.office` and its spellings (78),
`pancakeswap.finance` (25), `login.netflix`, `account-update.amazon`. The
original report described this cost as overwhelmingly infrastructure names; on
this re-measurement that is an overstatement, and the honest figure is about a
third. `metadata.google.internal.evil.com` is the case that lands inside the
repository: its only window is `metadata.google`, so it drops from
`0.50`/`medium` to `0.00`/`info` and is carried as a converted corpus row rather
than deleted.

The cost is smaller than a count of currently-reported windows predicts, because
a skipped window does not abort the scan. `appleid.apple.com.evil.tk` contains
both `appleid.apple` and `apple.com`; the `.apple` window used to win on
position and now falls through to the `.com` window on its right. That rescues
64 of the 85 phishing hosts whose reported window was `appleid.apple`, and is
why the measured cost is 3.05% rather than the 3.49% the naive count gives.

**No version stamp moves.** No reason code is added, renamed or removed, so
`ReasonCode`'s closed domain is unchanged; no weight and no band moves. Under
§6.4's matrix this is a firing-condition change reusing an existing code at an
existing weight, which is the disposition §6.1.1 took, and it is what
`LINK-pbilvjuv` — the previous narrowing of this same detector — did.

**Implemented (`LINK-vuqdzmzy`).** `suffixCarriesSignal` replaces
`isRegionCodeSuffix` in `src/detectors/embedded-domain.ts`, subsuming the
region-code carve-out into the positive test; fifteen corpus rows in both
directions land in `test/corpus/corpus.ts`, including the Azure recall-cost row;
`test/embedded-domain-suffix-class.test.ts` was pinned to the pre-change
behaviour one commit earlier and inverted here, with 18 of its 30 assertions
verified RED against the previous source. The corpus had **zero** rows in either
direction whose window sat under an expansion-era suffix, which is why the
harness could not see this defect for three waves.

#### 6.1.7 DGArchive membership as a detection source — declined (`LINK-ylxoeubd`)

**Decision — exact DGArchive membership is not bundled and does not score.** It
is recorded here because the proposal is attractive on its detection properties
and will otherwise recur: pre-generated DGA families match exactly, offline, at
a very low false-positive rate, which reads as an unusually good fit for the
charter.

It is not a fit, and the reason is not the data. **List membership is
reputation evidence, not a structural property of the string.** §1.1 admits a
finding on three forms — a normalization delta, disagreement between conforming
readers, or a false self-description — plus the fourth rule that reports a
determinable-from-string property at weight `0`. A domain drawn from a DGA
satisfies none of them: `kq3v9z7x1t.com` normalizes to itself, every conforming
parser agrees where it points, and it claims to be nothing it is not. What
makes it suspicious is that someone recognizes the string, which is exactly the
watchlist rule in §6.1.2 already governs: it admits a list only as a way to
**name** a structural anomaly the string itself exhibits, and membership is not
such an anomaly. Bundling DGArchive
would put claim (b) back through the door claim (a) was built to hold, so this
belongs to the Layer 3 reputation roadmap and not to the offline pipeline.

**The bundle-size budget is not the reason, contrary to how the question was
filed.** `test/bundle-size-budget.test.ts` gates the generated confusables data
against dataset-specific thresholds and the minified bundle against a total; a
new dataset would answer only to the latter. The budget would have to be
measured, not assumed, and it is not what settles this.

Two premises in the original decision issue were wrong and are corrected here
rather than left to mislead a future reader: core carries **ten** pinned
datasets in `DATA_VERSIONS`, not the two the issue named, so a third is not the
step-change it implied; and the issue's anchor line describes `brand_homoglyph`
behaviour rather than anything about DGA, quoting `0.50`/`0.60` scores that the
built package now reports as `0.80`/`0.84`.

#### 6.1.8 Per-label homograph evaluation — the gap is recorded, not closed (`LINK-aronhrrq`)

**Decision — `homograph_latin_skeleton` keeps its registrable-domain scope, and
the subdomain gap it leaves is recorded here as a positional limitation.**
`LINK-vtfyaizy` declined per-label evaluation 2–0 on measured false-positive
cost, and both verifiers asked that the underlying gap be carried forward rather
than closed with that decision. This is that record.

**The gap, re-measured at `0ad4566`.** The same disguised label scores
differently according to where it sits:

```text
https://сһаѕе.com/          → 1.00 critical   homograph_latin_skeleton + idn_host + collision
https://сһаѕе.example.com/  → 0.00 info       weight-0 codes only
https://сһаѕе.bad.co.uk/    → 0.00 info       weight-0 codes only
```

The 0.00 is not this detector's doing alone. Every scoring code in the IDN
family is scoped to the registrable domain, so `idn_host` (0.7) and
`homograph_skeleton_collision` (0.5) drop out too. An ordinary Unicode
subdomain reads the same way: `пример.example.com` is 0.00/info while
`пример.рф` is 0.70/high.

**The scope question is three-way, not two-way, and that resolves the
weight objection.** `LINK-vtfyaizy` recorded a conceptual problem that reads as
fatal: this detector's weight of 1.0 is grounded in *the whole host reads to a
human as an ASCII domain*, which is false of `гора.рф`, so a per-label finding
would carry a fragment-level fact under a host-level verdict. That objection is
sound against **per-label** scope. It does not reach a third option neither the
proposal nor the decline considered — the **whole effective host**, with the
public suffix carve-out of `LINK-ubzfajzm` left in place. Under that scope the
firing condition *is* the weight-1.0 justification, word for word:
`сһаѕе.example.com` skeletonizes to `chase.example.com`, and the whole host does
read as an ASCII domain. Today's code tests something narrower than its own
prose describes; per-label would test something wider. Only the middle option
matches it.

The fragment-versus-host framing also overstates how novel a subdomain-sourced
blocker would be. `mixed_script`, this code's weight-1.0 sibling, already
iterates `hostUnicode`'s labels and issues a host-level critical from a single
label — `paypаl.example.com` is 1.00/critical on `main` today.

**What the whole-effective-host scope would and would not reach, measured.** It
has to be a union with the shipped registrable-domain test rather than a
replacement: `пример.сһаѕе.com` fires today and its whole-host skeleton retains
`пpимep`, so replacing the scope would drop a true positive and hand attackers a
one-label evasion. As a union it reaches `сһаѕе.example.com`,
`сһаѕе.bad.co.uk` and `сһаѕе.tenant.github.io`. It does **not** reach the
namespaces whose measured cost killed per-label: `гора.рф`, `собор.рф`,
`сахар.рф` and `google.бг` stay exactly where they are, because a suffix that
retains a non-ASCII codepoint keeps the whole-host skeleton non-ASCII.

**Why it is not adopted here: the fourth bar cannot be discharged, and the
arithmetic shows why.** `LINK-pblqdrco` remains the standard a widening has to
meet — zero false positives across 36,200 unseen hosts. Re-measured
independently against the pinned confusables table over six 50k frequency lists
(ru, bg, sr, uk, el, mk): **1,902 of 256,288 non-ASCII word types — 0.74% —
skeletonize to pure ASCII**, 7.74% frequency-weighted, rising to 19.6% at label
length 2 and 30.2% at length 1. A mechanism with a measured 0.74% conditional
false-positive rate against ordinary vocabulary cannot return zero across 36,200
samples that exercise it; the expected count is roughly 270. And a corpus that
returned zero would have done so by containing no folding non-Latin subdomain
labels at all — which is §6.2's recorded artifact rather than a pass.

That artifact reproduced here on cue: simulating the union scope across all
**377 distinct corpus inputs flips zero rows**, so `pnpm check` would stay green
through the change. This is the third recorded instance, after `LINK-tydjfmci`
(§6.2, thorn-to-p and `thingvellir.is`) and `LINK-vtfyaizy`.

What `LINK-pblqdrco` could do and this cannot is exhaust its firing surface. Its
mechanism admitted exactly 192 pre-images, so it was probed completely and
against a control group. The surface here is open — every string over the
Latin-confusable subset of Cyrillic and Greek — so no sample settles it.

**Two of the four bars the re-file sets are already discharged, and one was
resolved the other way round.** Public-suffix exclusion (bar 1) shipped under
`LINK-ubzfajzm` and is documented in `docs/reason-codes.md`. The ASCII-letters
coherence gate (bar 2) was measured as strictly dominated — it cleared 4 of 16
suffixes while dropping 3 true positives — and the prose was corrected to match
the guard instead. A future proposal owes bars 3 and 4 only.

**The honest cost of the decision, stated plainly.** The same string fact draws
opposite verdicts by position: `агора.com` and `бебе.com` are 1.00/critical on
`main`, while `агора.example.com` and `бебе.example.com` are 0.00/info. Those
Cyrillic words are among the false positives `LINK-vtfyaizy` named as
disqualifying, and they already ship as critical in the registrable-domain
position — where the residual is accepted and documented, with `suppressReasons`
as the remedy. Consistency therefore argues for closing the gap, and the
measured false-positive rate argues against paying weight 1.0 for it. This entry
resolves that tension toward document-and-stop because the false-positive volume
in real traffic went unmeasured: it turns on how often a folding non-Latin label
sits left of an ASCII registrable domain, and Certificate Transparency
(`crt.sh`) was returning 502 on every query at decision time.

**What a future proposal must supply**, given the above: (a) a base-rate
measurement of non-ASCII subdomain labels under ASCII registrable domains, from
Certificate Transparency or passive DNS, since that is the one input missing
here; (b) a label-scoped suppression key, because `applySuppressions` matches the
registrable domain, so a caller whose one tenant label trips a blocker can only
respond by disarming it platform-wide; and (c) an argument for the weight. A
lower-weighted sibling is the option this entry declines to pick between — the
`embedded_domain_in_subdomain` precedent puts a deceptive label sequence left of
a truthfully-named registrable domain at 0.50 on the reasoning that the authority
the user reaches is displayed correctly, and that reasoning transfers intact.

#### 6.1.9 URL relationship comparison — `compareUrls()`, and the first production PRIVATE-inclusive call site (`LINK-vycgfumd`)

**Decision — a two-URL relationship comparator, ADOPTED.** `inspect()` asks
whether one string is deceptive. "Do these two URLs address the same origin, or
the same site?" is a different question about two strings, and `LINK-nlkfsnnd`
settled 2–0 that the package answers it. `compareUrls(left, right)` in
`src/compare/compare-urls.ts` is that answer. It scores nothing, emits no reason
codes, and reads only what the parser already derives.

**Why it is not a caller-side one-liner, measured rather than asserted.** The
proposal that it be documentation instead of code — "callers can derive this
from `inspect().parsed`, which already ships `scheme`, `effectiveHost`, `port`
and `registrableDomain`" — was tested by writing that derivation out and running
it. `test/parsed-origin-derivation.test.ts` holds both halves: `parse()` reports
what was *written*, which is what the character-level detectors need, so four
normalizations a comparison requires are absent from `ParsedUrl`, and the
strongest derivation an informed caller can write over that surface returns the
wrong answer in five distinct classes.

| Case | What `parsed` reports | What the derivation concludes |
| --- | --- | --- |
| `https://ex.com:443/` vs `https://ex.com/` | `port` 443 vs `null` | correct, after the caller supplies a default-port table |
| `http://EX.com/` vs `http://ex.com/` | `effectiveHost` `EX.com` vs `ex.com` | correct for ASCII, by `toLowerCase()` |
| `https://ex.com./` vs `https://ex.com/` | `effectiveHost` `ex.com.` vs `ex.com` | correct, by dropping the root label |
| `https://münchen.de/` vs `https://xn--mnchen-3ya.de/` | hosts differ, **and so do the registrable domains** | **wrong** — two origins, two sites |
| `data:`, `file:`, `about:blank` against themselves | every host field `null`, `status: "ok"` | **wrong** — one origin, one site |
| `http://0x7f000001/` vs `http://127.0.0.1/` | hosts differ | **wrong** — two origins |
| `https://alice.github.io/` vs `https://mallory.github.io/` | one registrable domain, `github.io` | **wrong** — one site |

The fourth row is the decisive one: no field of `ParsedUrl` puts the two IDN
spellings of one host on the same value, `registrableDomain` included, because
tldts is handed the spelling it was given. Closing that row needs a UTS-46
implementation, which is a dependency this package already carries and a caller
would have to acquire. The burden here was on shipping the export rather than on
withholding it, and the measurement discharged it.

**Specified semantics.** `sameOrigin` follows the WHATWG URL Standard's origin
comparison over a canonical `(scheme, host, port)` tuple: the scheme is
lower-cased by the parser, the port is elided when it is the scheme's own
default, an IP literal takes its canonical rendering (so `0x7f000001` meets
`127.0.0.1`, and `[0:0:0:0:0:0:0:1]` meets `[::1]`), and a domain goes through
UTS-46 ToASCII, which folds case and reconciles the A-label and U-label
spellings in one step. There is exactly **one** deliberate divergence from the
standard, the trailing root label: a browser reads `https://ex.com./` and
`https://ex.com/` as two origins, and `compareUrls()` reads them as one. That is
this repository's own stated position rather than a new one — `fqdn_root_label`
in `docs/reason-codes.md` records that the form "resolves identically to the
bare form and every URL parser reads it identically", and names host-**string**
comparison downstream as the hazard the reason code exists to flag. A comparator
is that downstream consumer, so it applies the normalization the reason code
asks callers to apply.

`sameSite` is schemeless — registrable domains only, so `http://ex.com/` and
`https://ex.com/` are one site. The schemeful variant (RFC 6265bis §5.2) is a
conjunction with `left.scheme === right.scheme`, and both fields are on the
result so a caller can form it.

**Opaque origins get a determinate answer, not a null.** `data:`,
`file:` and `about:blank` are settled: the standard gives each parse a fresh
opaque origin, and an opaque origin is not equal to any origin, itself included
— so two parses of one identical `data:` string are two origins. Reporting that
as "unknown" would tell a caller nothing is known about something the standard
decides. The result type is therefore three-state — `"same"` / `"different"` /
`"undetermined"` — and opaque origins land on `"different"`. `"undetermined"` is
reserved for the cases where this comparator genuinely could not tell: an input
that did not parse, an input that was not a string, a host UTS-46 rejects, and a
bare authority (`ex.com/a`), which has a site but an origin only relative to a
base URL. IP literals get the same treatment on the site question: an address is
its own site, per RFC 6265bis, rather than a `null` that would let two unrelated
addresses meet. `"different"` is evidence; `"undetermined"` is its absence, and
`!== "same"` is not a substitute for `=== "different"`.

**The PRIVATE-inclusive view is the piece with content.** `sameSite` resolves
under `allowPrivateDomains: true`, so `alice.github.io` and `mallory.github.io`
are two sites — the separation the ICANN-only view cannot express, and the exact
tenant-collapse the IMC '23 rows above exist to keep visible. `sameSiteIcann`
carries the other view, the one `parsed.registrableDomain` reports, because
which of the two a caller wants depends on whether a platform's tenants count as
one party. This makes `compareUrls()` the first PRIVATE-inclusive PSL call site
in shipped code rather than in tests; §6.1's declined `HostFacts` seam is
unaffected and the reasoning is recorded there.

**Advisory, and bounded by the provenance it carries.** The result reports a
relationship, not a permission — it is not an authorization decision and not a
substitute for the origin check a security boundary performs itself. Both site
answers ride on the bundled PSL snapshot, so the result carries `pslSnapshot`.
Read its `stale` in one direction only: it comes from `pslOutdated()`, which
returns `false` for a `dateKind` of `"exact"` alone, and the shipped
`PSL_PROVENANCE` record is a `"release-proxy"` — so the field can prove
staleness and cannot prove freshness, on any clock reading. Test `=== true` to
act on proven staleness and read `null` as unknown.

**Sibling and related-domain queries — declined permanently.** "Are these two
hosts run by the same party?" is claim (b) by construction under §1.1: it is a
fact about the world, not about the strings, and no offline computation settles
it. Shared registrable domain is what `sameSite` reports and is the end of what
the string supports. Better evidence does not reopen this; a different claim
would.

**Implemented (`LINK-vycgfumd`).** `src/compare/compare-urls.ts`, exported from
the package root and from `linklint/experimental`, pinned by
`test/compare-urls.test.ts` and `test/parsed-origin-derivation.test.ts`.

#### 6.1.10 Address destination codes — reported at weight 0 (`LINK-bwqhvjcs`)

**Decision — an `ip_*` code that fires on where an address points reports at
weight 0; a code that reads how the address is written keeps its weight,
ADOPTED.** This settles `LINK-qqwfpxvu` (option 2). Weights `1.23`.

**The rule.** Five codes fire on the address's *destination*: membership of an
IANA special-purpose range or of the vendor cloud-endpoint table, and nothing
else. They are `ip_cloud_metadata`, `ip_loopback`, `ip_private`,
`ip_link_local` and `ip_reserved` — the complete bucket set of
`detectors/ip-classification.ts`, one per address. Each now reports at
**weight 0** (`scoring: false`), exactly as the retired semantic tier does
(§6.1.5, §1.1's agent-mode table). Two codes read the address's *form* and keep
their weights. `ip_obfuscation` (0.40) is form 1: `http://2130706433/` reads as
one string and normalizes to `127.0.0.1`. `ambiguous_numeric_host` (0.30) is
form 2: a browser rejects the host and a non-browser client dials it.
`ssrf_cloud_metadata` (1.00) is not an address reading at all. It is §1.1's one
consequence-weighted escalation, and it keeps scoring.

**Why a destination is outside claim (a).** Claim (a) is *the string is not what
it presents itself to be*. `http://192.168.1.1/` presents itself as the private
address `192.168.1.1`, and that is what it is. `normalize(input) === input`,
every conforming reader agrees where it goes, and it makes no false claim about
itself. None of the three forms reaches it. What the bucket adds is a fact about
the address — which block a registry put it in, which vendor answers on it. That
fact is true, settleable offline and worth saying. It is not a deception finding,
so it belongs to §1.1's fourth rule: report it and do not score it. This holds for
the cloud-metadata endpoint too. `169.254.169.254` is honestly
`169.254.169.254`, and the hazard it names is what a fetcher does there, not
anything the string hides.

**What this is not.** This record must not be read as the axis `LINK-qqwfpxvu`
rejected, *authority-fixed content licenses scoring*. It is that rejection
applied. IANA and the vendors fixing the ranges defeats the durability objection
— the fact will not rot — and that is what earns the buckets a place in
`reasons[]`. It does not defeat the deception objection, so it earns them no
weight. §1.1 draws the same line for `special_use_name`: RFC-fixed content plus
weight 0, both required and neither sufficient alone. Nor is the rule "internal
destinations are dangerous, so score them": a consequence argument like that is
what §1.1 lets a caller's declaration license (`agentMode`), never linklint's own
guess about what a URL is for.

**What stays scored, and why that is consistent.** An obfuscated spelling still
scores, because the disguise is the deception and the destination is not. A
bucket code now only explains what the disguise was hiding. Under `agentMode`,
`ssrf_cloud_metadata` still meets §1.1's three conditions. Condition 1 asks that
the fact be *settled* with the gate off, and `ip_cloud_metadata` still settles
it, reported in both modes by the same lookup. The condition never required the
fact to score. `http://169.254.169.254/` therefore still lands `critical` under
`agentMode`, on the escalation alone: `1 − (1 − 1.0) = 1.00`. It always
saturated there, so the always-on `0.75` never contributed to that verdict.

**Measured consequences.**

| Input | Before (weights `1.22`) | After (weights `1.23`) |
|---|---|---|
| `http://169.254.169.254/` | `0.75`/`high` | `0.00`/`info`, `ip_cloud_metadata` reported |
| `http://169.254.169.254/` + `agentMode` | `1.00`/`critical` | `1.00`/`critical` |
| `http://192.168.1.1/` | `0.20`/`low` | `0.00`/`info`, `ip_private` reported |
| `http://2130706433/` | `0.52`/`high` | `0.40`/`medium`, carried by `ip_obfuscation` |
| `http://0251.0376.0251.0376/` | `0.85`/`critical` | `0.40`/`medium`, carried by `ip_obfuscation` |

In the labelled corpus, 47 rows that had scored only on a bucket move from
`deceptive` to `info` and keep their `expectReasons`. Two rows that also carry
`ip_obfuscation` (`[fd00:0ec2::254]`, `[fd20:00ce::254]`) move from
`minSeverity: high` to `medium`. Each relabel carries a `LINK-bwqhvjcs` comment,
and no embarrassment-corpus row carries a bucket code. The default CLI gate
(`--fail-on high`) no longer exits non-zero on a bare metadata address; `--agent`
restores the block. `@linklint/online`'s transport guard is untouched, because
it refuses a connection on `classifyHost()`'s bucket and never reads a weight.

**Implemented (`LINK-bwqhvjcs`).** The five registry entries in
`schema/reason-codes.ts` carry `scoring: false` / weight 0 and `WEIGHTS_VERSION`
moves `1.22` → `1.23`. The pin is `test/address-destination-weight.test.ts`,
and `docs/scoring.md` and `docs/reason-codes.md` list the five as annotations.

### 6.2 IDNA / UTS-46 conformance & the normalization flag profile

Every verdict that rests on *"what host is this really"* flows through
`src/unicode/idna.ts`, backed by `tr46` (pinned as `dataVersions.idna`). tr46
embeds its own UTS-46 and Unicode data and releases on its own cadence, so the
same silent-drift exposure the PSL has applies here.

**Flag profile.** `idna.ts` passes only `transitionalProcessing`; every other
tr46 option keeps its default of `false` — **CheckBidi, CheckHyphens,
CheckJoiners, UseSTD3ASCIIRules and VerifyDnsLength are all off**. This is
deliberate: `inspect()` must *classify* hostile input, not reject it, so
normalization stays maximally permissive and the detectors decide what is
suspicious. A bidi-violating or over-long host is a finding, not a parse failure.

**Conformance gate (U1).** `test/idna-conformance.test.ts` runs the **entire**
upstream `IdnaTestV2.txt` (6,391 rows, Unicode 17.0, vendored at
`test/data/IdnaTestV2.txt` and pinned by `sha256`) against `toAsciiUnder()`
(both transitional and nontransitional), `toUnicode()`, `toAscii()` and
`hasMalformedPunycode()` on every check.

Rows are triaged using the corpus's **own** relaxation table, not a linklint
allowlist — the file's header states that an implementation leaving a flag false
"would ignore the corresponding status codes" (`VerifyDnsLength: A4_1, A4_2` ·
`CheckHyphens: V2, V3` · `CheckJoiners: Cn` · `CheckBidi: Bn` ·
`UseSTD3ASCIIRules: U1`, plus `X4_2` as the toUnicode counterpart of `A4_2`).
Every remaining code (`P*`, `V1`, `V4`, `V6`, `V7`, `A3`) is a hard error
linklint must still reproduce.

**Result under the flag profile above: 100.00% on all three operations — zero
divergences to document.** The figure is profile-relative — conformance to
UTS-46 as linklint configures it, not a strict-admission result, since a row the
corpus fails only through a disabled check counts here as a pass. It is kept
honest by pinning the corpus shape alongside it: 4,181 rows must still *fail*
under this profile and 2,210 must *succeed*, of which 1,661 succeed only because
a flag is off. A relaxation rule that had quietly swallowed the corpus would also
report a profile-relative 100%, so the split is asserted too.

**Decision — compatibility folds get no signal distinct from `normalization_delta`.**
Investigated and **declined** (`LINK-qrktkbtg`). A host label can contain
compatibility-decomposable characters that fold to a different ASCII string than
they display as — `ﬁle.com` → `file.com`, `ｅxample.com` → `example.com`,
`ex⓪ample.com` → `ex0ample.com`. All currently score `info` 0.00 with
`normalization_delta` + `idna_mapping_ambiguity`, both weight 0. Three findings:

1. **The existing design already draws the right line, and it is finer than
   "contains a compatibility character".** The discriminator is *disagreement
   between standards*, not exotic input. A label that folds to the legitimate
   target under **both** IDNA2003 and UTS-46 reaches the genuine site and must
   not escalate (`ｇｏｏｇｌｅ.com` → the real `google.com`, pinned `info` in
   `corpus.ts` as J9 Group B). A label that folds *differently* depending on the
   standard, landing exactly on a watchlist brand, already escalates via
   `brand_idna_collapse` at weight 0.5 (`wordpreß.com` → `wordpress.com` under
   IDNA2003 but `xn--wordpre-6va.com` under UTS-46).
2. **The narrow alternative was tried and the corpus rejected it.** Making
   `idn_host` fire when the raw registrable domain is non-ASCII even though it
   folds to ASCII (`detectors/idn-host.ts` uses `toUnicode`, whose UTS-46 mapping
   erases the evidence) moved `ｇｏｏｇｌｅ.com` from 0.00 to 0.70 — one false
   positive, precision 1 → 0.992. That row is a deliberate decision, not an
   oversight, so the change is wrong rather than merely inconvenient.
3. Raising `normalization_delta` is not an option: weight 0 is required by
   FR-D-15, since every IDN trips it and a legitimate single-script IDN must stay
   benign.

**Accepted limitation.** A compatibility spelling of an *ASCII-homoglyph*
lookalike is not detected: `paypa１.com` (fullwidth digit one) scores 0.00 while
its folded twin `paypa1.com` scores 0.84 via `brand_homoglyph` + `ascii_homoglyph`.
Closing it would mean running the digit-fold homoglyph comparison on the
compat-folded host — stacking two fuzzy transforms, which is precisely the
combination whose false positives forced the `LINK-blgvypxk` rollback. Same
accepted class as `paypal-login.com` scoring 0.00.

**Unicode baseline.** The bundled tr46 carries **Unicode 17.0** data, evidenced
by CJK Extension J (`U+323B0..U+3347B`, assigned in 17.0, `disallowed` in 16.0):
running the 16.0 corpus against it produces exactly 13 failures at those code
points, and the 17.0 corpus produces none. Two assertions pin that baseline
directly, so a `tr46` pin that moves to a different Unicode release fails even
before the corpus is refreshed. Note this is a **newer** Unicode release than the
confusables table (16.0.0, `tools/build-confusables.mjs`); the two data sets are
independent and are pinned separately.

**The confusables pin deliberately stays at 16.0.0.** Aligning it to 17.0 was
measured and **declined** (`LINK-tydjfmci`). Unicode 17.0 adds `þ → p`, so a
Latin-script host whose only non-ASCII character is `þ` skeletons entirely to
ASCII and trips `homograph_latin_skeleton` (critical, weight 1.0):
`þingvellir.is` — a real Icelandic UNESCO site — goes from `info` 0.00 to
`critical` 1.00. The whole suite passed under the 17.0 table apart from the drift
guard, because the curated corpus contains no Icelandic: a hand-curated benign
corpus *confirmed* a bump that breaks real browsing, the same self-confirming
failure mode recorded after `brand_combosquat` (`LINK-cqdrdvfu`).
`confusables-drift.test.ts` carries the tripwire.

### 6.3 Pin-bump gate — diffing linklint's own answers

§6.1 and §6.2 both ask *"does linklint still agree with upstream?"*. Neither asks
the question that actually matters when bumping `tldts` or `tr46`: **did this
bump move an answer for a host linklint reasons about?** A change can be
perfectly conformant upstream — a genuinely new PSL rule, a newly-assigned code
point — and still silently redraw the registrable domain of a watchlist brand.

`test/boundary-baseline.ts` (run via `pnpm data:boundary`) records linklint's own
answers for a fixed, fully committed input set of **255 hosts**: every
`BRAND_DOMAINS` entry, every corpus vector host (extracted with linklint's own
parser, so U-labels survive), every host in the vendored upstream PSL corpus, and
the IMC '23 multi-tenant eTLDs with a tenant under each. For each host it records
both PSL views and both normalization modes:

| Recorded | Why |
|---|---|
| ICANN-only domain / suffix / subdomain | the view `inspect()` actually reasons with |
| PRIVATE-inclusive domain / suffix | the freshness-gated view (§6.1) |
| `isIcann` — **which section** the rule came from | a rule crossing the ICANN/PRIVATE boundary moves one view while leaving the other intact |
| U-label, toASCII transitional + nontransitional | `tr46` owns all three |

`pnpm data:boundary --check` diffs the committed baseline against what the
current pins produce and prints a **reviewable list of what moved** — section
moves called out first and separately — then exits non-zero.
`boundary-baseline.test.ts` runs it on every check, so an unreviewed bump cannot
land quietly, and its own negative-control tests mutate a cloned baseline to
prove each change class is really detected. Accepting a bump means regenerating
the baseline in the same commit; the bump checklist is in `CONTRIBUTING.md`.

This is the pattern pslr shipped as `psl_diff` (PSLR-ayahzscr) after surveying
PSL libraries across ten language ecosystems and finding none that offered
snapshot-to-snapshot diffing.

**On `pslSnapshot.stale` semantics.** pslr retired its boolean `psl_outdated()`
in 1.1.1 because a boolean conflates *content age* with *knowledge of the remote
endpoint*. linklint keeps a flag, and two separate limits are load-bearing.

*Age is not verification.* Even a `stale: false` would mean only **"the bundled
snapshot is under 180 days old"** — not "verified current against
publicsuffix.org". linklint has no network path and never contacts the upstream
list, so a young snapshot can still be missing rules added last week.
`stale: true` is a prompt to consider bumping the pin; it is not a claim that
anything is broken.

*The proxy date bounds age from one side only (`LINK-elzuacby`).* The bundled
date is the `tldts` release date `R`, and the list it ships was regenerated at or
before that build, so the true snapshot time `S` satisfies `S ≤ R` and
`now − R ≤ now − S`. The computed age is therefore a **minimum**: once it clears
the window, the true age has cleared it too, and `stale: true` is sound. Inside
the window it proves nothing at all — the real list could be years older — so the
verdict is `null`, not `false`. **A release date can prove staleness; it cannot
prove freshness.** `false` is reserved for a `dateKind: "exact"` record, which no
current dependency supplies. Read the field as `=== true`, never as `!== false`.

This corrected an inverted claim: the record previously called `R` an *upper*
bound on age and returned `stale: false` from it, so every result asserted a
freshness the offline evidence could not support. No `SCHEMA_VERSION` bump: the
result shape is unchanged and `stale` neither gained nor lost a documented value
— it is typed `boolean | null` before and after, and `null` was already a value
consumers had to handle. What changed is which value the *evidence* justifies.

### 6.4 Version stamps — what each one owns

Four stamps travel with a verdict, and until `LINK-zzydqrkd` the repository
stated two incompatible rules for the first of them. `schema/base.ts` said every
contract change, additive ones included, while `schema/options.ts`, §6's
invariant list and `docs/scoring.md` each carried a sentence excusing an
additive field from a bump. `base.ts` is the rule that stands, and the other
three sentences are deleted.

**The bump matrix — ADOPTED.**

| Stamp | Owns | Moves on |
|---|---|---|
| `SCHEMA_VERSION` (`schema/base.ts`) | the serialized `InspectResult`: its fields, their nullability, their documented meanings, and their CLOSED value domains | any change to those, **including an additive one** — a field added, a documented meaning widened or narrowed, a value added to or removed from a closed domain |
| `ENRICHMENT_SCHEMA_VERSION` (`schema/enrich.ts`) | the structured enrichment report: outcome states, evidence shapes, cause vocabulary | a change to those. It keeps its existing narrower ownership rather than folding into `SCHEMA_VERSION`, and it is also the cache-namespace key (§7) |
| `WEIGHTS_VERSION` (`scoring/weights.ts`) | the scoring weights and the severity bands | a weight or a band change (NFR-DATA-1) |
| `DataVersions` (`data/versions.ts`) | the pinned data snapshots — PSL, confusables, scripts, IDNA, file-extension TLDs, cloud metadata, IP ranges, brands | a snapshot re-pin, per §6.3 |
| package version + `CHANGELOG.md` | everything that is not the result contract: package semantics, `InspectOptions`, `linklint/experimental` exports, free-form `Reason.detail` prose | any such change — **unless** it also alters the result contract, in which case the stamp above applies as well |

Why additive counts, against the ordinary semver instinct: `base.ts` states the
purpose as *"so consumers can pin behavior"*, and a consumer pinning `1.7` is
asserting it knows the full set of values it can be handed. An additive change
is invisible to a reader that ignores unknown fields and load-bearing for one
that switches on a closed domain, and the version string is the only channel
that lets the second reader tell the two situations apart. The cost of the rule
is one line edited per contract change; the cost of the other rule is a change
the artifact cannot express.

**Closedness is decided by the documented registry, not by the TypeScript
annotation.** `Reason.code` is typed `string` on `InspectResult` and
`ReasonCode` (`keyof typeof REASON_CODES`) in the registry, so "closed value
domain at the serialized boundary" reads both ways if the type is left to
settle it. It is not left to the type. A domain is CLOSED when this repository
publishes an enumeration of its values — `docs/reason-codes.md` plus the
exported `REASON_CODES` — and OPEN when it does not. The `string` annotation
on the wire is a serialization convenience, and loosening an annotation is not a
route around a bump.

Three worked cases, so the matrix is testable rather than aspirational:

| Change | Stamp | Why |
|---|---|---|
| a new `checksSkipped` token | **no bump** | open domain. §6 documents `checksSkipped` as `string[]` with no enumerated domain, and the shipped `agent` channel token and the `options:<key>` family both entered under that reading |
| a new reason code | **`SCHEMA_VERSION`** | `ReasonCode` is a closed, publicly exported union. A new reason code never enters the registry without a bump: `test/docs-validation.test.ts` pins the key set to the version it registered under |
| a new enrichment cause | **`ENRICHMENT_SCHEMA_VERSION`** | the cause vocabulary belongs to the enrichment report, not to `InspectResult`. `SCHEMA_VERSION` stays put |

The matrix ratifies the three no-bump notes already in this document rather than
contradicting them: the tier-2 brand escalation (§6.1.1) reused an existing
code at an existing weight, the `brand_lookalike` → `brand_homoglyph` rename
(§6.1.2) moved a CHECK id, which reaches `checksSkipped` as
`lexical:<id>` in the open domain above, and the `pslSnapshot` correction
(§6.3) changed which value the evidence justifies without adding or removing
one. That is exactly why a prose grep for *"no `SCHEMA_VERSION` bump"* is the
weak guard here — it cannot separate those three from a defect. The guard
that bites is mechanical: `packages/core/test/docs-validation.test.ts` checks
in the `REASON_CODES` key set beside the `SCHEMA_VERSION` it was registered
under, and fails if either moves without the other. It reddens on the case that
actually recurs (see `CHANGELOG.md` for the two historical misses) and on a
bump that leaves the pin stale.

**The dissent, recorded (2–1 on the rule).** A BREAKING-ONLY rule — bump
only when a consumer that already handles the documented shape would break
— was argued and checkably grounded: nothing consumes `schemaVersion` (zero
references in `packages/cli/src` and `packages/mcp/src`),
`ENRICHMENT_SCHEMA_VERSION` is the only stamp with a real reader, and a strict
reading of the adopted rule implies roughly 35 bumps against the 7 that actually
happened. It lost on where the error is recoverable, not on the facts. A bump
nobody needed costs a consumer one pin edit and is visible in the artifact; a
bump that was owed and skipped is undetectable from the artifact, which is the
failure this whole section exists to close. Zero readers today is a statement
about today's consumers, not about the contract published for future ones —
and the 35-vs-7 gap is a measure of the historical practice, which is the thing
under review. Reopen this against a named consumer harmed by a bump, not against
the bump count.

**Implemented (`LINK-zzydqrkd`).** The three contrary sentences are deleted
(here, `docs/scoring.md`, `packages/core/src/schema/options.ts`), the two
historical misses are named in `CHANGELOG.md` rather than baselined, and the
mechanical pin ships in `packages/core/test/docs-validation.test.ts`.

## 7. Scoring

Probabilistic-OR aggregation over scoring reasons:

```
score = 1 − ∏(1 − wᵢ)
```

Order-independent and saturating toward 1. Severity bands:

| Severity | Score range |
|----------|-------------|
| `info` | `0` |
| `low` | `(0, 0.25]` |
| `medium` | `(0.25, 0.5]` |
| `high` | `(0.5, 0.8]` |
| `critical` | `(0.8, 1]` |

Weights are hand-tuned, version-pinned, and transparent. The full table is in `docs/scoring.md` and `packages/core/src/scoring/weights.ts`.

## 8. Policy layer

The policy layer answers "does this URL satisfy my org's allow/deny rules?" — a separate question from "is this URL deceptive?"

Policy reasons carry `layer: 'policy'` and `weight: 0`. They annotate the result without changing `score` or `severity`. `policy` appears in `checksRun` only when the caller configures at least one axis and at least one axis completes.

Each axis is guarded independently (FR-D-13): a failing axis is reported as `policy:<axis id>` in `checksSkipped` and costs only itself. See §5's result-invariant list for how the channel and per-axis tokens relate.

Available axes (all optional, all default-allow):

| Option | Effect |
|--------|--------|
| `allowTlds` / `denyTlds` | TLD allow-list or deny-list |
| `allowHosts` / `denyHosts` | Registrable-domain allow/deny |
| `allowSchemes` / `denySchemes` | Scheme allow/deny |
| `denyPorts` / `denyNonStandardPorts` | Port policy |
| `maxDecodeDepth` | Decode-bomb guard |

**A schemeless input is exempt from the scheme axis.** `allowSchemes` /
`denySchemes` are evaluated only when the input carries a scheme, so a bare
hostname (`example.com/path`) clears the axis without emitting `scheme_denied`.
This matters to an https-only lockdown built on `allowSchemes`: the axis
constrains inputs that state a scheme, and a caller who also wants to refuse
schemeless input has to reject or qualify it upstream. Opaque and hostless
inputs (`javascript:…`, `data:…`) do carry a scheme, so scheme policy applies to
them as usual.

Entries on the string axes are lower-cased, and a leading `.` is tolerated on
`*Tlds` / `*Hosts`, so a list built by splitting a config string
(`env.DENY_TLDS.split(",")`) behaves as written. An entry left empty after
normalization is dropped; an allow-list whose entries all drop stays
*configured*, so it reports every input as not-allow-listed rather than falling
open.

Enforcement is the consumer's job — linklint only reports the verdict. Ready-made
fail-closed wrappers (Claude Code PreToolUse hook, curl/wget shell aliases) live in
[`docs/enforcement.md`](enforcement.md).

### Trimming belongs to list-valued options, not to the axes

Trimming is a property of **every list-valued caller option**, not of the policy
axes. It happens once, inside `normalizedList` in
`packages/core/src/parse/runtime.ts`, so a list option inherits it by routing
through that function rather than by its author remembering to trim: **10** of
the **17** option keys the two entry points recognize are list-valued, and **8**
of them route through the choke point — the seven list-valued axes above
plus `idnAllowlist`, which is not an axis at all. Reading the property as
axis-scoped shipped two fail-opens: `idnAllowlist` was normalized inline, so
`--idn-allow " münchen.de"` exempted nothing, and `suppressReasons` matched
nothing on either of its two caller strings — both because each reader checked
the policy axes above and stopped there (LINK-qajalduf).

`suppressReasons` is the one structural exception. Its entries are OBJECTS, so
there is no single value for a list-level normalizer to trim — the caller's
strings are the `code` and `host` fields one level down. It applies the identical
trim to each field through the shared `trimListValue` helper, and the comment at
its definition records why it cannot be folded into `normalizedList`.

`enrichers` is out of class. It is the tenth list-valued key, but its entries are
provider objects supplied in code rather than configuration text a caller typed
or split, so a padded value there is visibly wrong rather than silently void.

Both counts, the routed set, and the two exceptions are derived from the option
interfaces and from `parse/runtime.ts` by
[`packages/core/test/list-option-trim-scope.test.ts`](../packages/core/test/list-option-trim-scope.test.ts):
a new list-valued option that skips the choke point reddens the suite instead of
waiting for a reader to notice.

### Caller false-positive escape hatch (`suppressReasons`)

`idnPolicy`/`idnAllowlist` let a caller say "non-ASCII here is fine" for the one
`idn_host` heuristic. `suppressReasons` generalizes that to **every** heuristic:
a caller supplies `{ code, host? }` rules marking a reason a false positive.

- **Annotate, don't delete.** A matched reason stays in `reasons[]` marked
  `suppressed: true`; its scoring `weight` is zeroed so `aggregate` ignores it and
  `score`/`severity` drop as if the signal were absent. linklint is never silently
  clean — the finding is still visible, just excluded from the verdict.
- **Scope.** No `host` = suppress that `code` for all inputs; a `host` limits it to
  inputs whose registrable domain matches (mirrors `idnAllowlist`: registrable
  domain, case-insensitive, Unicode/punycode agnostic, covers subdomains).
  Structured enrichment findings use their outcome's actual URL/host subject;
  allowing the original host never suppresses a discovered destination.
- **Honesty.** Whenever the option is present (even `[]`) the `suppression` token
  is appended to `checksRun` (order: `lexical → policy → agent → suppression`), so
  a result never hides that a caller escape hatch was applied.
- **Default-off.** With the option absent, output is byte-for-byte unchanged.
- **Both paths.** A single shared predicate (`scoring/suppress.ts`) is applied by
  sync `inspect()` (in `buildOkResult`, before sort/aggregate) and by
  `inspectAsync`'s re-aggregation, so enricher-layer reasons are equally
  suppressible.

## 9. Channels

| Package | Surface | npm name |
|---------|---------|----------|
| `packages/core` | `inspect()` library | `linklint` |
| `packages/mcp` | `check_url` / `check_domain` MCP tools (stdio) | `@linklint/mcp` |
| `packages/cli` | `linklint check` / `linklint batch` | `@linklint/cli` |
| `packages/online` | Explicit Node/server capabilities; L0 safe transport and L2 local wrappers shipped | `@linklint/online` |

Planned but not yet built: browser extension, GitHub Action, REST/serverless wrapper. The rule is the same for all of them: call `inspect()`, present the result, enforce policy at the adapter — never fork detector logic.

Concrete online work follows a stricter package boundary. Pure enrichment
contracts and orchestration remain in `linklint`; DNS-pinned destination
transport, resolution, provider adapters, and caller-owned mirror integrations
live in the Node-only `@linklint/online` sibling package; long-running
monitoring owns a separate deployable service and durable state. The existing
CLI and MCP packages remain offline, and browsers delegate authorized online
work to a caller-owned backend because browser fetch cannot enforce the L0
socket and DNS-pinning controls. The accepted decision, export categories,
dependency direction, consent, secret, licensing, and migration rules are in
[`online-runtime-boundary.md`](online-runtime-boundary.md).

The online package exposes L0 through `@linklint/online/transport`. Its
exact-URL authorization, resolver-returned-set address policy, DNS-pinned socket,
original-host TLS identity, fresh header set, manual redirects, cumulative
budgets, and structured outcomes are documented in
[`safe-transport.md`](safe-transport.md). The internal LT harness remains the
zero-external-network acceptance seam for resolver changes, connector identity,
streamed HTTP, failures, and deterministic deadlines.

Exact local Microsoft Safe Links and Proofpoint URL Defense decoding is exposed
through `@linklint/online/resolution`. It is separately bounded, never calls a
vendor decoder service, and re-inspects every recovered destination through the
offline pipeline. See [`wrapper-decoding.md`](wrapper-decoding.md).

The same subpath exposes bounded redirect and declarative-refresh expansion.
Every initial request and discovered target receives a separate caller
authorization decision and passes through one cumulative L0 session. Only
GET/HEAD and 301/302/303/307/308 are followed; HTTP Refresh and HTML meta refresh
share byte, MIME, charset, delay, and hop limits, and JavaScript is never
executed. Every target is inspected offline before the chain continues, ordered
hop evidence is retained, and only the worst fetched hop projects de-duplicated
findings. See [`redirect-chain-resolution.md`](redirect-chain-resolution.md).

## 10. Layer model

The three-layer model is a forward-compatibility contract:

| Layer | Status | Description |
|-------|--------|-------------|
| **Lexical** (L1) | **Implemented** | Offline, deterministic, synchronous. 40 checks: 4 structural, 36 parsed (4 of them agent-gated). < 5 ms typical. |
| **Resolution** (L2) | **Partial** | Exact local wrapper decoding and caller-authorized bounded redirect/refresh expansion are implemented; observed correlation/divergence and MIME evidence remain roadmap work. Every discovered target is re-inspected through L1. |
| **Reputation** (L3) | Roadmap | Threat feeds, RDAP domain age, CT, DNS posture. Privacy-preserving by design. |

L2 and L3 extend `checksRun` / `checksSkipped` — they add to lexical results,
never replace them. Unconfigured or incomplete sources remain explicit, so a
score never implies that unfinished resolution or reputation work was clean.

**Result cache (opt-in).** So networked enrichers don't re-hit third parties on every call, `inspectAsync` accepts a pluggable `EnrichmentCache`; `get`/`set` may be synchronous or Promise-capable, and `InMemoryEnrichmentCache` is the dependency-free default. Only runtime-validated structured reports are stored and every hit is revalidated. An enricher opts in with `cacheKey(result, context)` plus a positive static `cacheTtlMs`, a response-driven `cacheTtlMsFor(report, context)`, or both. Dynamic TTLs allow explicit no-hit results to use shorter negative-cache lifetimes; failures, skips, and partial reports are never cached. A hit skips the provider call but still counts as a run (`<layer>:<id>` in `checksRun`). **Privacy:** the framework never derives caller key material from the full URL, rejects direct full-URL leakage, and wraps the caller's projection in an opaque schema/source namespace. The adapter must still use a privacy-preserving projection (registrable domain, local-mirror ID, one-way hash-prefix), never reconstructible URL material.

**Bounded runner and per-source governor.** Every configured enricher is hard-bounded by the runner at 5000 ms by default, even when no governor is supplied. A positive finite `Enricher.timeoutMs` overrides the bound; `null` is the only explicit opt-out and is intended for callers with an outer hard deadline. Non-positive/non-finite values retain the safe default. Timeout aborts the composed context signal and wins a runner-level promise race even when an enricher ignores cancellation; the abandoned promise stays observed so a late rejection is handled. Promise-capable cache reads/writes are awaited behind the same source timeout policy and late rejections remain observed. `inspectAsync` also accepts an optional stateful `EnrichmentGovernor` (`InMemoryEnrichmentGovernor` is dependency-free with an injectable clock) for (1) a **token-bucket rate limit** and (2) **exponential backoff**, both keyed by `<layer>:<id>` and persisted when the instance is shared. The governor can additionally override/disable the timeout policy. Its built-in denial decisions distinguish `rate-limited` from `backoff-active`. **Ordering (cache-before-governor):** a cache HIT consumes no token and touches no backoff because no network happened; only a MISS is admitted, consuming exactly one token. All enricher, cache-key, dynamic-TTL, cache, and governor calls are guarded. Exceptions become source-attributed structured degradation outcomes rather than escaping `inspectAsync`; valid provider evidence is retained alongside auxiliary TTL/cache-write/governor-lifecycle failures, making partial coverage explicit in both `checksRun` and `checksSkipped`.

**Staged orchestration.** The caller-ordered `EnrichmentPlan` is the existing
`enrichers` list plus optional `Enricher.dependsOn` `<layer>:<id>` edges. The
runner derives stable topological stages: independent steps in one stage run in
parallel over the same prior-outcome snapshot, while fan-in waits until every
declared prerequisite wholly completes. `EnrichmentContext.previousOutcomes`
carries every earlier structured status in plan order. Skipped, failed, or
partial prerequisites produce an explicit `prerequisite-unavailable` skipped
outcome; invalid/duplicate edges and cycles also degrade explicitly. Final
serialization stays in caller plan order regardless of promise completion order.
No dependency declarations preserves the original single parallel stage.

## 11. Testing

Two runners:

- **Vitest** (`packages/*/test/`, `tests/`) — unit tests, corpus-driven detector tests, policy tests, public-API contract tests, performance baseline.
- **Cucumber** (`features/`) — behavioral specs: `inspect.feature`, `policy.feature`, `cli.feature`, `mcp_prefetch.feature`, `success_criteria.feature`.

Verify gate: `pnpm check` = `tsc --noEmit` + `vitest run` + `cucumber-js`. Pre-push hook and CI run the same gate.

Corpus vectors live in `packages/core/test/corpus/corpus.ts`. Labels: `deceptive`, `benign`, `info`, `invalid`. Per-row assertions on expected / forbidden reason codes.

## 12. Design invariants

- No network I/O in core or MCP.
- No telemetry.
- No native runtime dependencies.
- `inspect()` never throws — unparseable input returns `status: "invalid"`. The
  guarantee is unconditional: a **non-string** argument (a plain-JS caller, or
  `JSON.parse` output handing back `null`) also returns `invalid` rather than a
  `TypeError`, since an uncaught throw in a calling hook fails *open*.
- Every finding has a named reason code with a human-readable `detail` string.
- Channels do not implement detectors.
- `normalization_delta`, `confusable_char`, and `confusable_in_path` are always informational (weight 0).
- Skipped lexical scoring detectors make the score a lower bound; fail-closed consumers must detect and handle `checksSkipped` entries matching `lexical:*`.
