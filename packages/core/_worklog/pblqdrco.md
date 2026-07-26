# LINK-pblqdrco — digits-in-labels decision: (a) adopted, (b) declined

Decision text lives in `docs/architecture.md` §6.1.1. This worklog records **how
the evidence was obtained**, because §6.1 finding #3 rejected the previous
attempt for lacking exactly this and a future revisit needs to be able to redo
the measurement rather than trust the numbers.

## The method that unblocked a question that had been stuck

The prior decision (§6.1, `LINK-yfejldva`) declined label-level matching partly
on an FP surface it could not measure, and finding #3 named the trap: validating
a benign set by reading our own brand list is self-confirming. The way out was
noticing that this particular mechanism has a **closed** firing surface.

`fold(label) !== label && BRAND_LABEL_SET.has(fold(label))` can only fire on a
valid pre-image of a brand label under the 0→o/1→l/5→s fold. Inverting the fold
and enumerating subsets of the o/l/s positions (subject to `ascii_homoglyph`'s
gates) yields **192 labels, full stop** — 65 of 106 brand labels are
fold-reachable. So the FP surface did not have to be *sampled and extrapolated*;
it could be **enumerated and probed exhaustively**. That is why this decision
could be settled and the earlier one could not, and it is the reusable trick: ask
whether a proposed matcher's firing surface is finite before arguing about its
precision.

The issue's own estimate was 62 fold-reachable labels; enumeration says 65. The
gap is why the arithmetic was not trusted as the answer.

## Three measurements, all reproducible

Scripts were scratch (not committed — they are network-dependent and
point-in-time). Recreating them:

1. **Enumerate the surface.** Invert `ASCII_DIGIT_HOMOGLYPHS`, and for each
   `BRAND_LABEL_SET` member emit every non-empty subset of its o/l/s positions
   replaced by the corresponding digit, keeping those that pass
   `ascii-homoglyph.ts`'s gates (len ≥ 5, ASCII alnum, leading letter, digits ⊆
   {0,1,5}, letters > digits). Result: 192.

2. **Unseen tenant-label corpus.** `gh api "/users?since=<id>&per_page=100"`
   paginated to 36,200 logins. A GitHub login **is** the tenant label for
   `<login>.github.io`, which is what makes this an unfiltered real-world corpus
   rather than a curated one — no judgment call selects its members. Run the
   gates over it: 427 (1.18%) pass, **0** fold to a brand label.

3. **Exhaustive liveness probe + control.** `curl` each of the 192 labels under
   `github.io` / `vercel.app` / `myshopify.com` and read the HTTP status and
   `<title>`; 404 means no tenant. Then repeat against the 106 **unfolded**
   labels as a control. 25 live vs 127 live is the number the decision turns on.

## Non-obvious judgment calls

### 1. The control group is what actually won the argument

Measurements 1–3 show the fold-gated surface is clean, but "clean" invites the
reply that any narrow guard looks clean until probed harder — which is the exact
history of `brand_combosquat`. The control answers that differently: it shows the
*rejected* mechanism is filthy (127 live tenants, including `microsoft.github.io`
and friends — brands' own official orgs, which exact matching would flag as
impersonating themselves) under the **identical probe methodology**. A single
measurement showing "no FPs found" is weak evidence; the same measurement finding
127 FPs next door, and 0 here, is strong. Ran the control specifically because
the standing rule demanded the argument be won rather than asserted.

### 2. Why HTTP status, not DNS

All three platforms wildcard their DNS — `dig +short paypal.github.io` returns
GitHub Pages IPs whether or not a tenant exists. DNS would have reported 100%
"live" and produced a garbage FP rate. Status codes discriminate (404 = no
tenant), and two of them turned out to be *evidence about intent* rather than
noise: `402` is a suspended/unpaid deployment and `451` is a legal takedown.
`bl0ckchain.vercel.app` returning 451 is the platform independently agreeing the
label is abusive.

### 3. The FP mechanism is structural, and it is not the fold gate alone

The thing that makes real tenant labels safe is *why* they contain digits: they
are counters (`mwalker1`, `haru01`, `jramirez00`), and a counter folds to
gibberish. Combined with the fold requiring **exact length-preserving equality**
to a brand label, no `shop1`-style label can reach a shorter brand. So the
benign population and the attack population are separated by word *position* of
the digit, not by any list we curate. That is the finding worth keeping if this
is ever revisited — it is the part that would survive a brand-watchlist change.

### 4. Adopted despite ~20% content-benign hits, on consistency

4–6 of the 25 live hits are benign by content while being look-alikes by name
(`salesf0rce.vercel.app` serving an unrelated template, `g0ogle.github.io` a
personal page). Adopting anyway, because the ICANN-side `brand_homoglyph`
already scores `paypa1.com` `high` on the name alone with no content evidence.
Declining here would not be caution — it would be *inconsistency*, scoring one
disguise 3x lower purely because the attacker rented space under a PSL PRIVATE
suffix. Recorded in §6.1.1 rather than buried, since it is the weakest point of
the decision.

### 5. Found that the standing tripwire does not guard this

§6.1 named the IMC '23 multi-tenant rows as the tripwire against reintroducing
label-level brand matching. Those rows (`myshop.myshopify.com`,
`docs.readthedocs.io`, …) contain **no digits**, so they cannot fire under this
mechanism in either direction — they would have stayed green through a completely
broken implementation. Surfaced this in §6.1.1 and in `LINK-tbqeqqvv`'s
acceptance criteria with named replacement rows (`pete1.github.io`,
`haru01.github.io`, both real and both `0.20`/`low` today). A tripwire that cannot
fail is worse than no tripwire, because it is cited as protection.

### 6. (b) declined on the corpus, not on taste

The digits-in-domain-means-spam premise was tested, not dismissed: 1.18% of real
tenant labels pass the gates (~1 in 85 hosts) and only 5.2% of those fold to even
a dictionary word. The gates select for digit-in-word *shape*, which is necessary
but nowhere near sufficient for the disguise — which is precisely the reason
`ascii_homoglyph` is weighted 0.2 and documented to matter only in combination.
Also checked the benign classes the request named: `z100` fails
letters-outnumber-digits, `kiss108` fails on the unmapped `8`, `987fm` fails the
leading-letter gate. A knob would buy no coverage the current gates withhold.
