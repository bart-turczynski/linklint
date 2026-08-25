/**
 * Reserved special-use TOP-LEVEL names (LINK-mgnbgicq).
 *
 * WHAT EVERY ROW ASSERTS, AND IT IS THE SAME ASSERTION FOR ALL OF THEM:
 *
 *   reserved, never delegated in the global DNS root, never publicly resolvable
 *
 * That is the uniform, standards-fixed fact this table exists to carry, and it
 * is the ONLY fact `special_use_name` states in its own voice. Getting the
 * predicate wrong ships a false claim, so the two tempting shorter phrasings are
 * recorded here as REJECTED:
 *
 *   - *"cannot resolve"* is FALSE for `.internal` and `.local`. Resolving is the
 *     whole point of those names inside the deployment that uses them; a
 *     corporate resolver or an mDNS responder answers for them every day. What
 *     is true is that no answer comes from the global DNS root.
 *   - *"context-dependent"* is FALSE for `.invalid` and `.alt`. `.invalid` names
 *     nothing on any network anywhere — RFC 6761 §6.4 guarantees NXDOMAIN — and
 *     `.alt` is reserved for name systems that are not the DNS at all. Neither
 *     is a name whose meaning varies with where you stand; there is no meaning
 *     to vary.
 *
 * The set is NOT homogeneous below that predicate, which is why each row carries
 * a {@link SpecialUseName.referent} and a category note that the detector prints
 * BENEATH the uniform sentence rather than in place of it. Four kinds:
 *
 *   - `no-referent` — `.invalid`, `.alt`. Nothing anywhere, by construction.
 *   - `locally-scoped` — `.internal`, `.local`, `home.arpa`, `.test`. A real
 *     referent, fixed by whichever network you are on.
 *   - `machine-relative` — `.localhost`. RFC 6761 §6.3 MANDATES loopback, which
 *     makes it the LEAST context-dependent name in the set: every resolver on
 *     every network is required to give the same answer, and the answer is
 *     simply relative to the machine asking.
 *   - `separate-namespace` — `.onion`. RFC 7686 assigns it to Tor. Resolution
 *     happens, in a namespace that is not the DNS.
 *
 * SCOPE: SUFFIXES ONLY, AND THE EXAMPLE DOMAINS ARE DELIBERATELY EXCLUDED.
 * RFC 6761 §6.5 reserves `.example` **and** `example.com`, `example.net`,
 * `example.org` in one section, and it is tempting to read that as one set. It
 * is two. `.example` is a TLD that was never delegated and never will be, which
 * is this table's predicate exactly. `example.com` is a SECOND-LEVEL reservation
 * under `com` — a delegated TLD — and it resolves: IANA operates the site and
 * an A record answers. The measurable form of the difference is the public
 * suffix, which is `example` for the first and `com` for the second.
 *
 * The exclusion is not fastidiousness. ROUGHLY A QUARTER of the labeled corpus
 * uses an `example.com`/`.net`/`.org` host as a neutral stand-in (85 of 372 rows
 * when this shipped; the share is asserted, not the count, in
 * `test/special-use-name.test.ts`). A table that included them would annotate
 * that whole population with a finding about the STAND-IN rather than about the
 * string under test — and would make the code's own predicate false on every one
 * of those rows, since example.com resolves.
 *
 * OUT OF SCOPE — `.onion` LABEL SYNTAX. A v3 onion address is a 56-character
 * base32 encoding of an Ed25519 public key plus a checksum and a version byte
 * (rend-spec-v3 §6). `ab.onion` therefore announces a Tor identity it cannot
 * be, which is architecture §1.1 form 3 — false self-description — and form 3
 * is SCORING-eligible. That is a separate question with a separate answer, and
 * folding it into a weight-0 informational code would decide it by smuggling.
 * This table says only that `.onion` is reserved and not in the DNS; it says
 * nothing about whether a particular label under it is a well-formed address.
 *
 * LIVING REGISTRY, HENCE A VERSION STAMP. This is not a fixed historical list:
 * `.alt` arrived in 2023 (RFC 9476) and `.internal` in 2024 (ICANN Board
 * resolution, not an RFC). {@link SPECIAL_USE_NAMES_VERSION} is surfaced as
 * `dataVersions.specialUseNames` so a verdict is reproducible against the
 * snapshot that produced it, exactly as the IANA and vendor tables are.
 *
 * WHICH SIDE OF THE NAME-NEVER-CREATE LINE THIS SITS ON (architecture §1.1).
 * The same argument `data/cloud-metadata.ts` makes for its hostname rows, and
 * with less to defend: a row here asserts that a naming authority has withheld a
 * name from the root, which is settleable offline, settleable for all time, and
 * cited to the document that settles it. It is the class of fact
 * `data/ip-ranges.ts` carries, not the class `data/brands.ts` carries — nothing
 * here claims a name is worth impersonating, and nothing here creates a scoring
 * finding, because the code's weight is 0.
 */

/**
 * Version stamp for this curated table, surfaced as
 * `dataVersions.specialUseNames`. Bump deliberately whenever a row is added,
 * removed, or re-cited — the reservation registry is living.
 */
export const SPECIAL_USE_NAMES_VERSION = "2026-08-25-rfc6761";

/**
 * What kind of thing the name refers to, BENEATH the uniform predicate. Selects
 * the category sentence, never the reason code: every row emits
 * `special_use_name`.
 */
export type SpecialUseReferent =
  | "no-referent"
  | "locally-scoped"
  | "machine-relative"
  | "separate-namespace";

export interface SpecialUseName {
  /** The reserved suffix, lower-case, with no leading or trailing dot. */
  readonly name: string;
  /** The document that reserves it. */
  readonly citation: string;
  readonly referent: SpecialUseReferent;
  /**
   * Category-specific sentence, printed BENEATH the uniform predicate. It
   * refines; it never contradicts or replaces.
   */
  readonly note: string;
}

/**
 * The reserved suffixes. TLD-level (plus `home.arpa`, which RFC 8375 reserves as
 * a whole second-level name under the infrastructure TLD and which behaves as a
 * suffix in the PSL). `arpa` itself is delegated and is NOT a row.
 */
export const SPECIAL_USE_NAMES: readonly SpecialUseName[] = [
  {
    name: "invalid",
    citation: "RFC 6761 §6.4",
    referent: "no-referent",
    note: "it names nothing on any network anywhere — the RFC guarantees a lookup returns NXDOMAIN, which is the point of the name",
  },
  {
    name: "alt",
    citation: "RFC 9476",
    referent: "no-referent",
    note: "it is reserved for name systems that are NOT the DNS, so it has no DNS referent in any deployment",
  },
  {
    name: "localhost",
    citation: "RFC 6761 §6.3",
    referent: "machine-relative",
    note: "the RFC MANDATES loopback, so every resolver everywhere is required to give the same answer — the referent is fixed globally and is simply relative to the machine asking",
  },
  {
    name: "onion",
    citation: "RFC 7686",
    referent: "separate-namespace",
    note: "it addresses a Tor hidden service in a namespace that is not the DNS; resolution happens, through the Tor overlay",
  },
  {
    name: "internal",
    citation: "ICANN Board resolution 2024-07-29",
    referent: "locally-scoped",
    note: "it is reserved for private-use applications, so it resolves only inside the deployment whose own resolver defines it",
  },
  {
    name: "local",
    citation: "RFC 6762 §3",
    referent: "locally-scoped",
    note: "it is answered by link-local multicast DNS, so it resolves only on the link the query was asked on",
  },
  {
    name: "home.arpa",
    citation: "RFC 8375",
    referent: "locally-scoped",
    note: "it is the name for a home network's own zone, so it resolves only inside that home network",
  },
  {
    name: "test",
    citation: "RFC 6761 §6.2",
    referent: "locally-scoped",
    note: "it is reserved for testing, so any referent it has belongs to whichever test environment defined it",
  },
  {
    name: "example",
    citation: "RFC 6761 §6.5",
    referent: "locally-scoped",
    note: "it is reserved for documentation; the SECOND-LEVEL reservations in the same section — example.com, example.net, example.org — are deliberately NOT covered here, because those sit under a delegated TLD and do resolve",
  },
];

/** Index for {@link matchSpecialUseName}, built once at module load. */
const NAME_INDEX = new Map<string, SpecialUseName>(
  SPECIAL_USE_NAMES.map((row) => [row.name, row]),
);

/**
 * The reserved special-use name `host` sits under, or undefined.
 *
 * SUFFIX MATCH ON WHOLE LABELS, longest first, after case folding and after
 * dropping ONE trailing root dot. Whole labels because `notinvalid.com` is an
 * ordinary domain and a substring test would call it reserved; longest first so
 * `foo.home.arpa` reports `home.arpa` rather than falling through to nothing
 * (`arpa` is delegated and is not a row, so there is no shorter match to prefer,
 * but the ordering is what keeps that true if a shorter row is ever added).
 *
 * The trailing dot is dropped for the same reason `matchCloudMetadataHostname`
 * drops it: `foo.invalid.` is the fully-qualified spelling of the same name and
 * resolves identically. Two or more trailing dots never reach here — they create
 * an empty label and fail parsing as `invalid`.
 *
 * Zero-network: a string comparison against a fixed table. No lookup is
 * performed and none is implied.
 */
export function matchSpecialUseName(host: string): SpecialUseName | undefined {
  if (host === "") return undefined;
  const bare = (host.endsWith(".") ? host.slice(0, -1) : host).toLowerCase();
  const labels = bare.split(".");
  // i = 0 is the whole host; each step drops the leftmost label, so the first
  // hit is the LONGEST matching suffix.
  for (let i = 0; i < labels.length; i++) {
    const hit = NAME_INDEX.get(labels.slice(i).join("."));
    if (hit) return hit;
  }
  return undefined;
}
