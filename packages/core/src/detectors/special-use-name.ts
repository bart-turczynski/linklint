import { matchCloudMetadataHostname } from "../data/cloud-metadata.js";
import { matchSpecialUseName } from "../data/special-use-names.js";
import type { Detector } from "./types.js";

/**
 * The uniform, RFC-fixed fact every row of the table asserts. It is stated in
 * these words and no shorter ones — see `data/special-use-names.ts` for why
 * "cannot resolve" and "context-dependent" are each false of part of the set.
 */
const PREDICATE =
  "reserved, never delegated in the global DNS root, never publicly resolvable";

/**
 * LINK-mgnbgicq. INFORMATIONAL, weight 0.
 *
 * The host sits under a reserved special-use name — `.invalid`, `.internal`,
 * `.localhost`, `.onion`, `home.arpa` and the rest of the set.
 *
 * **NOT a scoring finding, and the reason is the same one host length gives.**
 * None of these names satisfies any of architecture §1.1's three forms of claim
 * (a). `normalize(input) === input`, so there is no normalization delta. Every
 * conforming reader agrees on the string, so there is no reader disagreement —
 * and the agreement is unusually strong here, because the disagreement about
 * these names is over what they REFER to, not over what the string is. The
 * string makes no false claim about itself either; `foo.invalid` is honest to
 * the point of being named for its own honesty. Nothing here is deception.
 *
 * **Why it is reported at all: §1.1's fourth rule, and its worked case is next
 * door.** `host_length_unresolvable` announces at weight 0 that an over-long
 * hostname will never work. `foo.invalid` is exactly that shape — well-formed,
 * universally agreed, honest about itself, and guaranteed by RFC 6761 §6.4 never
 * to work — so silence there is the same inconsistency the fourth rule exists to
 * close. The sharpest form of it is a pair: `192.168.1.1` already scores 0.20
 * because a literal that addresses a private network is worth mentioning, while
 * `svc.internal` — a NAME reserved for exactly that purpose — said nothing at
 * all.
 *
 * **THE PREDICATE IS THE UNIFORM FACT, and the category detail goes beneath it.**
 * The set is not homogeneous: `.invalid` and `.alt` have no referent anywhere,
 * `.internal`/`.local`/`home.arpa`/`.test` have a locally-scoped one, `.onion`
 * is a separate namespace, and `.localhost` is fixed to loopback by RFC 6761
 * §6.3, which makes it the LEAST context-dependent name in the set. All of that
 * is refinement printed after the sentence above, never in place of it.
 *
 * **SUFFIXES ONLY — the example DOMAINS are excluded.** RFC 6761 §6.5 also
 * reserves `example.com`/`.net`/`.org`, but those are second-level reservations
 * under a DELEGATED TLD and they do resolve. The line is "TLD-level reservation,
 * never delegated" versus "second-level reservation under a delegated TLD", and
 * it is measurable: `example.com`'s public suffix is `com`.
 *
 * **THE CLOUD-METADATA COLLISION, decided and pinned.** `metadata.google.internal`
 * sits under `.internal` and already carries a finding — `ip_cloud_metadata`
 * (0.75 when this was decided; weight 0 since LINK-bwqhvjcs, architecture
 * §6.1.10), and 1.00 with `ssrf_cloud_metadata` under `agentMode`. This check SUPPRESSES itself on exactly the hosts
 * `matchCloudMetadataHostname` names, for two reasons and not one:
 *
 *   1. The fourth rule's trigger is absent. The rule fires on "returning 0.00
 *      with no reasons"; a host that already carries an ip_cloud_metadata
 *      finding is not being silently passed (at any weight), so there is no silence to close and nothing is owed.
 *   2. The sentence would be FALSE where it landed. The predicate says the name
 *      is never publicly resolvable. That is true of `.internal` as a suffix and
 *      beside the point for this host, whose whole hazard is that it resolves,
 *      reliably, to a credential-vending endpoint that the vendor publishes. Two
 *      reasons that disagree about what matters is worse than one.
 *
 * The suppression reads the SAME matcher `ssrf_cloud_metadata` and
 * `ip_cloud_metadata` read, so the two can never drift apart. What it does not
 * do is generalise: a host is suppressed because a specific table names it, not
 * because some other reason happened to fire.
 *
 * **`.onion` LABEL SYNTAX IS OUT OF SCOPE and is not decided here.** A v3 onion
 * address is a 56-character base32 pubkey + checksum, so `ab.onion` announces a
 * Tor identity it cannot be — §1.1 form 3, which is scoring-eligible. Folding
 * that into a weight-0 code would settle a scoring question by smuggling. This
 * check says only that `.onion` is reserved and not in the DNS.
 *
 * **THIS DOES NOT DECIDE `LINK-qqwfpxvu` SIDEWAYS.** The axis rejected there was
 * *authority-fixed content licenses SCORING*. Nothing here scores. Weight 0
 * defeats the deception objection and RFC-fixed content defeats the durability
 * objection; both are required and neither suffices alone, so a proposal that
 * has only one of them is still refused.
 */
export const specialUseName: Detector = {
  id: "special_use_name",
  layer: "lexical",
  run(ctx) {
    // IP literals are not domain names and have no suffix structure.
    if (ctx.isIp || ctx.host === "") return [];

    const row = matchSpecialUseName(ctx.host);
    if (!row) return [];

    // A host a cloud-metadata code already names is not being silently passed.
    if (matchCloudMetadataHostname(ctx.host)) return [];

    return [
      {
        code: "special_use_name",
        detail:
          `host sits under the reserved special-use name \`.${row.name}\`: ${PREDICATE} ` +
          `(${row.citation}) — ${row.note}. Informational only — the string is well-formed, ` +
          `every reader agrees on it, and it makes no false claim about itself, so it is not ` +
          `a deception finding`,
      },
    ];
  },
};
