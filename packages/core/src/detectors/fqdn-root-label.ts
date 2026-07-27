import type { Detector } from "./types.js";

/**
 * V7 (`LINK-fboctpse`). INFORMATIONAL, weight 0.
 *
 * The authority carries an explicit DNS root label — the trailing dot in
 * `example.com.`, the fully-qualified form. It resolves identically to
 * `example.com`, and every URL parser reads it identically, so nothing is
 * disguised and no parser disagrees.
 *
 * **Why this is an annotation and not `ambiguous_authority`.** The obvious home
 * looked like `ambiguous_authority` (0.65), but that code's contract is
 * "parsers disagree on the host" — and here they do not. The divergence is one
 * layer downstream, in consumers that compare host **strings**: an allow-list
 * holding `example.com` does not match `example.com.`, which is the documented
 * Smokescreen SSRF-filter bypass. That is a real hazard, but it is a property of
 * the consumer's comparison, not a structural deception in the URL, so under
 * architecture §1.1 it is reportable without being scoreable. Scoring it at 0.65
 * would also fail the CLI's default `--fail-on high` on a URL that is valid per
 * RFC 1034 §3.1 and resolves to exactly where it says.
 *
 * **linklint's own policy layer is not affected** and was verified before this
 * check was written: `allowHosts`/`denyHosts` match on `ctx.registrableDomain`,
 * which is already root-label-normalized, so `https://example.com./` matches an
 * `example.com` allow-list and an unlisted host is still refused. The finding
 * exists for *other* consumers, which is why it explains the bypass rather than
 * just naming the character.
 *
 * Scope is the single root dot, which is the form that actually works. Two or
 * more trailing dots (`example.com..`) produce an empty label, are rejected at
 * parse time as `invalid`/`parse_error`, and never reach a detector.
 */
export const fqdnRootLabel: Detector = {
  id: "fqdn_root_label",
  layer: "lexical",
  run(ctx) {
    // IP literals are not domain names and have no root label.
    if (ctx.isIp || ctx.host === "") return [];
    if (!ctx.host.endsWith(".")) return [];

    const bare = ctx.host.slice(0, -1);
    return [
      {
        code: "fqdn_root_label",
        detail:
          `host '${ctx.host}' carries an explicit DNS root label (the trailing dot) — the ` +
          `fully-qualified form of '${bare}'. It is valid (RFC 1034 §3.1) and resolves ` +
          `identically, so this is informational, not a deception finding. It is reported ` +
          `because a consumer that allow-lists host names by STRING comparison will not ` +
          `match '${bare}' against this input and can be bypassed by the single trailing ` +
          `character; compare registrable domains instead, as linklint's own policy layer does`,
      },
    ];
  },
};
