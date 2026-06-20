import type { Detector } from "./types.js";

/** Subdomain label count at or above which the host is flagged. */
const SUBDOMAIN_DEPTH_THRESHOLD = 5;

/**
 * I3 — excessive subdomain depth. Low-weight scoring (0.15) so it is only
 * meaningful in combination, never a flag on its own.
 *
 * An abnormally large number of subdomain labels (e.g.
 * `a.b.c.d.paypal.com.evil.tk`) is a known phishing structure used to bury the
 * real registrable domain far to the right of the visible host. Complements
 * `embedded_domain_in_subdomain` (FR-D-8): that detector fires only when a mid-
 * window of the subdomain is itself a registrable domain, whereas I3 fires on raw
 * subdomain DEPTH regardless of whether any window looks like a registrable
 * domain. Only the subdomain labels (everything left of the registrable domain)
 * are counted — the registrable-domain and public-suffix labels are excluded.
 */
export const excessiveSubdomainDepth: Detector = {
  id: "excessive_subdomain_depth",
  layer: "lexical",
  run(ctx) {
    if (ctx.isIp || !ctx.subdomain || !ctx.registrableDomain) return [];
    const count = ctx.subdomainLabels.filter(Boolean).length;
    if (count < SUBDOMAIN_DEPTH_THRESHOLD) return [];
    return [
      {
        code: "excessive_subdomain_depth",
        detail: `Host has ${count} subdomain labels left of the registrable domain '${ctx.registrableDomain}'`,
      },
    ];
  },
};
