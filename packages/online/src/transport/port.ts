/**
 * The outbound effective port, in one place (LINK-fnonqivj).
 *
 * Every boundary in this package that opens a socket needs the same number: the
 * URL's explicit port when it has one, otherwise the scheme's default. It used
 * to be written out at four of them — L0's fetch, L0's TLS inspection, the RDAP
 * provider client and the mirror-download engine — with only L0's fetch giving
 * it a name. That made the named one look like a choke point it was not: three
 * live outbound boundaries re-derived the value inline, so anything attached to
 * the name would have covered one connection in four.
 *
 * It lives in its own module rather than in `safe-transport.ts` because two of
 * its callers sit OUTSIDE L0 on purpose (see `reputation/rdap-node.ts` and
 * `mirrors/mirror-http-node.ts`): a provider client importing from the L0
 * entrypoint would read as routing provider traffic through a boundary that
 * `docs/online-runtime-boundary.md` says it must not. This is the same shape as
 * `transport/address.ts` and `transport/policy.ts`, which those clients already
 * share — the derivation is single-sourced, the boundary is not moved.
 *
 * It is deliberately NOT a policy hook. It answers what the URL says, and
 * nothing here decides whether that port may be dialled; restricting
 * destination ports was declined separately (LINK-rfjeztxh).
 *
 * `mirrors/url-canonical.ts` is not a caller and does not belong here. It
 * answers a different question — may this port be OMITTED from canonical text —
 * against a string, and its answer never reaches a socket.
 */

/**
 * The port a request to `url` connects to: `url.port` when the URL carries one,
 * otherwise 443 for `https:` and 80 for anything else.
 *
 * WHATWG `URL` has already erased a redundantly written default (`:443` on
 * https, `:80` on http) by the time this runs, so those arrive as the
 * empty-port case and come back as the same number they were written as. A
 * default written for the OTHER scheme (`:80` on https) survives parsing and is
 * an explicit port like any other.
 */
export function effectivePort(url: URL): number {
  if (url.port !== "") return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}
