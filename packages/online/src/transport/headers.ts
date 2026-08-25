const FORWARDED_REQUEST_HEADERS = new Set([
  "accept",
  "accept-language",
  "user-agent",
]);

/** Longest synthetic Referer accepted; a referrer is never a bulk data channel. */
const MAX_REFERER_LENGTH = 2_048;

/**
 * Build a fresh destination header set; never mutate or spread caller input.
 * `referer` is the dedicated same-origin channel and is applied last, so no
 * caller-supplied header can reach or shadow it — `Referer` is deliberately
 * absent from the forwarded allowlist.
 */
export function destinationHeaders(
  host: string,
  input: Readonly<Record<string, string>> | undefined,
  referer?: string,
): Readonly<Record<string, string>> {
  const headers: Record<string, string> = {
    host,
    "accept-encoding": "gzip, deflate, br",
  };
  for (const [name, value] of Object.entries(input ?? {})) {
    const normalized = name.toLowerCase();
    if (
      typeof value === "string" &&
      FORWARDED_REQUEST_HEADERS.has(normalized) &&
      // A request-SPLITTING guard, and ONLY that. It is not the wire charset and
      // must not be widened into one: this seam runs for every HTTP port,
      // caller-supplied ones included, so what it refuses has to be what NO port
      // may ever be handed — a value that could forge a second request or
      // terminate the header block. Silently dropping such a value is right
      // here, because it is an injection attempt rather than a request the
      // caller can restate.
      //
      // Whether a value is SENDABLE is a different question with a different
      // answer per port. Node's line is Latin-1, so `ü` is legal and `Ā` is not,
      // and a copy of that line in this file would be an adapter's rule wearing
      // the boundary's clothes. `transport/node.ts` owns it, screens for it
      // before dispatch, and catches Node's synchronous refusal behind that —
      // where an unsendable value becomes a typed `http-malformed` the caller
      // can act on rather than a silent drop or a raw `TypeError`.
      !/[\0\r\n]/.test(value)
    ) {
      headers[normalized] = value;
    }
  }
  if (referer !== undefined) headers.referer = referer;
  return headers;
}

/**
 * Validate a synthetic Referer candidate against the destination it would be
 * sent to. Returns the exact value to send, or `null` when the candidate is not
 * a usable same-origin referrer, in which case the request must fail closed.
 *
 * Same-origin means the scheme, host, and effective port all match, so a
 * caller-held cross-origin (possibly private) referrer can never leave through
 * this channel. Userinfo is rejected and the fragment is dropped, both of which
 * a referrer must never carry.
 */
export function sameOriginRefererValue(destination: URL, candidate: string): string | null {
  if (typeof candidate !== "string" || candidate.length > MAX_REFERER_LENGTH) return null;
  let referer: URL;
  try {
    referer = new URL(candidate);
  } catch {
    return null;
  }
  if (referer.protocol !== "http:" && referer.protocol !== "https:") return null;
  if (referer.username !== "" || referer.password !== "") return null;
  if (referer.origin !== destination.origin) return null;
  referer.hash = "";
  if (referer.href.length > MAX_REFERER_LENGTH || /[\0\r\n]/.test(referer.href)) return null;
  return referer.href;
}
