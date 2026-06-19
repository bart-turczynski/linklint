import type { DetectorFinding } from "./types.js";
import { authorityRegion } from "../parse/authority-region.js";
import { boundedDecode } from "../parse/decode.js";

/**
 * J3 — `control_char` (Epic J, FR parser-differential). SCORING.
 *
 * Flags ASCII control / whitespace characters — raw OR percent-encoded — used to
 * SMUGGLE a protocol or TERMINATE the host. The Tsai "A New Era of SSRF"
 * protocol-smuggling + glibc-NSS sections: a CRLF lets the requester speak a
 * second protocol on the wire (Redis `SLAVEOF`, SMTP `HELO`, Memcached `set`); a
 * TAB or whitespace truncates the host so the validator and `getaddrinfo()` see
 * different destinations. A flagship MCP pre-fetch signal: these payloads attack
 * Redis / SMTP / Memcached sitting behind the server that fires the request.
 *
 * Complements `invisible_char` (FR-D-4), which already catches RAW control
 * characters because they are Unicode `Cc`. The non-overlapping value here is:
 *   - PERCENT-ENCODED control chars (`%0D%0A`, `%09`) — plain ASCII text in the
 *     raw input, so `invisible_char` never sees them.
 *   - DOUBLE-ENCODED control chars (`%250D%250A`, `%2509`) — libraries that
 *     URL-decode twice resolve `%2509` → `%09` → TAB. Uses the shared bounded
 *     recursive decoder so adversarial nesting cannot create a decode-bomb.
 *   - BARE whitespace inside the authority (`127.0.0.1 foo`) — a space is `Zs`,
 *     not `Cc`, so `invisible_char` skips it, and a scheme-less host is out of
 *     `ambiguous_authority`'s scope. Scoped to host-shaped authorities (SC-2) so
 *     a space in a path or in non-URL prose does not flag.
 *
 * Runs as a raw scan (like J1/J2/J9) over the prepared input rather than the
 * parsed context, so the encoded payloads `parse()` would decode or discard
 * still explain themselves instead of degrading to a bare `parse_error`.
 */

/** Classify a control code point into a named sub-signal. */
function classify(code: number): "crlf" | "tab" | "null" | "control" | null {
  if (code === 0x0d || code === 0x0a) return "crlf";
  if (code === 0x09) return "tab";
  if (code === 0x00) return "null";
  // C0 controls (excluding the named ones above) and DEL.
  if ((code >= 0x01 && code <= 0x1f) || code === 0x7f) return "control";
  return null;
}

const SIGNAL_DETAIL: Record<string, string> = {
  crlf: "CR/LF — lets a requester smuggle a second protocol (Redis/SMTP/Memcached) on the wire",
  tab: "TAB — terminates the host so validator and resolver disagree",
  null: "NUL — truncates the host for a C-string resolver",
  control: "other C0/DEL control character",
  whitespace_in_host: "whitespace inside the authority — getaddrinfo strips the trailing rubbish",
};

/**
 * Scan the prepared input for control / whitespace smuggling characters. Returns
 * a single `control_char` finding naming every sub-signal that fired, or `[]`.
 */
export function scanControlChar(prepared: string): DetectorFinding[] {
  if (prepared === "") return [];

  const signals = new Set<string>();
  /** Encoding form per code class, for the detail gloss. */
  const forms = new Set<"raw" | "percent-encoded" | "double-encoded">();

  // 1. Raw control characters anywhere in the input (also caught by
  //    invisible_char, but reported here with the smuggling-specific framing).
  for (const ch of prepared) {
    const sig = classify(ch.codePointAt(0)!);
    if (sig) {
      signals.add(sig);
      forms.add("raw");
    }
  }

  // 2. Percent-encoded (and multiply-encoded) control characters. A legitimate
  //    URL never encodes CR/LF/TAB/NUL, so any decoded control byte is a signal.
  if (prepared.includes("%")) {
    const { decoded, passes } = boundedDecode(prepared);
    if (decoded !== prepared) {
      for (const ch of decoded) {
        const sig = classify(ch.codePointAt(0)!);
        if (sig) {
          signals.add(sig);
          forms.add(passes >= 2 ? "double-encoded" : "percent-encoded");
        }
      }
    }
  }

  // 3. Bare whitespace inside a host-shaped authority.
  const { authority, opaque } = authorityRegion(prepared);
  if (!opaque && authority !== "") {
    const hostport = authority.includes("@")
      ? authority.slice(authority.lastIndexOf("@") + 1)
      : authority;
    // Host-shaped guard (SC-2): a dot plus an alphanumeric — so non-URL prose
    // ("hello world") with no dot does not flag.
    if (/ |\t/.test(hostport) && /\./.test(hostport) && /[A-Za-z0-9]/.test(hostport)) {
      signals.add("whitespace_in_host");
      forms.add("raw");
    }
  }

  if (signals.size === 0) return [];

  const glossed = [...signals].map((s) => `${s} (${SIGNAL_DETAIL[s]})`).join("; ");
  const formNote = `[${[...forms].join(", ")}]`;
  return [
    {
      code: "control_char",
      detail:
        `URL carries control/whitespace characters used to smuggle a protocol or terminate ` +
        `the host ${formNote}: ${glossed}`,
    },
  ];
}
