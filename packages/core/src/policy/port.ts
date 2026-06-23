import type { InspectionContext } from "../detectors/types.js";
import type { CollectedFinding } from "../schema/serialize.js";

/**
 * Standard default port per scheme, used by the `denyNonStandardPorts` axis. A
 * scheme not in this map has no known standard port, so any explicit port on it
 * counts as non-standard.
 */
const STANDARD_PORTS: Record<string, number> = {
  http: 80,
  https: 443,
  ftp: 21,
  ws: 80,
  wss: 443,
};

/**
 * Port axis. Caller-configured deny on the port, evaluated only when an
 * explicit port is present (ctx.port non-null). `denyPorts` blocks enumerated
 * ports; `denyNonStandardPorts` blocks any explicit port that is not the
 * scheme's standard default (see STANDARD_PORTS). At most one port_denied is
 * emitted per input — if both conditions hit, the deny-list reason wins
 * (deduped).
 */
export function runPortAxis(ctx: InspectionContext): CollectedFinding[] {
  const findings: CollectedFinding[] = [];

  if (ctx.port !== null) {
    const port = ctx.port;
    if (ctx.runtime.policy.denyPorts.set.has(port)) {
      findings.push({
        code: "port_denied",
        detail: `port ${port} is on the caller deny-list`,
      });
    } else if (ctx.runtime.policy.denyNonStandardPorts) {
      const scheme = ctx.scheme ? ctx.scheme.toLowerCase() : null;
      const standard = scheme !== null ? STANDARD_PORTS[scheme] : undefined;
      if (standard === undefined || port !== standard) {
        const expected =
          standard !== undefined
            ? ` (expected ${standard})`
            : scheme !== null
              ? ` (no standard port for scheme '${scheme}')`
              : "";
        findings.push({
          code: "port_denied",
          detail: `port ${port} is non-standard for scheme '${scheme ?? "?"}'${expected}`,
        });
      }
    }
  }

  return findings;
}
