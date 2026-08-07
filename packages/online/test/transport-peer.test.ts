/**
 * LINK-abozdqtp — the built-in adapters report the peer the socket OBSERVED, or
 * they fail. They used to report `socket.remoteAddress ?? request.address` and
 * `socket.remotePort ?? request.port`, so a socket that observed nothing handed
 * the caller back the very pin the caller was about to check it against.
 *
 * `observedPeer` is the shared gate. These cases cover an absent field, a
 * malformed field, and a well-formed observation of either family; the pin
 * COMPARISON itself (match, mismatch, IPv4/IPv6 equivalence) is exercised end to
 * end in `safe-transport.test.ts` and `tls-inspect.test.ts`.
 */
import { describe, expect, it } from "vitest";

import { observedPeer } from "../src/transport/peer.js";

describe("observedPeer (LINK-abozdqtp)", () => {
  it("returns the observed endpoint when the socket reports both fields", () => {
    expect(observedPeer({ remoteAddress: "93.184.216.34", remotePort: 443 })).toEqual({
      address: "93.184.216.34",
      port: 443,
    });
    expect(observedPeer({ remoteAddress: "2606:2800:220:1:248:1893:25c8:1946", remotePort: 8443 }))
      .toEqual({ address: "2606:2800:220:1:248:1893:25c8:1946", port: 8443 });
  });

  it("refuses an absent address or port instead of substituting anything", () => {
    expect(observedPeer({ remotePort: 443 })).toBeNull();
    expect(observedPeer({ remoteAddress: "93.184.216.34" })).toBeNull();
    expect(observedPeer({})).toBeNull();
    expect(observedPeer({ remoteAddress: undefined, remotePort: undefined })).toBeNull();
  });

  it("refuses a malformed address", () => {
    for (const remoteAddress of ["", "origin.example", "93.184.216.999", "::ffff:", "not an ip"]) {
      expect(observedPeer({ remoteAddress, remotePort: 443 })).toBeNull();
    }
  });

  it("refuses a port outside the usable range or of the wrong shape", () => {
    for (const remotePort of [0, -1, 65_536, 443.5, Number.NaN]) {
      expect(observedPeer({ remoteAddress: "93.184.216.34", remotePort })).toBeNull();
    }
    expect(
      observedPeer({ remoteAddress: "93.184.216.34", remotePort: "443" as unknown as number }),
    ).toBeNull();
  });
});
