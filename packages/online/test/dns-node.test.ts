/**
 * The c-ares error-code -> {@link DnsAnswerState} table (LINK-enbiprjm).
 *
 * This table had zero coverage: every DNS test injects a fake resolver port, so
 * nothing ever drove the real mapping, and two entries were wrong. EBADNAME — a
 * name c-ares rejects locally, before any packet leaves the host — fell through
 * to `error`, which the enricher reports as retryable, so a caller was invited
 * to retry a call that can only ever fail the same way. Separately an empty name
 * produced ENODATA, which mapped to the AUTHORITATIVE `nodata`: a claim that a
 * name we never queried has no records.
 *
 * `stateForError` is imported from the module rather than the package index; it
 * is exported for this test alone, following `systemErrorCode`.
 */
import { describe, expect, it } from "vitest";

import { stateForError } from "../src/reputation/dns-node.js";
import type { DnsAnswerState } from "../src/reputation/dns-types.js";

/** A c-ares-shaped rejection: what `node:dns` actually throws. */
function coded(code: string): Error & { code: string } {
  return Object.assign(new Error(`queryA ${code} example.com`), { code });
}

/** Every code this port claims to map, and the state it must map to. */
const TABLE: readonly (readonly [string, Exclude<DnsAnswerState, "ok">])[] = [
  ["ENODATA", "nodata"],
  ["ENOTFOUND", "nxdomain"],
  ["ENONAME", "nxdomain"],
  ["ESERVFAIL", "servfail"],
  ["EBADRESP", "servfail"],
  ["EFORMERR", "servfail"],
  ["EREFUSED", "refused"],
  ["ECONNREFUSED", "refused"],
  ["ETIMEOUT", "timeout"],
  ["EBADNAME", "invalid-name"],
  ["EBADSTR", "invalid-name"],
];

describe("stateForError", () => {
  it.each(TABLE)("maps %s to %s", (code, state) => {
    expect(stateForError(coded(code), undefined)).toBe(state);
  });

  it("splits ECANCELLED on whether the caller actually aborted", () => {
    // Same code, two meanings: c-ares cancels on the caller's signal and on its
    // own timeout, and only the signal tells them apart.
    const aborted = AbortSignal.abort();
    expect(stateForError(coded("ECANCELLED"), aborted)).toBe("aborted");
    expect(stateForError(coded("ECANCELLED"), new AbortController().signal)).toBe("timeout");
    expect(stateForError(coded("ECANCELLED"), undefined)).toBe("timeout");
  });

  it("keeps a server sending garbage on servfail, not invalid-name", () => {
    // The line the fix must not cross. EBADRESP/EFORMERR look like "bad input"
    // but describe the RESPONSE, which is a network condition: a retry can
    // legitimately hit a different server and succeed.
    expect(stateForError(coded("EBADRESP"), undefined)).toBe("servfail");
    expect(stateForError(coded("EFORMERR"), undefined)).toBe("servfail");
  });

  it("falls back to error for an unanticipated or absent code", () => {
    expect(stateForError(coded("ENOTIMP"), undefined)).toBe("error");
    expect(stateForError(new Error("no code at all"), undefined)).toBe("error");
    expect(stateForError({ code: 42 }, undefined)).toBe("error");
    expect(stateForError(null, undefined)).toBe("error");
  });

  it("never reports a local rejection as an authoritative negative", () => {
    // The invariant dns-types.ts states: only ok/nodata/nxdomain describe DNS
    // reality. A locally rejected name never reached DNS at all.
    const authoritative = new Set(["nodata", "nxdomain"]);
    for (const code of ["EBADNAME", "EBADSTR"]) {
      expect(authoritative.has(stateForError(coded(code), undefined))).toBe(false);
    }
  });
});
