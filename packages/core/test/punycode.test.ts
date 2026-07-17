import { describe, expect, it } from "vitest";
import { classifyAceLabel, analyzeMalformedPunycode } from "../src/unicode/punycode.js";
import { hasMalformedPunycode } from "../src/unicode/idna.js";
import { inspect } from "../src/index.js";

/**
 * P1 (LINK-dynjdiax) — RFC 3492 Punycode failure taxonomy for punycode_malformed.
 * The reason code stays stable; the detail names the specific sub-code. Firing is
 * still gated by tr46, so no host changes its flag decision.
 */

describe("classifyAceLabel — one case per decode-level sub-code", () => {
  it.each([
    ["xn--", "empty_ace_payload"],
    ["xn--@@", "invalid_punycode_digit"], // non-base-36 char in payload
    ["xn--a_b", "invalid_punycode_digit"],
    ["xn--0", "truncated_punycode_input"],
    ["xn--99999999a", "punycode_overflow"],
    ["xn--bb0c", "decoded_code_point_out_of_range"], // decodes above U+10FFFF
    ["xn--a-", "non_canonical_encoding"], // decodes but not canonical
    ["xn--caf-dma-", "non_canonical_encoding"],
  ])("%s → %s", (label, sub) => {
    expect(classifyAceLabel(label)).toBe(sub);
  });

  it("returns null for valid ACE labels (including uppercase — no case regression)", () => {
    for (const label of [
      "xn--caf-dma", // café
      "XN--CAF-DMA", // uppercase ACE round-trips after case-fold
      "xn--bcher-kva", // bücher
      "xn--pypal-4ve", // paypal Cyrillic homograph (valid ACE)
      "xn--ls8h", // 💩
      "xn--fa-hia", // faß
    ]) {
      expect(classifyAceLabel(label), label).toBeNull();
    }
  });

  it("A-label round-trip is the non_canonical_encoding signal (RFC 5891 §5.4)", () => {
    // A trailing delimiter makes the payload decode yet re-encode differently.
    expect(classifyAceLabel("xn--a-")).toBe("non_canonical_encoding");
    // The canonical form of the same content does round-trip.
    expect(classifyAceLabel("xn--caf-dma")).toBeNull();
  });
});

describe("analyzeMalformedPunycode — host-level, tr46-gated", () => {
  it("reports the first offending label with its sub-code", () => {
    const m = analyzeMalformedPunycode("xn--99999999a.com");
    expect(m).not.toBeNull();
    expect(m?.label).toBe("xn--99999999a");
    expect(m?.subCode).toBe("punycode_overflow");
    expect(m?.description).toContain("overflow");
  });

  it("falls back to invalid_idna_label when the label decodes but tr46 rejects it", () => {
    // xn--abc decodes + round-trips, but tr46 rejects the resulting U-label.
    const m = analyzeMalformedPunycode("xn--abc.com");
    expect(m?.subCode).toBe("invalid_idna_label");
  });

  it("returns null for valid IDNs and non-ACE hosts (no firing regression)", () => {
    for (const host of ["xn--bcher-kva.de", "XN--CAF-DMA.com", "example.com", "bücher.de"]) {
      expect(analyzeMalformedPunycode(host), host).toBeNull();
    }
  });

  it("fires on exactly the tr46-gated set (analyze ⇔ hasMalformedPunycode)", () => {
    for (const host of [
      "xn--.com",
      "xn--abc.com",
      "xn--0.com",
      "xn--99999999a.com",
      "xn--a-.com",
      "xn--bb0c.com",
      "xn--bcher-kva.de",
      "XN--CAF-DMA.com",
      "example.com",
    ]) {
      expect(analyzeMalformedPunycode(host) !== null, host).toBe(hasMalformedPunycode(host));
    }
  });
});

describe("punycode_malformed detector — sub-code surfaced in the detail", () => {
  it.each([
    ["https://xn--.com/", "empty_ace_payload"],
    ["https://xn--0.com/", "truncated_punycode_input"],
    ["https://xn--99999999a.com/", "punycode_overflow"],
    ["https://xn--a-.com/", "non_canonical_encoding"],
    ["https://xn--bb0c.com/", "decoded_code_point_out_of_range"],
    ["https://xn--abc.com/", "invalid_idna_label"],
  ])("%s detail names %s", (url, sub) => {
    const reason = inspect(url, { idnPolicy: "allow" }).reasons.find(
      (r) => r.code === "punycode_malformed",
    );
    expect(reason, url).toBeDefined();
    expect(reason?.detail).toContain(sub);
  });

  it("keeps valid IDNs (incl. uppercase ACE) free of punycode_malformed", () => {
    for (const url of [
      "https://xn--bcher-kva.de/",
      "https://XN--CAF-DMA.com/",
      "https://xn--pypal-4ve.ru/",
    ]) {
      const codes = inspect(url, { idnPolicy: "allow" }).reasons.map((r) => r.code);
      expect(codes, url).not.toContain("punycode_malformed");
    }
  });
});
