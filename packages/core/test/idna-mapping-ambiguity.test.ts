import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { scanIdnaMappingAmbiguity } from "../src/detectors/idna-mapping-ambiguity.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  scanIdnaMappingAmbiguity(input)[0]?.detail ?? "";

describe("J9 idna_mapping_ambiguity — Group A (deviation chars differ across standards)", () => {
  it("eszett ß resolves to a different ASCII domain (wordpreß → wordpress)", () => {
    const r = inspect("http://wordpreß.com");
    expect(r.reasons.map((x) => x.code)).toContain("idna_mapping_ambiguity");
    const d = detail("http://wordpreß.com");
    expect(d).toContain("wordpress.com"); // the IDNA2003 reading
    expect(d).toContain("IDNA2003");
  });

  it("ZWJ (U+200D) — IDNA2003 strips it, UTS-46 encodes it", () => {
    expect(codes("http://g‍oogle.com")).toContain("idna_mapping_ambiguity");
  });
});

describe("J9 — Group B (compatibility folds to ASCII, no punycode)", () => {
  it("fullwidth Latin folds to google.com (parseable, stays ok)", () => {
    const r = inspect("http://ｇｏｏｇｌｅ.com");
    expect(r.status).toBe("ok");
    expect(r.reasons.map((x) => x.code)).toContain("idna_mapping_ambiguity");
    expect(detail("http://ｇｏｏｇｌｅ.com")).toContain("google.com");
  });

  it("circled letters are rejected by parse() but still explained on the invalid result", () => {
    const r = inspect("http://ⓖⓞⓞⓖⓛⓔ.com");
    expect(r.status).toBe("invalid");
    expect(r.reasons.map((x) => x.code)).toEqual(["idna_mapping_ambiguity"]);
    expect(r.reasons[0]!.detail).toContain("google.com");
  });
});

describe("J9 — informational only (weight 0); legit IDNs stay benign (SC-2)", () => {
  it("does not raise severity on its own — baß.de is a real German IDN", () => {
    const r = inspect("https://baß.de");
    expect(r.status).toBe("ok");
    expect(r.severity).toBe("info");
    expect(r.score).toBe(0);
    expect(r.reasons.map((x) => x.code)).toContain("idna_mapping_ambiguity");
    const reason = r.reasons.find((x) => x.code === "idna_mapping_ambiguity");
    expect(reason!.weight).toBe(0);
  });

  const noFlag = [
    "https://example.com", // pure ASCII
    "https://мойдомен.рф", // legitimate Cyrillic IDN → punycode under both standards
    "https://例子.中国", // legitimate Chinese IDN
    "https://xn--80ak6aa92e.com", // already-ACE host, pure ASCII
    "http://127.0.0.1/", // IP, never an IDN
  ];
  for (const input of noFlag) {
    it(`no idna_mapping_ambiguity for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("idna_mapping_ambiguity");
    });
  }
});

describe("J9 — scanIdnaMappingAmbiguity is total and host-scoped", () => {
  it("returns [] for empty / opaque / IP / pure-ASCII input", () => {
    for (const i of ["", "javascript:alert(1)", "https://example.com", "http://2130706433/"]) {
      expect(scanIdnaMappingAmbiguity(i)).toEqual([]);
    }
  });

  it("ignores deviation chars in userinfo, not the host", () => {
    // ß is in the userinfo; the real host (example.com) is plain ASCII.
    expect(scanIdnaMappingAmbiguity("http://uß@example.com")).toEqual([]);
  });
});
