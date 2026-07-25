import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { scanIdnaMappingAmbiguity } from "../src/detectors/idna-mapping-ambiguity.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  scanIdnaMappingAmbiguity(input)[0]?.detail ?? "";

describe("J9 idna_mapping_ambiguity — Group A (deviation chars differ across standards)", () => {
  // straße.de is the Group A shape on a NON-brand domain, so it stays on the
  // base informational code. The brand-bearing Group A hosts (wordpreß.com,
  // g<ZWJ>oogle.com) escalate — covered in the brand_idna_collapse block below.
  it("eszett ß resolves to a different ASCII domain (straße → strasse)", () => {
    const r = inspect("http://straße.de");
    expect(r.reasons.map((x) => x.code)).toContain("idna_mapping_ambiguity");
    const d = detail("http://straße.de");
    expect(d).toContain("strasse.de"); // the IDNA2003 reading
    expect(d).toContain("IDNA2003");
  });

  it("ZWNJ (U+200C) on a non-brand host — IDNA2003 strips it, UTS-46 encodes it", () => {
    expect(codes("http://ex‌ample.de")).toContain("idna_mapping_ambiguity");
  });
});

describe("J9 brand_idna_collapse — the IDNA2003 form IS a brand exactly", () => {
  it("wordpreß.com: validator reads wordpress.com, resolver reaches the attacker", () => {
    const r = inspect("http://wordpreß.com", { idnPolicy: "allow" });
    const codeList = r.reasons.map((x) => x.code);
    expect(codeList).toContain("brand_idna_collapse");
    // Mutually exclusive with the base code — one finding per input.
    expect(codeList).not.toContain("idna_mapping_ambiguity");

    const reason = r.reasons.find((x) => x.code === "brand_idna_collapse")!;
    expect(reason.weight).toBe(0.5);
    expect(reason.detail).toContain("wordpress.com"); // what the validator sees
    expect(reason.detail).toContain("xn--wordpre-6va.com"); // where the request lands
  });

  it("escalates through the ZWJ deviation route too", () => {
    expect(codes("http://g‍oogle.com")).toContain("brand_idna_collapse");
  });

  it("escalates on a subdomain — a validator checking the eTLD+1 still reads the brand", () => {
    const r = inspect("http://login.wordpreß.com", { idnPolicy: "allow" });
    expect(r.reasons.map((x) => x.code)).toContain("brand_idna_collapse");
    expect(r.score).toBeGreaterThanOrEqual(0.5);
  });

  // PRECISION GUARDS — the shapes that must NOT escalate.
  it("does not escalate Group B: both standards fold to the REAL google.com", () => {
    // The request reaches the genuine site, so there is no impersonation to
    // score. This is the load-bearing scope decision for the escalation.
    const codeList = codes("http://ｇｏｏｇｌｅ.com");
    expect(codeList).toContain("idna_mapping_ambiguity");
    expect(codeList).not.toContain("brand_idna_collapse");
  });

  it("does not escalate a Group A host whose IDNA2003 form is not a brand", () => {
    const codeList = codes("http://straße.de");
    expect(codeList).toContain("idna_mapping_ambiguity");
    expect(codeList).not.toContain("brand_idna_collapse");
  });

  it("does not escalate a legitimate brand-adjacent German IDN (baß.de)", () => {
    expect(codes("https://baß.de")).not.toContain("brand_idna_collapse");
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
    // idnPolicy "allow" isolates the J9 annotation: under the default "block"
    // this IDN is deliberately flagged by idn_host (covered by idn-policy.test.ts).
    const r = inspect("https://baß.de", { idnPolicy: "allow" });
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
