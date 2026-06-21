import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const CYR_A = String.fromCodePoint(0x0430); // Cyrillic а
const ZWSP = String.fromCodePoint(0x200b); // zero-width space
const RLO = String.fromCodePoint(0x202e); // right-to-left override

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);

describe("scoring detectors reach >= medium on their own (SC-1)", () => {
  it("mixed_script", () => {
    const r = inspect(`https://p${CYR_A}ypal.com`);
    expect(codes(r.input)).toContain("mixed_script");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });

  it("invisible_char", () => {
    const r = inspect(`https://exa${ZWSP}mple.com`);
    expect(r.reasons.map((x) => x.code)).toContain("invisible_char");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });

  it("bidi_override", () => {
    const r = inspect(`https://example.com/${RLO}fdp.exe`);
    expect(r.reasons.map((x) => x.code)).toContain("bidi_override");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });

  it("userinfo_present surfaces the real host", () => {
    const r = inspect("https://paypal.com@evil.com/login");
    const reason = r.reasons.find((x) => x.code === "userinfo_present");
    expect(reason).toBeDefined();
    expect(reason!.detail).toContain("evil.com");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });

  it("ip_obfuscation", () => {
    const r = inspect("http://2130706433/");
    const reason = r.reasons.find((x) => x.code === "ip_obfuscation");
    expect(reason?.detail).toContain("127.0.0.1");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });

  it("embedded_domain_in_subdomain", () => {
    const r = inspect("https://paypal.com.spoof.info/");
    const reason = r.reasons.find((x) => x.code === "embedded_domain_in_subdomain");
    expect(reason?.detail).toContain("spoof.info");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });

  it("embedded_domain_in_subdomain — mid-subdomain window, not just suffix (E4)", () => {
    // The brand domain sits between filler labels and the real eTLD+1.
    for (const url of [
      "https://paypal.com.login.evil.com/",
      "https://login.paypal.com.account.evil.com/",
      "https://secure-paypal.com.cdn.evil.com/",
    ]) {
      const r = inspect(url);
      const reason = r.reasons.find((x) => x.code === "embedded_domain_in_subdomain");
      expect(reason, url).toBeDefined();
      expect(reason?.detail, url).toContain("evil.com");
      expect(["medium", "high", "critical"], url).toContain(r.severity);
    }
  });

  it("dangerous_scheme (javascript: and data:)", () => {
    expect(inspect("javascript:alert(1)").severity).toBe("critical");
    expect(inspect("data:text/html,<script>").severity).toBe("critical");
  });

  it("dangerous_scheme — hostless local file: forms (V2 local-file-read coverage)", () => {
    // The hostless/slash-prefixed local forms previously slipped through as
    // `invalid` so the detector never saw scheme:file. They must now parse ok
    // and reach dangerous_scheme/critical like the host-qualified form.
    for (const url of ["file:/etc/passwd", "file:///etc/passwd", "file://localhost/etc/passwd"]) {
      const r = inspect(url);
      expect(r.status).toBe("ok");
      expect(r.reasons.map((x) => x.code)).toContain("dangerous_scheme");
      expect(r.severity).toBe("critical");
    }
  });
});

describe("encoding_obfuscation", () => {
  it("flags encoded traversal in the path", () => {
    expect(codes("https://example.com/%2e%2e%2fadmin")).toContain("encoding_obfuscation");
  });
  it("flags percent-encoding in the host", () => {
    expect(codes("http://%65xample.com/")).toContain("encoding_obfuscation");
  });
  it("does NOT flag legitimate encoding in a query value", () => {
    expect(codes("https://example.com/?redirect=https%3A%2F%2Fok.com")).not.toContain(
      "encoding_obfuscation",
    );
  });
});

describe("file_extension_tld (J6) owns .zip/.mov, sharper than risky_tld", () => {
  it("a bare filename host flags file_extension_tld, not risky_tld", () => {
    const r = inspect("https://invoice.zip/");
    const codes = r.reasons.map((x) => x.code);
    expect(codes).toContain("file_extension_tld");
    expect(codes).not.toContain("risky_tld");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });
});

describe("risky_tld is low and only matters in combination", () => {
  it("a bare risky TLD is low severity", () => {
    const r = inspect("https://promo.tk/");
    expect(r.reasons.map((x) => x.code)).toContain("risky_tld");
    expect(r.severity).toBe("low");
  });
});

describe("informational-only cases stay benign (SC-1a / SC-2)", () => {
  it("a single-script Cyrillic label on .com is benign with info reasons", () => {
    const r = inspect("https://пример.com"); // пример = Cyrillic word
    expect(r.status).toBe("ok");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.reasons.map((x) => x.code)).not.toContain("mixed_script");
    expect(r.reasons.every((x) => x.weight === 0)).toBe(true);
  });

  it("a legitimate German IDN is benign", () => {
    const r = inspect("https://müller.de/"); // müller.de
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
  });

  it("an ACE-form IDN with no scoring signal is benign", () => {
    const r = inspect("https://xn--bcher-kva.de/"); // bücher.de
    expect(r.score).toBe(0);
    expect(r.reasons.map((x) => x.code)).toContain("normalization_delta");
  });

  it("a path-embedded confusable annotates but does not score", () => {
    const r = inspect(`https://example.com/p${CYR_A}y`);
    expect(r.reasons.map((x) => x.code)).toContain("confusable_in_path");
    expect(r.score).toBe(0);
    expect(r.severity).toBe("info");
    expect(r.confusables.some((c) => c.component === "path")).toBe(true);
  });
});

describe("embedded_domain does not over-flag deep legitimate subdomains", () => {
  it("multi-label subdomain on a real multi-level suffix is benign", () => {
    const r = inspect("https://sub.domain.example.co.uk/path?a=1#x");
    expect(r.score).toBe(0);
    expect(r.reasons.map((x) => x.code)).not.toContain("embedded_domain_in_subdomain");
  });
});

describe("punycode_malformed (E5)", () => {
  it("flags an undecodable xn-- label at low severity", () => {
    for (const url of ["https://xn--abc.com/", "https://xn--.com/"]) {
      const r = inspect(url);
      expect(r.reasons.map((x) => x.code), url).toContain("punycode_malformed");
      expect(r.severity, url).toBe("low");
    }
  });

  it("does NOT flag a valid IDN, including uppercase ACE", () => {
    for (const url of [
      "https://xn--bcher-kva.de/", // bücher.de
      "https://XN--CAF-DMA.com/", // café.com — round-trips after case-folding
      "https://example.com/",
    ]) {
      expect(codes(url), url).not.toContain("punycode_malformed");
    }
  });
});

describe("confusables[] / reason invariant (FR-SCORE-2a)", () => {
  it("non-empty confusables implies a confusable reason and vice versa", () => {
    const r = inspect(`https://p${CYR_A}ypal.com`);
    const hasConfReason = r.reasons.some(
      (x) => x.code === "confusable_char" || x.code === "confusable_in_path",
    );
    expect(r.confusables.length > 0).toBe(hasConfReason);
  });
});

describe("PRD canonical reference example", () => {
  it("scores 0.7 / high with the documented reasons", () => {
    const r = inspect("https://paypal.com@xn--pypal-4ve.ru/login");
    expect(r.score).toBeCloseTo(0.7, 10);
    expect(r.severity).toBe("high");
    expect(r.reasons.map((x) => x.code)).toEqual([
      "userinfo_present",
      "mixed_script",
      "confusable_char",
      "normalization_delta",
    ]);
    expect(r.confusables).toHaveLength(1);
    expect(r.confusables[0]!.component).toBe("host");
  });
});

describe("benign control", () => {
  it("a plain URL has no reasons", () => {
    expect(inspect("https://www.example.com/path").reasons).toHaveLength(0);
  });
});
