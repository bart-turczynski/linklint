import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

// LINK-txgqerim — a HOSTLESS payload inside a redirect parameter.
//
// `open_redirect_param` matches a payload only through `targetHost`, which needs
// `scheme://host` or `//host`. A `javascript:` payload has no authority at all, so
// the highest-severity payload the registry knows about is the one shape the
// redirect-param detector cannot see. `docs/architecture.md` puts the two codes in
// the SAME family (**Dangerous payloads**: `dangerous_scheme`, `file_extension_tld`,
// `suspicious_extension`, `open_redirect_param`), and a redirect parameter carrying
// `javascript:` is the paradigm case of that family.
//
// State pinned by this revision: a hostless dangerous-scheme payload fires
// `open_redirect_param` on BOTH surfaces, at that code's own weight 0.4 and NOT at
// `dangerous_scheme`'s 0.9. That is a constraint rather than a preference —
// `checks.ts` declares `emits: ["open_redirect_param"]` for this check and
// `checks-registry.test.ts` forbids two descriptors from emitting one code, so the
// payload case cannot be routed through the `dangerous_scheme` check; a NEW code
// would force a SCHEMA_VERSION bump. The one-band understatement relative to the
// same bytes standing alone is asserted below so it stays visible.
//
// The previous revision of this file pinned the opposite (silent on both surfaces)
// and its rows were watched to redden on this change.

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

const codes = (input: string): string[] =>
  inspect(input)
    .reasons.map((r) => r.code)
    .sort();

/**
 * The FR-D-11 scheme set, read out of `dangerous-scheme.ts` rather than restated.
 * `open-redirect-param.ts` has to carry its own copy — `checks.ts` forbids two
 * descriptors from emitting one reason code, so the payload case cannot be routed
 * through the `dangerous_scheme` check — and this is the guard that keeps the two
 * copies in step when either moves.
 */
function fileRdSchemes(): string[] {
  const src = readFileSync(
    join(REPO_ROOT, "packages", "core", "src", "detectors", "dangerous-scheme.ts"),
    "utf8",
  );
  const m = src.match(/const DANGEROUS_SCHEMES = new Set\(\[([^\]]*)\]\)/);
  expect(m, "DANGEROUS_SCHEMES literal not found in dangerous-scheme.ts").toBeTruthy();
  const schemes = [...(m![1] as string).matchAll(/"([a-z]+)"/g)].map((x) => x[1] as string);
  expect(schemes.length).toBeGreaterThanOrEqual(5);
  return schemes;
}

const DANGEROUS = fileRdSchemes();

/** A hostless URL in each dangerous scheme — the shape `targetHost` cannot see. */
const HOSTLESS: Record<string, string> = {
  javascript: "javascript:alert(1)",
  data: "data:text/html,<b>x</b>",
  vbscript: "vbscript:msgbox(1)",
  blob: "blob:https://example.org/uuid",
  file: "file:///etc/passwd",
};

describe("LINK-txgqerim — a bare dangerous-scheme URL is critical (unchanged baseline)", () => {
  it.each(DANGEROUS)("%s: as the INPUT scores 0.9/critical via dangerous_scheme", (scheme) => {
    const payload = HOSTLESS[scheme];
    expect(payload, `no hostless sample for scheme '${scheme}'`).toBeTruthy();
    const r = inspect(payload!);
    expect(r.reasons.map((x) => x.code)).toContain("dangerous_scheme");
    expect(r.score).toBeCloseTo(0.9, 5);
    expect(r.severity).toBe("critical");
  });
});

describe("LINK-txgqerim — hostless payloads fire on BOTH surfaces", () => {
  it.each(DANGEROUS)("%s: in a query redirect param fires open_redirect_param", (scheme) => {
    const input = `https://example.com/login?next=${HOSTLESS[scheme]}`;
    expect(codes(input)).toContain("open_redirect_param");
  });

  it.each(DANGEROUS)("%s: in a fragment redirect param fires open_redirect_param", (scheme) => {
    const input = `https://example.com/login#next=${HOSTLESS[scheme]}`;
    expect(codes(input)).toContain("open_redirect_param");
  });

  it.each(DANGEROUS)("%s: query and fragment spellings agree exactly", (scheme) => {
    const q = `https://example.com/login?next=${HOSTLESS[scheme]}`;
    const f = `https://example.com/login#next=${HOSTLESS[scheme]}`;
    expect(codes(f)).toEqual(codes(q));
    expect(inspect(f).score).toBe(inspect(q).score);
  });

  it("still reported as open_redirect_param, never as dangerous_scheme", () => {
    // `checks.ts` gives `dangerous_scheme` to exactly one descriptor; this check
    // may not also emit it, and a new code would force a SCHEMA_VERSION bump.
    const r = inspect("https://example.com/login?next=javascript:alert(1)");
    expect(r.reasons.map((x) => x.code)).toEqual(["open_redirect_param"]);
  });

  it("the understatement against the same bytes standing alone is deliberate", () => {
    const wrapped = inspect("https://example.com/login?next=javascript:alert(1)");
    const bare = inspect("javascript:alert(1)");
    expect(wrapped.reasons.find((x) => x.code === "open_redirect_param")!.weight).toBeCloseTo(
      0.4,
      5,
    );
    expect(bare.reasons.find((x) => x.code === "dangerous_scheme")!.weight).toBeCloseTo(0.9, 5);
    expect(wrapped.severity).toBe("medium");
    expect(bare.severity).toBe("critical");
  });

  it("the detail says executable payload, not off-site, and names the scheme", () => {
    const d = (input: string): string =>
      inspect(input).reasons.find((r) => r.code === "open_redirect_param")?.detail ?? "";
    expect(d("https://example.com/login?next=javascript:alert(1)")).toContain(
      "carries an executable payload",
    );
    expect(d("https://example.com/login?next=javascript:alert(1)")).toContain("'javascript:'");
    expect(d("https://example.com/login#next=data:text/html,<b>x</b>")).toContain(
      "fragment redirect parameter",
    );
  });

  it("percent-encoded and mixed-case spellings fire too", () => {
    expect(codes("https://example.com/login?next=javascript%3Aalert(1)")).toContain(
      "open_redirect_param",
    );
    expect(codes("https://example.com/login?next=JaVaScRiPt:alert(1)")).toContain(
      "open_redirect_param",
    );
  });
});

describe("LINK-txgqerim — the hostless shape must not over-flag (SC-2)", () => {
  const benign = [
    "https://example.com/?next=mailto:someone@example.org", // ordinary non-dangerous scheme
    "https://example.com/?next=tel:+15550100",
    "https://example.com/?ref=javascript:alert(1)", // not a redirect param name
    "https://example.com/?next=/dashboard", // relative
    "https://example.com/?next=datacenter-report", // starts with 'data' but is not a scheme
    "https://example.com/?next=filet-mignon", // starts with 'file' but is not a scheme
    "https://example.com/#/blob/main/README.md", // hash route that merely contains 'blob'
  ];
  for (const input of benign) {
    it(`no open_redirect_param for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("open_redirect_param");
    });
  }
});

describe("LINK-txgqerim — the WITH-host spellings already fire (not part of the hole)", () => {
  it("file://evil.com/x fires — it has an authority", () => {
    expect(codes("https://example.com/?next=file://evil.com/x")).toContain("open_redirect_param");
  });

  it("javascript://evil.com/%0aalert(1) fires — it parses as an authority", () => {
    expect(codes("https://example.com/?next=javascript://evil.com/%0aalert(1)")).toContain(
      "open_redirect_param",
    );
  });
});
