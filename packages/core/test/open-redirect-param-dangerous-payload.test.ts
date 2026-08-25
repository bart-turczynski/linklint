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
// State pinned by this revision: hostless dangerous-scheme payloads are silent on
// BOTH surfaces, and no other detector covers them — `dangerous_scheme` itself reads
// `ctx.scheme`, the INPUT's own scheme, so it can never see a payload.

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

describe("LINK-txgqerim — hostless payloads are CURRENTLY SILENT (pinned, to be changed)", () => {
  it.each(DANGEROUS)("%s: in a query redirect param does NOT fire", (scheme) => {
    const input = `https://example.com/login?next=${HOSTLESS[scheme]}`;
    expect(codes(input)).not.toContain("open_redirect_param");
    expect(inspect(input).score).toBe(0);
  });

  it.each(DANGEROUS)("%s: in a fragment redirect param does NOT fire", (scheme) => {
    const input = `https://example.com/login#next=${HOSTLESS[scheme]}`;
    expect(codes(input)).not.toContain("open_redirect_param");
    expect(inspect(input).score).toBe(0);
  });

  it("no other detector covers it — dangerous_scheme reads the INPUT's scheme only", () => {
    expect(codes("https://example.com/login?next=javascript:alert(1)")).toEqual([]);
    expect(codes("https://example.com/login#next=javascript:alert(1)")).toEqual([]);
  });

  it("percent-encoded and mixed-case spellings are silent too", () => {
    expect(codes("https://example.com/login?next=javascript%3Aalert(1)")).not.toContain(
      "open_redirect_param",
    );
    expect(codes("https://example.com/login?next=JaVaScRiPt:alert(1)")).not.toContain(
      "open_redirect_param",
    );
  });
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
