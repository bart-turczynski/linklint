import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { SCHEMA_VERSION } from "../src/schema/base.js";

/**
 * LINK-sgcovhzr — the hostile-string sweep, made permanent.
 *
 * This is the STRING half of the 107-case adversarial sweep that found
 * LINK-zsbeqtcr. The non-string half already has a home in
 * `non-string-input.test.ts`; the string half lived only in a scratchpad and
 * would have been lost.
 *
 * Every case here PASSES today. That is the point: this is regression
 * protection, not a bug report. What it pins is the never-throws guarantee
 * (docs/reason-codes.md) across the inputs an attacker actually reaches for —
 * bidi overrides, lone surrogates, punycode overflow, decode bombs, malformed
 * IPv6, exotic schemes. An uncaught throw inside a link-checking hook fails
 * OPEN, which is the exact failure mode linklint exists to prevent.
 *
 * The assertions are deliberately CONTRACT-level, not verdict-level. Pinning
 * the score of `http://xn--<200 nines>.com` would be pinning an accident;
 * pinning that it returns a schema-valid result without throwing is pinning
 * the guarantee. Verdict-level expectations belong in the per-detector suites.
 */

/** Every C0 control, as a single run inside a host label. */
const ALL_C0 = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).join("");
/** A representative C1 run (U+0080–U+009F is the whole block; three is enough). */
const C1_RUN = "\u0080\u0085\u009F";

/** A 12-deep redirect wrapper nest — the decode bomb. */
const NESTED_WRAPPER = ((): string => {
  let url = "https://evil.example/";
  for (let i = 0; i < 12; i++) {
    url = `https://r.example/?url=${encodeURIComponent(url)}`;
  }
  return url;
})();

type Case = readonly [label: string, input: string];

const DEGENERATE: readonly Case[] = [
  ["empty string", ""],
  ["single space", " "],
  ["only scheme", "http:"],
  ["scheme + slashes", "http://"],
  ["just dots", "..."],
  ["just a dot host", "http://."],
  ["double dot host", "http://.."],
  ["trailing dot host", "http://example.com."],
  ["many trailing dots", "http://example.com...."],
  ["empty interior label", "http://foo..bar.com"],
  ["leading dot", "http://.example.com"],
];

const CONTROL_CHARS: readonly Case[] = [
  ["null byte in host", "http://exam\u0000ple.com"],
  ["null byte as terminator", "http://example.com\u0000.evil.com"],
  ["tab in host", "http://exam\tple.com"],
  ["newline in host", "http://exam\nple.com"],
  ["CR in host", "http://exam\rple.com"],
  ["every C0 control in a label", `http://a${ALL_C0}b.com`],
  ["DEL char", "http://example.com\u007F"],
  ["C1 controls", `http://a${C1_RUN}.com`],
  ["newline in path", "http://example.com/a\nb"],
  ["null byte in query", "http://example.com/?q=\u0000"],
];

const BIDI_AND_INVISIBLE: readonly Case[] = [
  ["RLO override", "http://example.com/\u202Egnp.exe"],
  ["LRO override", "http://\u202Dexample.com"],
  ["RLM/LRM marks", "http://exa\u200Fmple\u200E.com"],
  ["zero-width space", "http://exa\u200Bmple.com"],
  ["zero-width non-joiner", "http://exa\u200Cmple.com"],
  ["zero-width joiner", "http://exa\u200Dmple.com"],
  ["soft hyphen", "http://exa\u00ADmple.com"],
  ["word joiner", "http://exa\u2060mple.com"],
  ["BOM in host", "http://\uFEFFexample.com"],
  ["bidi isolates", "http://\u2066example.com\u2069"],
  ["Mongolian vowel separator", "http://exa\u180Emple.com"],
];

const MALFORMED_UNICODE: readonly Case[] = [
  ["lone high surrogate", "http://exa\uD800mple.com"],
  ["lone low surrogate", "http://exa\uDC00mple.com"],
  ["reversed surrogate pair", "http://exa\uDC00\uD800mple.com"],
  ["replacement character", "http://exa\uFFFDmple.com"],
  ["noncharacter U+FFFE", "http://exa\uFFFEmple.com"],
  ["noncharacter U+FFFF", "http://exa\uFFFFmple.com"],
  ["astral-plane host", "http://\u{1F4A9}\u{1F4A9}.com"],
  ["mathematical alphanumerics", "http://\u{1D5BE}\u{1D5CF}\u{1D5EE}.com"],
];

const PUNYCODE: readonly Case[] = [
  ["bare xn--", "http://xn--.com"],
  ["malformed punycode", "http://xn--a.com"],
  ["punycode garbage", "http://xn--zzzzzzzzzz.com"],
  ["nested xn--", "http://xn--xn--a-a.com"],
  ["punycode overflow", `http://xn--${"9".repeat(200)}.com`],
  ["uppercase XN--", "http://XN--MNCHEN-3YA.de"],
  ["double-encoded punycode", "http://xn--xn--mnchen-3ya-lwb.de"],
];

const EXHAUSTION: readonly Case[] = [
  ["10k-char host", `http://${"a".repeat(10000)}.com`],
  ["5k-label chain", `http://${"a.".repeat(5000)}com`],
  ["100k-char path", `http://example.com/${"a".repeat(100000)}`],
  ["100k-char query", `http://example.com/?q=${"a".repeat(100000)}`],
  ["50k percent-escapes", `http://example.com/${"%41".repeat(50000)}`],
  ["5k at-signs", `http://${"a@".repeat(5000)}evil.example`],
  ["5k colons", `http://${":".repeat(5000)}evil.example`],
  ["2k nested percent-encodings", `http://example.com/${"%25".repeat(2000)}41`],
];

const DECODE_BOMBS: readonly Case[] = [
  ["12-deep wrapper nest", NESTED_WRAPPER],
  [
    "self-referential wrapper",
    "https://r.example/?url=https%3A%2F%2Fr.example%2F%3Furl%3Dhttps%253A%252F%252Fr.example%252F",
  ],
  [
    "data: inside a wrapper",
    `https://r.example/?url=${encodeURIComponent(
      "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    )}`,
  ],
];

const SCHEMES: readonly Case[] = [
  ["data: html", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
  ["data: with no comma", "data:"],
  ["file: /etc/passwd", "file:///etc/passwd"],
  ["file: UNC path", "file://server/share/x"],
  ["javascript: nested eval", "javascript:eval(atob('YWxlcnQoMSk='))"],
  ["vbscript:", "vbscript:msgbox(1)"],
  ["blob:", "blob:https://example.com/uuid-here"],
  ["about:blank", "about:blank"],
  ["chrome://settings", "chrome://settings"],
  ["intent://", "intent://scan/#Intent;scheme=zxing;end"],
  ["jar:", "jar:http://evil.example/a.jar!/b"],
  ["no scheme at all", "example.com/path"],
  ["protocol-relative", "//evil.example/path"],
  ["scheme with a space", "ht tp://example.com"],
  ["uppercase scheme", "JAVASCRIPT:alert(1)"],
  ["scheme split by a tab", "java\tscript:alert(1)"],
  ["mailto:", "mailto:a@b.com"],
];

const IP_LITERALS: readonly Case[] = [
  ["IPv6 loopback", "http://[::1]/"],
  ["IPv6 cloud metadata", "http://[fd00:ec2::254]/"],
  ["IPv6 v4-mapped metadata", "http://[::ffff:169.254.169.254]/"],
  ["IPv6 malformed [:::1]", "http://[:::1]/"],
  ["IPv6 unclosed bracket", "http://[::1/"],
  ["IPv6 zone id", "http://[fe80::1%25eth0]/"],
  ["IPv6 nine groups", "http://[1:2:3:4:5:6:7:8:9]/"],
  ["decimal IP", "http://2130706433/"],
  ["octal IP", "http://0177.0.0.1/"],
  ["mixed-radix IP", "http://0x7f.0.0.01/"],
  ["IP integer overflow", "http://999999999999999999999/"],
  ["five dotted octets", "http://1.2.3.4.5/"],
  ["negative octet", "http://-1.2.3.4/"],
];

const AUTHORITY_ABUSE: readonly Case[] = [
  ["userinfo with password", "http://user:pass@evil.example/"],
  ["empty userinfo", "http://@evil.example/"],
  ["bare port colon", "http://example.com:/"],
  ["out-of-range port", "http://example.com:999999/"],
  ["negative port", "http://example.com:-80/"],
  ["non-numeric port", "http://example.com:abc/"],
  ["newline inside userinfo", "http://us\ner@evil.example/"],
];

const PROTOTYPE_FLAVORED: readonly Case[] = [
  ["__proto__ as a host label", "http://__proto__.example.com/"],
  ["constructor/prototype in path", "http://example.com/constructor/prototype"],
  ["__proto__ in query", "http://example.com/?__proto__[x]=1"],
];

const GROUPS: ReadonlyArray<readonly [string, readonly Case[]]> = [
  ["degenerate and empty inputs", DEGENERATE],
  ["control characters and null bytes", CONTROL_CHARS],
  ["bidi overrides and invisible formatting", BIDI_AND_INVISIBLE],
  ["surrogates and malformed Unicode", MALFORMED_UNICODE],
  ["punycode abuse", PUNYCODE],
  ["length and resource exhaustion", EXHAUSTION],
  ["decode bombs and wrapper nesting", DECODE_BOMBS],
  ["exotic and dangerous schemes", SCHEMES],
  ["IP literals", IP_LITERALS],
  ["userinfo and port abuse", AUTHORITY_ABUSE],
  ["prototype-pollution-flavored inputs", PROTOTYPE_FLAVORED],
];

const ALL_CASES: readonly Case[] = GROUPS.flatMap(([, cases]) => cases);

/**
 * The sweep's contract checks, applied to one result. Kept as a single helper
 * so a new case added to any group inherits every invariant automatically.
 */
function assertResultContract(input: string, result: ReturnType<typeof inspect>): void {
  expect(["ok", "invalid"]).toContain(result.status);
  expect(result.schemaVersion).toBe(SCHEMA_VERSION);
  expect(typeof result.input).toBe("string");
  expect(Array.isArray(result.reasons)).toBe(true);
  expect(Array.isArray(result.confusables)).toBe(true);

  if (result.status === "ok") {
    // A scored result must be a real number in the unit interval. `NaN >= 0` is
    // false, so a NaN score would fail the range check on its own; asserting it
    // separately names the failure instead of leaving a bare range error.
    expect(Number.isNaN(result.score)).toBe(false);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(1);
    expect(result.severity).not.toBeNull();
  } else {
    // The A3 invalid contract (LINK-ctkfbdkf): null score AND null severity, so
    // a fail-closed caller cannot mistake "not checked" for "checked and clean".
    expect(result.score).toBeNull();
    expect(result.severity).toBeNull();
    expect(result.parsed).toBeNull();
  }

  // Both the CLI's --json path and the MCP channel serialize the result.
  expect(() => JSON.stringify(result)).not.toThrow();

  // The echo must not silently diverge from what was passed in; a truncating or
  // sanitizing echo would misrepresent the input in a report.
  expect(result.input).toBe(input);
}

describe.each(GROUPS)("adversarial strings — %s (LINK-sgcovhzr)", (_group, cases) => {
  it.each(cases)("never throws: %s", (_label, input) => {
    expect(() => inspect(input)).not.toThrow();
  });

  it.each(cases)("returns a schema-valid result: %s", (_label, input) => {
    assertResultContract(input, inspect(input));
  });

  it.each(cases)("round-trips through JSON: %s", (_label, input) => {
    const result = inspect(input);
    const round = JSON.parse(JSON.stringify(result));
    expect(round.status).toBe(result.status);
    expect(round.score ?? null).toBe(result.score);
  });
});

describe("the corpus itself (LINK-sgcovhzr)", () => {
  it("covers every hostile-input family the sweep found", () => {
    // A guard against a group being silently emptied or dropped from GROUPS
    // during a refactor — the suite would still be green with zero coverage.
    expect(GROUPS).toHaveLength(11);
    for (const [name, cases] of GROUPS) {
      expect(cases.length, `group "${name}" is empty`).toBeGreaterThan(0);
    }
  });

  it("has no duplicate labels", () => {
    const labels = ALL_CASES.map(([label]) => label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("is large enough to be worth running", () => {
    // The original sweep was 107 cases, 9 of which were non-strings and now live
    // in non-string-input.test.ts. The string half is the remainder.
    expect(ALL_CASES.length).toBeGreaterThanOrEqual(98);
  });
});

/**
 * Performance budget — a ReDoS guard, not a benchmark.
 *
 * These inputs are up to 5,500x the length of a baseline URL. Measured on the
 * sweep, time grew ~140x, not superlinearly: the worst case ran ~4.4 ms. The
 * ceilings below are deliberately far above that. They are not tuned to the
 * measurements and must not be — a catastrophic-backtracking regression takes
 * a pathological input from milliseconds to seconds, and that is the only
 * thing this suite is trying to catch. Unit tests would miss it entirely.
 */
describe("adversarial input stays linear (LINK-sgcovhzr)", () => {
  /** Generous ceiling for one pathological input. NFR-PERF-1's bound is 5 ms. */
  const CEILING_MS = 250;

  /**
   * Best-of-N, matching perf.test.ts: a single sample is dominated by GC and
   * scheduler noise, which made an earlier absolute timing assertion flaky.
   * The floor across repetitions reflects the true compute cost.
   */
  function fastestMs(input: string, reps = 3): number {
    let best = Number.POSITIVE_INFINITY;
    for (let n = 0; n < reps; n++) {
      const start = performance.now();
      inspect(input);
      best = Math.min(best, performance.now() - start);
    }
    return best;
  }

  const PATHOLOGICAL: readonly Case[] = [
    ...EXHAUSTION,
    ...DECODE_BOMBS,
    ["punycode overflow", `http://xn--${"9".repeat(200)}.com`],
  ];

  it.each(PATHOLOGICAL)(`stays under ${CEILING_MS} ms: %s`, (_label, input) => {
    inspect(input); // warm up JIT and lazy data init
    expect(fastestMs(input)).toBeLessThan(CEILING_MS);
  });

  it("processes the whole hostile corpus in one pass without blowing up", () => {
    for (const [, input] of ALL_CASES) inspect(input);

    const start = performance.now();
    for (const [, input] of ALL_CASES) inspect(input);
    const elapsed = performance.now() - start;

    console.log(
      `[perf] adversarial corpus = ${elapsed.toFixed(1)} ms over ${ALL_CASES.length} inputs`,
    );
    expect(elapsed).toBeLessThan(CEILING_MS * 4);
  });
});
