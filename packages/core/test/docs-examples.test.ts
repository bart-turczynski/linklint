import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";

// Docs-as-claims validation: extract every verifiable claim FROM the prose and
// check it against the code, never the reverse. Generating docs from code would
// have hidden LINK-hsweunks entirely — that prose was internally coherent and
// simply wrong about what the option did (LINK-zyvfmjfe).
//
// Every extractor below is paired with a COUNT FLOOR. A regex that silently
// stops matching is the one failure mode these guards cannot self-report: the
// suite would stay green while covering nothing. The floors are set just under
// the current yield, so deleting examples wholesale trips them while adding
// examples never does.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (...p: string[]) => readFileSync(join(REPO_ROOT, ...p), "utf8");

const reasonCodesDoc = read("docs", "reason-codes.md");
const readme = read("README.md");
const architectureDoc = read("docs", "architecture.md");
const scoringDoc = read("docs", "scoring.md");
const coreReadme = read("packages", "core", "README.md");
const optionsSource = read("packages", "core", "src", "schema", "options.ts");

// ---------------------------------------------------------------------------
// 1. Reason-code examples emit the code they illustrate.
// ---------------------------------------------------------------------------

// Only fully-literal URLs are assertable. Examples written as prose recipes
// (host_length_unresolvable's "`https://` + 64 × `a` + `.com`") or as bare
// character descriptions are skipped by construction — the count floor below is
// what stops that skip set from quietly growing.
const LITERAL_URL_RE = /`([a-z][a-z0-9+.-]*:\/\/[^`\s]+|javascript:[^`]+)`/g;

interface CodeExample {
  readonly code: string;
  readonly url: string;
  readonly agentGated: boolean;
}

function reasonCodeExamples(): CodeExample[] {
  const out: CodeExample[] = [];
  // Split on the h3 headers that open each code's section; odd indices are the
  // captured code, even indices the body that follows it.
  const parts = reasonCodesDoc.split(/^### `([a-z_]+)`/gm);
  for (let i = 1; i < parts.length; i += 2) {
    const code = parts[i] as string;
    const body = parts[i + 1] as string;
    // The Example bullet runs until the next bullet or the next section.
    const example = body.match(/^- \*\*Example:\*\*([\s\S]*?)(?=\n- \*\*|\n### |\n## |$)/m);
    if (!example) continue;
    const agentGated = /agent-gated/i.test(body);
    for (const m of (example[1] as string).matchAll(LITERAL_URL_RE)) {
      out.push({ code, url: m[1] as string, agentGated });
    }
  }
  return out;
}

describe("docs/reason-codes.md examples emit the code they illustrate", () => {
  const examples = reasonCodeExamples();

  it("extracts a literal URL example for most of the registry", () => {
    // 46 today across 34 sections. A drop means the extractor went blind or the
    // examples were rewritten into unassertable prose; both need a human.
    expect(examples.length).toBeGreaterThanOrEqual(40);
    const covered = new Set(examples.map((e) => e.code));
    expect(covered.size).toBeGreaterThanOrEqual(30);
    // No orphan sections: every code carrying an example is a real registry key.
    for (const code of covered) expect(REASON_CODES).toHaveProperty(code);
  });

  it.each(examples.map((e) => [e.code, e.url, e] as const))(
    "%s example %s emits %s",
    (code, _url, example) => {
      const result = inspect(example.url, example.agentGated ? { agentMode: true } : {});
      const emitted = (result.reasons ?? []).map((r) => r.code);
      expect(emitted).toContain(code);
    },
  );
});

// ---------------------------------------------------------------------------
// 2. Documented verdicts match inspect().
// ---------------------------------------------------------------------------

// This is LINK-jabpgeto's class exactly: the README Quick start claimed
// 0.7/high where the real answer was 1.0/critical. The claim lived in a comment
// next to the call that produces it, which is precisely where a reader trusts
// it most.
interface VerdictClaim {
  readonly source: string;
  readonly url: string;
  readonly score?: number | undefined;
  readonly severity?: string | undefined;
  readonly reasons?: string[] | undefined;
}

// inspect('<url>'[, {...}]);  followed by one or more `// ...` comment lines
// that state some combination of severity, score and reasons.
const VERDICT_RE =
  /inspect\(\s*(['"])((?:(?!\1).)+)\1\s*\)\s*;((?:\s*\/\/[^\n]*\n?)+)/g;

function verdictClaims(source: string, markdown: string): VerdictClaim[] {
  const out: VerdictClaim[] = [];
  for (const m of markdown.matchAll(VERDICT_RE)) {
    const url = m[2] as string;
    const comment = m[3] as string;
    const score = comment.match(/score:?\s*`?(\d+(?:\.\d+)?)/);
    const severity = comment.match(/severity:\s*'([a-z]+)'/);
    const reasons = comment.match(/reasons:\s*\[([^\]]*)\]/);
    if (!score && !severity && !reasons) continue;
    out.push({
      source,
      url,
      score: score ? Number(score[1]) : undefined,
      severity: severity ? (severity[1] as string) : undefined,
      // A trailing '...' means the list is abridged; treat the named codes as a
      // subset rather than the whole set.
      reasons: reasons
        ? [...(reasons[1] as string).matchAll(/'([a-z_]+)'/g)].map((r) => r[1] as string)
        : undefined,
    });
  }
  return out;
}

describe("documented example verdicts match inspect()", () => {
  const claims = [
    ...verdictClaims("README.md", readme),
    ...verdictClaims("packages/core/README.md", coreReadme),
    ...verdictClaims("docs/reason-codes.md", reasonCodesDoc),
    ...verdictClaims("docs/scoring.md", scoringDoc),
    ...verdictClaims("docs/architecture.md", architectureDoc),
  ];

  it("finds the documented inspect() examples", () => {
    expect(claims.length).toBeGreaterThanOrEqual(6);
  });

  it.each(claims.map((c) => [`${c.source}: ${c.url}`, c] as const))("%s", (_label, claim) => {
    const result = inspect(claim.url);
    if (claim.score !== undefined) expect(result.score).toBe(claim.score);
    if (claim.severity !== undefined) expect(result.severity).toBe(claim.severity);
    if (claim.reasons !== undefined) {
      const emitted = (result.reasons ?? []).map((r) => r.code);
      for (const code of claim.reasons) expect(emitted).toContain(code);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Prose "these hosts all score N/severity" claims.
// ---------------------------------------------------------------------------

// These carry the evidence behind standing decisions — the brand-fold declines
// in architecture.md §6 rest on named hosts scoring 0.00/info. If the scoring
// ever moves, the decision's stated basis is gone and the prose must be re-read,
// not silently left behind.
const ALL_SCORE_RE =
  /((?:`[a-z0-9.‐-―-]+`(?:,| and|,? and)? ?)+)\s*all score `(\d+\.\d+)`\/`?([a-z]+)`?/g;

describe("prose 'all score' claims hold", () => {
  const claims: { host: string; score: number; severity: string }[] = [];
  for (const [source, doc] of [
    ["docs/architecture.md", architectureDoc],
    ["README.md", readme],
  ] as const) {
    void source;
    for (const m of doc.matchAll(ALL_SCORE_RE)) {
      const hosts = [...(m[1] as string).matchAll(/`([^`]+)`/g)].map((h) => h[1] as string);
      for (const host of hosts) {
        claims.push({ host, score: Number(m[2]), severity: m[3] as string });
      }
    }
  }

  it("finds the prose score claims", () => {
    expect(claims.length).toBeGreaterThanOrEqual(3);
  });

  it.each(claims.map((c) => [c.host, c] as const))("%s scores as documented", (_host, claim) => {
    const result = inspect(claim.host);
    expect(result.score).toBe(claim.score);
    expect(result.severity).toBe(claim.severity);
  });
});

// ---------------------------------------------------------------------------
// 4. Option surface — every InspectOptions key documented, no phantom keys.
// ---------------------------------------------------------------------------

function inspectOptionKeys(): string[] {
  const start = optionsSource.indexOf("export interface InspectOptions {");
  expect(start).toBeGreaterThan(-1);
  const body = optionsSource.slice(start, optionsSource.indexOf("\n}", start));
  return [...body.matchAll(/^ {2}([a-zA-Z][a-zA-Z0-9]*)\?:/gm)].map((m) => m[1] as string);
}

describe("the InspectOptions surface is documented", () => {
  const keys = inspectOptionKeys();
  // Options are documented across the README option table, the IDN guidance and
  // the architecture/scoring sections on the escape hatch. Any of those counts.
  const corpus = [readme, coreReadme, architectureDoc, scoringDoc].join("\n");

  it("parses the interface", () => {
    expect(keys.length).toBeGreaterThanOrEqual(13);
    expect(keys).toContain("agentMode");
    expect(keys).toContain("suppressReasons");
  });

  it.each(keys)("option %s is documented", (key) => {
    expect(corpus).toContain(`\`${key}\``);
  });

  it("the README option table names only real options", () => {
    const start = readme.indexOf("Available options (all optional");
    expect(start).toBeGreaterThan(-1);
    const table = readme.slice(start, readme.indexOf("\n## ", start));
    const named = [...table.matchAll(/`([a-zA-Z][a-zA-Z0-9]*)`/g)].map((m) => m[1] as string);
    // Filter to identifiers that look like option keys (camelCase), so prose
    // values such as `https` in the same cell are not mistaken for options.
    const optionish = named.filter((n) => /[A-Z]/.test(n));
    expect(optionish.length).toBeGreaterThanOrEqual(6);
    for (const key of optionish) expect(keys).toContain(key);
  });
});
