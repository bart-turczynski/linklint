import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CLOUD_METADATA_ENDPOINTS } from "../src/data/cloud-metadata.js";
import { CHECKS } from "../src/detectors/checks.js";
import { DETECTORS } from "../src/detectors/registry.js";
import { STRUCTURAL_SCANS } from "../src/detectors/structural.js";
import { REASON_CODES, type ReasonCode } from "../src/schema/reason-codes.js";

// Light validation (NOT generation) that catches the common drift between code
// and docs. Paths are resolved relative to THIS test module (not process.cwd())
// so the test runs the same regardless of the working directory.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const reasonCodesDoc = readFileSync(join(REPO_ROOT, "docs", "reason-codes.md"), "utf8");
const readme = readFileSync(join(REPO_ROOT, "README.md"), "utf8");
const architectureDoc = readFileSync(join(REPO_ROOT, "docs", "architecture.md"), "utf8");

// Each code is documented with an h3 header of the form: ### `code_name` — …
// Parse the backtick-wrapped code name out of every such header.
const DOC_CODE_RE = /^### `([a-z_]+)`/gm;
function documentedCodes(markdown: string): string[] {
  return [...markdown.matchAll(DOC_CODE_RE)].map((m) => m[1] as string);
}

describe("docs/reason-codes.md stays in sync with the REASON_CODES registry", () => {
  const registryCodes = Object.keys(REASON_CODES) as ReasonCode[];
  const docCodes = documentedCodes(reasonCodesDoc);
  const docCodeSet = new Set(docCodes);
  const registryCodeSet = new Set<string>(registryCodes);

  // 1. COMPLETENESS — every registry code is documented.
  it.each(registryCodes)("registry code %s is documented", (code) => {
    expect(docCodeSet.has(code)).toBe(true);
  });

  // 2. NO ORPHANS — every documented code is a real registry key (catches
  //    stale/renamed doc entries).
  it.each(docCodes)("documented code %s is a real REASON_CODES key", (code) => {
    expect(registryCodeSet.has(code)).toBe(true);
  });

  // 3. POLICY COVERAGE — every policy-layer code is documented under the policy
  //    section heading (i.e. its header appears after the section heading).
  it("every policy-layer code is documented under the policy section", () => {
    const policyHeadingIndex = reasonCodesDoc.search(/^## Policy codes\b/m);
    expect(policyHeadingIndex).toBeGreaterThan(-1);
    const policySection = reasonCodesDoc.slice(policyHeadingIndex);
    const policyDocCodes = new Set(documentedCodes(policySection));

    const policyCodes = registryCodes.filter((code) => REASON_CODES[code].layer === "policy");
    expect(policyCodes.length).toBeGreaterThan(0);
    for (const code of policyCodes) {
      expect(policyDocCodes.has(code)).toBe(true);
    }
  });

  // SKIP: "every detector-emitted code is registered" — emitted codes are
  // type-constrained to the ReasonCode union, so tsc enforces it at compile time.

  // 4. CLOUD-METADATA TABLE — the doc reproduces the curated endpoint table as
  //    markdown, and a reader treats that list as the answer to "is my provider
  //    covered?". Nothing but this check couples the two, so without it a new
  //    row lands in code while the doc keeps quietly claiming the old set — the
  //    same stale-documentation failure the README detector count hit.
  it("the endpoint table reproduces CLOUD_METADATA_ENDPOINTS exactly", () => {
    const section = reasonCodesDoc.slice(reasonCodesDoc.search(/^### `ip_cloud_metadata`/m));
    expect(section.length).toBeGreaterThan(0);

    // Rows look like: | `169.254.169.254/32` | AWS / Azure / … |
    // The address cell may carry a /32 suffix for readability; strip it.
    const rows = [...section.matchAll(/^\s*\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|\s*$/gm)].map(
      (m) => ({ address: (m[1] as string).replace(/\/32$/, ""), provider: m[2] as string }),
    );

    expect(rows.map((r) => r.address)).toEqual(CLOUD_METADATA_ENDPOINTS.map((e) => e.address));
    // Providers are prose in the doc (the shared row adds "(shared)"), so the
    // code's attribution must be a prefix of the documented one, not equal.
    for (const [i, row] of rows.entries()) {
      expect(row.provider.startsWith(CLOUD_METADATA_ENDPOINTS[i]!.provider)).toBe(true);
    }
  });
});

describe("README detector count matches the computed total", () => {
  // 4. DETECTOR COUNT — the true count is the lexical detector registry plus the
  //    structural scans. README hardcodes this number in two public sections;
  //    assert the targeted lines, not a loose substring.
  it("CHECKS, DETECTORS, STRUCTURAL_SCANS, and README all state the current shape", () => {
    const total = CHECKS.length;
    const structural = CHECKS.filter((c) => c.phase === "structural").length;
    const parsed = CHECKS.filter((c) => c.phase === "parsed").length;
    const agentGated = CHECKS.filter((c) => c.agentGated === true).length;

    expect(total).toBe(36);
    expect(structural).toBe(4);
    expect(parsed).toBe(32);
    expect(agentGated).toBe(5);
    expect(DETECTORS.length).toBe(parsed);
    expect(STRUCTURAL_SCANS.length).toBe(structural);

    const protectionSection = readme.match(
      /## What linklint protects against[\s\S]*?### 1\. Authority spoofing/m,
    )?.[0];
    expect(protectionSection).toContain(`linklint runs **${total} offline detectors**`);
    expect(protectionSection).toContain(`${structural} structural`);
    expect(protectionSection).toContain(`${parsed} parsed-context detectors`);
    expect(protectionSection).toContain(`including ${agentGated} agent-mode detectors`);
    expect(protectionSection).toContain("cloud-metadata SSRF) that are opt-in via `agentMode`");

    const roadmapLine = readme.match(
      /\*\*v1 — implemented\.\*\* The lexical layer is complete: (\d+) offline, deterministic detectors,/m,
    );
    expect(roadmapLine?.[1]).toBe(String(total));

    // The intro and the repository-layout table restate the same count. Neither
    // was covered here, and both drifted: LINK-blgvypxk took the total 37 -> 35
    // by dropping brand_in_path and brand_combosquat, detectors added since
    // brought it back to 37, and these two prose sites were never updated
    // (LINK-zlgtnpff). Pin them to their surrounding wording so a bare number
    // elsewhere in the file cannot satisfy the assertion.
    expect(readme).toContain(`turns that intuition into ${total} deterministic`);
    expect(readme).toContain(`\`inspect()\`, ${total} detectors, scoring, policy, schema`);

    // And no stale count may survive anywhere in the README: 35 is the exact
    // value that drifted, so assert it cannot reappear in either phrasing.
    expect(readme).not.toMatch(new RegExp(`\\b${total - 2} (deterministic|detectors|offline)\\b`));
  });

  // 5. ARCHITECTURE DOC COUNT — architecture.md restates the same shape in four
  //    places. It was NOT covered here before, and drifted silently: three sites
  //    said 37 while two still said 35/31. Assert every occurrence so the next
  //    check added has to update all of them.
  it("docs/architecture.md states the current shape everywhere it appears", () => {
    const total = CHECKS.length;
    const structural = CHECKS.filter((c) => c.phase === "structural").length;
    const parsed = CHECKS.filter((c) => c.phase === "parsed").length;
    const agentGated = CHECKS.filter((c) => c.agentGated === true).length;

    // The four prose/table sites, each pinned to its surrounding wording so a
    // bare number elsewhere in the doc cannot satisfy the assertion.
    expect(architectureDoc).toContain(`inspect(), ${total} checks`);
    expect(architectureDoc).toContain(
      `run ${total} independent lexical checks: ${structural} structural scans ahead of ` +
        `parsing, then ${parsed} parsed-context detectors`,
    );
    expect(architectureDoc).toContain(
      `contains ${total} lexical checks: ${structural} structural scans and ${parsed} ` +
        "parsed-context detectors",
    );
    expect(architectureDoc).toContain(`The ${total} checks group into seven families`);
    expect(architectureDoc).toContain(
      `${total} checks: ${structural} structural, ${parsed} parsed (${agentGated} of them agent-gated)`,
    );

    // No stale count may survive anywhere in the doc: the previous total and
    // parsed count are the exact strings that drifted last time.
    expect(architectureDoc).not.toMatch(new RegExp(`\\b${total - 2} lexical checks\\b`));
    expect(architectureDoc).not.toMatch(new RegExp(`\\b${parsed - 2} parsed-context detectors\\b`));
  });
});

describe("docs/architecture.md detector families cover every check", () => {
  // The families table claims to group "the 35 checks", and every cell is a
  // CHECK ID (not a reason code — one check may emit several). It had drifted to
  // 32 of 37: ip_classification, ambiguous_numeric_host, homograph_latin_skeleton,
  // locale_case_collapse, and idn_host were all missing. Pin it to the registry.
  it("every check id appears in the families table", () => {
    const tableStart = architectureDoc.indexOf("The 36 checks group into seven families");
    expect(tableStart).toBeGreaterThan(-1);
    const table = architectureDoc.slice(tableStart, architectureDoc.indexOf("## 6."));

    const missing = CHECKS.map((c) => c.id).filter((id) => !table.includes(`\`${id}\``));
    expect(missing).toEqual([]);
  });
});

describe("the scope-of-claim boundary is stated in one canonical place", () => {
  // The boundary (claim (a) structural, NOT claim (b) semantic; the watchlist
  // may NAME an anomaly but never CREATE a finding) now appears in three files:
  // docs/architecture.md §1.1 (canonical), README.md, and SECURITY.md. Three
  // copies drift. These assertions are deliberately anchored on short, stable
  // artifacts — a heading, a code expression, a term of art, and a link
  // fragment — rather than on prose, so ordinary rewording does not break them.
  const readmeSectionHeading = "## What linklint does not do";

  it("architecture.md carries the canonical section, the claim, and the rule", () => {
    expect(architectureDoc).toContain("### 1.1 Scope of claim");
    expect(architectureDoc).toContain("normalize(input) !== input");
    expect(architectureDoc.toLowerCase()).toContain("never create");
  });

  it("the README boundary section states the rule and the rejected claim", () => {
    const start = readme.indexOf(readmeSectionHeading);
    expect(start).toBeGreaterThan(-1);
    const section = readme.slice(start, readme.indexOf("\n## ", start + 1)).toLowerCase();

    // The rule itself — absent from the README before LINK-odhpryrh.
    expect(section).toContain("never create a finding");
    // The worked pair that shows where the line falls.
    expect(section).toContain("paypa1.com");
    expect(section).toContain("paypal-login.com");
  });

  it("SECURITY.md defers to the boundary rather than restating it", () => {
    const security = readFileSync(join(REPO_ROOT, "SECURITY.md"), "utf8");
    expect(security).toContain("#what-linklint-does-not-do");
    expect(security).toContain("docs/architecture.md");
  });

  // §1.1 named only form 1 (`normalize(input) !== input`) while the registry had
  // shipped forms 2 and 3 for releases — which is how LINK-ygglwkuy talked itself
  // into a DNS length check at weight 0.5 before the corpus caught it
  // (LINK-tukbqyjg). Pin all three forms and, more importantly, pin the CODES
  // §1.1 cites as evidence: if one is deleted or reweighted, the canonical
  // section is making a claim the registry no longer backs.
  it("§1.1 names all three forms of claim (a)", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));

    expect(section).toContain("normalize(input) !== input"); // form 1
    expect(section).toContain("read_A(input) !== read_B(input)"); // form 2
    expect(section.toLowerCase()).toContain("false self-description"); // form 3

    // The exclusion that form 2 and 3 make necessary: malformed-but-agreed-upon
    // is not a finding. Without this, "validity claims are in scope" reads as a
    // licence to flag anything non-conforming.
    expect(section.toLowerCase()).toContain("well-formed but unusable");
  });

  it("every reason code §1.1 cites as evidence exists at the weight it claims", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));

    // Codes §1.1 names to justify forms 2 and 3, with the weights it quotes.
    const cited: [ReasonCode, number][] = [
      ["ambiguous_authority", 0.65],
      ["ambiguous_numeric_host", 0.3],
      ["punycode_malformed", 0.2],
    ];
    for (const [code, weight] of cited) {
      expect(section).toContain(code);
      expect(REASON_CODES[code]).toBeDefined();
      expect(REASON_CODES[code].weight).toBeCloseTo(weight, 5);
    }

    // Cited without a weight, so assert existence only.
    for (const code of [
      "idna_mapping_ambiguity",
      "locale_case_ambiguity",
      "separator_lookalike",
      "invisible_char",
      "brand_homoglyph",
    ] as ReasonCode[]) {
      expect(section).toContain(code);
      expect(REASON_CODES[code]).toBeDefined();
    }
  });
});
