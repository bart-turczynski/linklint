import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CLOUD_METADATA_ENDPOINTS } from "../src/data/cloud-metadata.js";
import { CHECKS } from "../src/detectors/checks.js";
import { DETECTORS } from "../src/detectors/registry.js";
import { STRUCTURAL_SCANS } from "../src/detectors/structural.js";
import { inspect } from "../src/index.js";
import { analyzeIpv4, analyzeIpv6 } from "../src/parse/ip.js";
import { SCHEMA_VERSION } from "../src/schema/base.js";
import { REASON_CODES, type ReasonCode } from "../src/schema/reason-codes.js";
import { WEIGHTS_VERSION } from "../src/scoring/weights.js";

// Light validation (NOT generation) that catches the common drift between code
// and docs. Paths are resolved relative to THIS test module (not process.cwd())
// so the test runs the same regardless of the working directory.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const reasonCodesDoc = readFileSync(join(REPO_ROOT, "docs", "reason-codes.md"), "utf8");
const readme = readFileSync(join(REPO_ROOT, "README.md"), "utf8");
const architectureDoc = readFileSync(join(REPO_ROOT, "docs", "architecture.md"), "utf8");
const scoringDoc = readFileSync(join(REPO_ROOT, "docs", "scoring.md"), "utf8");

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

  // 5. NO HOSTNAME ROWS IN THE ADDRESS TABLE — this assertion outlived the
  //    reason it was written for and is kept on a narrower one (LINK-hvawpgos).
  //    It used to enforce a claim that hostnames are unrecognizable offline
  //    because "resolving one is a network call"; that claim was overturned and
  //    the names now live in CLOUD_METADATA_HOSTNAMES, matched by string
  //    equality with no resolver in sight. What survives is mechanical:
  //    CLOUD_METADATA_ENDPOINTS is indexed through the IPv4/IPv6 parser, so a
  //    hostname put in THIS table parses as neither, matches nothing, and fails
  //    silently — the failure shape LINK-ltyjctpf exists to make loud. The
  //    hostname table has its own integrity checks in
  //    test/cloud-metadata-hostname.test.ts.
  it("every endpoint is an IP literal — a hostname row here would match nothing", () => {
    expect(CLOUD_METADATA_ENDPOINTS.length).toBeGreaterThan(0);
    for (const endpoint of CLOUD_METADATA_ENDPOINTS) {
      const parsed = analyzeIpv4(endpoint.address) ?? analyzeIpv6(endpoint.address);
      expect(parsed, `${endpoint.address} (${endpoint.provider}) is not an IP literal`).not.toBe(
        null,
      );
    }
  });
});

describe("docs/scoring.md weights tables stay in sync with the registry", () => {
  // The weights table is the surface a user consults to answer "why did this
  // score 0.60?", and it had drifted to 33 of 56 entries — with brand_homoglyph,
  // the code behind the most-asked-about verdict, missing entirely
  // (LINK-hfqhcuov). Nothing coupled the two, so every weights bump since had
  // silently widened the gap. These assertions are the coupling.
  //
  // The doc splits the registry in two: scoring codes (weight > 0) carry a
  // Weight column, zero-weight codes carry a Role column instead. Parse each
  // table from its own section so a code cannot satisfy the check by appearing
  // in the wrong one.
  const registryCodes = Object.keys(REASON_CODES) as ReasonCode[];
  const scoringCodes = registryCodes.filter((code) => REASON_CODES[code].weight > 0);
  const zeroWeightCodes = registryCodes.filter((code) => REASON_CODES[code].weight === 0);

  function section(heading: string): string {
    const start = scoringDoc.indexOf(heading);
    expect(start, `missing section: ${heading}`).toBeGreaterThan(-1);
    const next = scoringDoc.indexOf("\n### ", start + 1);
    return scoringDoc.slice(start, next === -1 ? undefined : next);
  }

  // Rows: | `code` | 0.50   | lexical    |
  const scoringSection = section("### Scoring codes");
  const scoringRows = new Map<string, number>(
    [...scoringSection.matchAll(/^\|\s*`([a-z_]+)`\s*\|\s*(\d\.\d\d)\s*\|/gm)].map((m) => [
      m[1] as string,
      Number(m[2]),
    ]),
  );

  // Rows: | `code` | lexical    | annotation     |
  const zeroSection = section("### Zero-weight codes");
  const zeroRows = new Map<string, string>(
    [...zeroSection.matchAll(/^\|\s*`([a-z_]+)`\s*\|\s*([a-z]+)\s*\|\s*([a-z ]+?)\s*\|/gm)].map(
      (m) => [m[1] as string, m[3] as string],
    ),
  );

  // 1. COMPLETENESS — every scoring code is in the scoring table.
  it.each(scoringCodes)("scoring code %s is documented", (code) => {
    expect(scoringRows.has(code)).toBe(true);
  });

  // 2. VALUE — the documented weight is the shipped weight, not merely present.
  //    Presence alone would let a reweight ship against a stale number, which is
  //    worse than an omission: the reader gets a confident wrong answer.
  it.each(scoringCodes)("documented weight for %s equals the registry weight", (code) => {
    expect(scoringRows.get(code)).toBeCloseTo(REASON_CODES[code].weight, 5);
  });

  // 3. COMPLETENESS — every zero-weight code is in the zero-weight table.
  it.each(zeroWeightCodes)("zero-weight code %s is documented", (code) => {
    expect(zeroRows.has(code)).toBe(true);
  });

  // 4. ROLE — policy-layer codes must be labelled as policy verdicts. A policy
  //    code is caller configuration, not a detector finding; mislabelling one as
  //    an annotation would misrepresent where the decision came from.
  it.each(zeroWeightCodes.filter((code) => REASON_CODES[code].layer === "policy"))(
    "policy code %s is labelled a policy verdict",
    (code) => {
      expect(zeroRows.get(code)).toBe("policy verdict");
    },
  );

  // 5. NO ORPHANS, BOTH TABLES — a deleted or renamed code must not survive as a
  //    row. LINK-cphogucn deleted three brand codes at once; without this, their
  //    rows would still be documenting weights that no longer exist.
  it.each([...scoringRows.keys()])("scoring-table row %s is a real scoring code", (code) => {
    expect(REASON_CODES[code as ReasonCode]).toBeDefined();
    expect(REASON_CODES[code as ReasonCode].weight).toBeGreaterThan(0);
  });

  it.each([...zeroRows.keys()])("zero-weight-table row %s is a real zero-weight code", (code) => {
    expect(REASON_CODES[code as ReasonCode]).toBeDefined();
    expect(REASON_CODES[code as ReasonCode].weight).toBe(0);
  });

  // 6. STATED COUNTS — the prose around each table quotes a total. Those numbers
  //    are what a reader trusts without counting rows, so pin them too.
  it("the prose totals match the registry", () => {
    expect(scoringSection).toContain(`The **${scoringCodes.length}** codes that carry`);
    expect(zeroSection).toContain(`The remaining **${zeroWeightCodes.length}** codes`);
    expect(scoringRows.size).toBe(scoringCodes.length);
    expect(zeroRows.size).toBe(zeroWeightCodes.length);
  });

  // 7. VERSION PIN — the doc's header quotes the current weights version. A
  //    reweight bumps WEIGHTS_VERSION, so an unguarded restatement here is
  //    guaranteed to go stale exactly when the table content changes.
  it("the stated weights version is WEIGHTS_VERSION", () => {
    expect(scoringDoc).toContain(`Current weights version:\n> **${WEIGHTS_VERSION}**`);
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

    expect(total).toBe(39);
    expect(structural).toBe(4);
    expect(parsed).toBe(35);
    expect(agentGated).toBe(4);
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
    expect(architectureDoc).toContain(`The ${total} checks group into six families`);
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
  // The families table claims to group "the 37 checks", and every cell is a
  // CHECK ID (not a reason code — one check may emit several). It had drifted to
  // 32 of 37: ip_classification, ambiguous_numeric_host, homograph_latin_skeleton,
  // locale_case_collapse, and idn_host were all missing. Pin it to the registry.
  it("every check id appears in the families table", () => {
    const tableStart = architectureDoc.indexOf("The 39 checks group into six families");
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

  // LINK-vwjtdtzn. The fail-closed doctrine covered `invalid` only; the clean
  // case is the one a consumer actually reads as an endorsement. §1.1 already
  // cited Szurdi and Tian to justify NOT emitting claim-(b) verdicts — the same
  // two numbers, read the other way, are why a 0.00 says nothing about safety.
  it("§1.1 states that a clean result is not a safety claim", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));

    expect(section).toContain("not a safety claim");
    // The evidence must travel with the claim, or it reads as an opinion.
    expect(section).toContain("Szurdi");
    expect(section).toContain("Tian");
  });

  // LINK-pralkaeo. The combosquatting hole was recorded only as the RATIONALE
  // for deleting brand_combosquat (§6.1.2, LINK-blgvypxk) — an unlisted absence
  // from the canonical boundary, which is how a settled non-goal gets re-filed
  // every six months. §1.1's own worked example is a combosquat, so the class
  // has to be named where that example lives.
  it("§1.1 records combosquatting as a stated non-goal with its base rate", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));

    expect(section).toContain("combosquat");
    expect(section).toContain("Kintis");
    // The measurement is the whole argument: prevalent AND largely benign is
    // what makes the class a non-goal rather than a backlog item.
    expect(section.toLowerCase()).toContain("largely benign");
    // It must land as a boundary, not as a gap awaiting a fix.
    expect(section).toContain("stated non-goal and not a gap");
  });

  // LINK-uorcqwnm. Every worked case in §1.1 was host-side — host length,
  // combosquatting, brands, `xn--` — so the path had the principle stated at it
  // and no application of it anywhere in docs/, README.md or SECURITY.md, while
  // §1.1's own list of what it does NOT settle named only RFC 6761. A proposer
  // holding `..;/` could therefore not discover that the class was already
  // decided; that is the silent absence this repo keeps rediscovering. The
  // RESCOPE settled it, and an unpinned settlement is a deletable one.
  describe("§1.1 settles the path layer on standards enumeration", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));
    const blockStart = section.indexOf("**The path layer, settled");
    // LINK-mgnbgicq closed the last open boundary, so the heading these blocks
    // used to end at ("**One boundary this section does NOT yet settle**") is
    // gone. They now end at the settlement that replaced it — the slice bounds
    // are unchanged in intent, and the anti-vacuity assertions below still fail
    // if the delimiter stops matching.
    const openList = section.indexOf("**Reserved special-use names, settled");
    const block = section.slice(blockStart, openList);

    // EVERY match below runs against whitespace-flattened text. The boundary
    // question and the out-of-scope sentences hard-wrap mid-claim, and a raw
    // substring match against wrapped prose matches NOTHING while still passing
    // as a `not.toContain` — or, worse, passes vacuously on an empty slice. The
    // boundary question is a markdown blockquote, so strip the `> ` prefixes
    // first: they survive whitespace-flattening and land mid-sentence on a
    // reflow, exactly as the CWE-20 assertion above already accounts for.
    const flat = block.replace(/^\s*>\s?/gm, "").replace(/\s+/g, " ");

    it("the block exists and the slice is not empty (anti-vacuity)", () => {
      expect(blockStart).toBeGreaterThan(-1);
      expect(openList).toBeGreaterThan(blockStart);
      expect(flat.length).toBeGreaterThan(1000);
      expect(flat).toContain("LINK-uorcqwnm");
    });

    it("states the boundary as standards enumeration, not consumer agnosticism", () => {
      // The one sentence a future path proposal has to answer.
      expect(flat).toContain(
        "Is the divergence enumerated by the URL standards themselves, or introduced by " +
          "application code **below** the URL layer?",
      );

      // The rejected phrasing must be recorded AS rejected, with the shipped
      // counterexample that kills it — otherwise it gets re-proposed, and it is
      // the phrasing that reads most natural. `%2F` in a path is flagged today
      // even though RFC 3986 §2.2 makes it non-equivalent to `/`, so a
      // consumer-agnostic line condemns shipped code.
      expect(flat).toContain("consumer-agnostic");
      expect(flat).toContain("gen-delim");
      expect(flat).toContain("RFC 3986 §2.2");
      expect(flat).toContain("encoding_obfuscation");
    });

    it("puts encoded double-dot segments IN, by the standard's own enumeration", () => {
      expect(flat).toContain("double-dot path segment");
      // The four spellings the WHATWG URL Standard names. All four pop the
      // parent in Node; that is the whole in-scope argument.
      for (const spelling of ["`..`", "`.%2e`", "`%2e.`", "`%2e%2e`"]) {
        expect(flat).toContain(spelling);
      }
      expect(flat).toContain("ASCII case-insensitive");
      // Cited as forms of claim (a), so no server assumption is smuggled in.
      expect(flat).toContain("normalize(input) !== input");
      // The in-scope half is a DETECTOR change, tracked separately. This
      // boundary does not implement it and must not read as if it had.
      expect(flat).toContain("LINK-dpahotkg");
    });

    it("puts `..;/` and bare path parameters OUT, as a stated non-goal", () => {
      expect(flat).toContain("`..;`");
      expect(flat).toContain("path parameters");
      // No standard assigns `;` a generic meaning — the traversal is created by
      // a servlet container below the URL layer, not by the string.
      expect(flat).toContain("RFC 3986 §3.3");
      expect(flat).toContain("RFC 2396");
      expect(flat).toContain("servlet container");
    });

    it("puts web cache deception OUT, under the well-formed-but-unusable rule", () => {
      expect(flat).toContain("web cache deception");
      expect(flat).toContain("/api/user/123/x.css");
      // It must land on the EXISTING exclusion rather than inventing a new one.
      expect(flat).toContain("well-formed but unusable");
    });

    it("lands both exclusions as boundaries, not as gaps awaiting a fix", () => {
      // Same phrase the combosquatting boundary uses, asserted inside THIS
      // block — the section-wide assertion above would be satisfied by the
      // combosquatting paragraph alone.
      expect(flat.match(/stated non-goal and not a gap/g)?.length).toBeGreaterThanOrEqual(2);
    });

    it("the settles-list names the path layer, and nothing is left open", () => {
      // §1.1 once listed only what it does NOT settle. A reader scanning for "is
      // the path decided?" found a principle and an open list, and concluded it
      // was open. The list must say what IS settled and name the path layer.
      // Bounded at the next paragraph, or "the path layer" could be satisfied
      // by any later mention in the section.
      const openFlat = section
        .slice(openList, section.indexOf("**The rule.**", openList))
        .replace(/\s+/g, " ");
      expect(openFlat.length).toBeGreaterThan(200);
      expect(openFlat).toContain("RFC 6761");
      // CONVERTED (LINK-mgnbgicq): this read "That list is the whole of what is
      // open" while a list of open boundaries existed. The last entry is now
      // decided, so the sentence that survives has to say so — an empty open
      // list left un-narrated is exactly how a settled question reopens.
      expect(openFlat).toContain("Nothing in this section is open");
      expect(openFlat).not.toContain("does NOT yet settle");
      expect(openFlat).toContain("the path layer");
      expect(openFlat).toContain("should therefore not be re-filed");
    });
  });

  // LINK-uyoocslu. The agent-gated family shipped with a gate, a weight and no
  // scope note: §1.1 never named it, §5 listed the family bare, and every
  // agent-gated entry in docs/reason-codes.md argued from consumer consequence
  // while its neighbours cite this section by number. A family that cites no
  // boundary has whatever boundary its next author assumes — and the assumption
  // that lands is "form 2, because a browser and an LLM behave differently",
  // which widens form 2 until it swallows the section. Pin the charter, the
  // rejected widening, the three escalation conditions, and the per-code ruling.
  describe("§1.1 settles the agent-mode layer", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));
    const blockStart = section.indexOf("**Agent mode, settled");
    // LINK-mgnbgicq closed the last open boundary, so the heading these blocks
    // used to end at ("**One boundary this section does NOT yet settle**") is
    // gone. They now end at the settlement that replaced it — the slice bounds
    // are unchanged in intent, and the anti-vacuity assertions below still fail
    // if the delimiter stops matching.
    const openList = section.indexOf("**Reserved special-use names, settled");
    const block = section.slice(blockStart, openList);

    // Same two traps the path-layer block above documents: raw substrings match
    // NOTHING once a sentence hard-wraps, and blockquote `> ` markers SURVIVE
    // whitespace-flattening and land mid-sentence. Strip the markers per line,
    // then flatten. Every assertion below runs against `flat`.
    const flat = block.replace(/^\s*>\s?/gm, "").replace(/\s+/g, " ");

    it("the block exists and the slice is not empty (anti-vacuity)", () => {
      expect(blockStart).toBeGreaterThan(-1);
      expect(openList).toBeGreaterThan(blockStart);
      expect(flat.length).toBeGreaterThan(1000);
      expect(flat).toContain("LINK-uyoocslu");
    });

    it("states the boundary question an agent-gated proposal has to answer", () => {
      expect(flat).toContain(
        "Does the finding name a property of the string, or a property of what one consumer " +
          "does with the bytes **after** every reader has agreed where they came from?",
      );
    });

    it("records the form-2 widening AS rejected, with the reason it fails", () => {
      // The widening is the natural re-derivation, so it has to be written down
      // as refused rather than merely absent. Form 2 is DESTINATION-scoped: its
      // two shipped exemplars both fork on where the string resolves.
      expect(flat).toContain("rejected");
      expect(flat).toContain("read_A(input) !== read_B(input)");
      expect(flat).toContain("ambiguous_authority");
      expect(flat).toContain("ambiguous_numeric_host");
      expect(flat).toContain("same destination");
      // And the consequence of widening it: the section stops excluding anything.
      expect(flat).toContain("dissolves the section");
    });

    it("routes a reader-consumption property to the fourth rule at weight 0", () => {
      expect(flat).toContain("normalize(input) === input");
      expect(flat).toContain("fourth rule");
      expect(flat).toContain("determinable from the string");
      expect(flat).toContain("weight 0");
    });

    it("states all three conditions a consequence-weighted escalation must meet", () => {
      expect(flat).toContain("The fact is settled with the gate off");
      expect(flat).toContain("The gate moves the weight, not the finding set");
      expect(flat).toContain("The declaration, not an inference, fixes the consequence");
      // The escalation that meets them, and the always-on code that settles the
      // fact for it — the escalation is grounded only because that one is.
      expect(flat).toContain("ssrf_cloud_metadata");
      expect(flat).toContain("ip_cloud_metadata");
    });

    it("rules on EVERY agent-gated check, and on no code that is not one", () => {
      // Derived from CHECKS, not from a literal list: the family shrank from
      // five to four when api_endpoint_impersonation was deleted (LINK-eurtxkit),
      // and a ruling table hand-maintained against a moving tree is the exact
      // defect this block exists to close.
      const gated = CHECKS.filter((c) => c.agentGated === true).map((c) => c.id);
      expect(gated.length).toBeGreaterThan(0);
      for (const id of gated) expect(flat).toContain(`| \`${id}\` |`);
      // The deleted code must not have a live ruling row.
      expect(flat).not.toContain("| `api_endpoint_impersonation` |");
    });

    it("quotes each ruled code's shipped weight from the registry", () => {
      // A ruling that misquotes the weight it is ruling on argues with nothing.
      const gated = CHECKS.filter((c) => c.agentGated === true).map((c) => c.id);
      for (const id of gated) {
        const weight = REASON_CODES[id as ReasonCode].weight.toFixed(2);
        expect(flat).toContain(`| \`${id}\` | ${weight} |`);
      }
    });

    it("marks the table as SHIPPED, and names the change that shipped it", () => {
      // LINK-brsntven. The table used to be a statement of what was owed, with
      // three of the four shipping above weight 0. It now describes the code, so
      // present tense is finally a true claim about what the code does
      // (AGENTS.md). The assertion is inverted rather than dropped: the failure
      // it guards against has flipped from "claims work that has not landed" to
      // "still reads as owed after it landed".
      expect(flat).not.toContain("Disposition column is what is owed");
      expect(flat).toContain("**shipped**");
      expect(flat).toContain("LINK-brsntven");
      expect(flat).toContain("§6.4");
    });

    it("the three re-grounded codes are quoted at 0.00, which is the drift guard biting", () => {
      // The weight-quoting assertion above reads each ruled code's weight from
      // REASON_CODES and demands the table match it. That guard is unchanged and
      // is what forced these three rows to be rewritten; assert the post-change
      // values directly so the guard's OUTPUT is pinned and not merely its
      // mechanism. A revert of any of the three weights turns both red.
      for (const id of ["prompt_injection_url", "credential_harvesting", "data_exfiltration"]) {
        expect(REASON_CODES[id as ReasonCode].weight).toBe(0);
        expect(flat).toContain(`| \`${id}\` | 0.00 |`);
      }
      // And the one grounded escalation still scores, or the charter is empty.
      expect(REASON_CODES.ssrf_cloud_metadata.weight).toBeCloseTo(1, 5);
      expect(flat).toContain("| `ssrf_cloud_metadata` | 1.00 |");
    });

    it("states the consequence: agent mode cannot out-score plain mode", () => {
      expect(flat).toContain(
        "agent mode can no longer raise a score above what plain mode gives",
      );
      expect(flat).toContain("ssrf_cloud_metadata");
    });

    it("lands credential_harvesting's inverse allowlist on the name-never-create rule", () => {
      expect(flat).toContain("inverse watchlist");
      expect(flat).toContain("complement");
      expect(flat).toContain("either polarity");
      // The precedent it has to argue with.
      expect(flat).toContain("api_endpoint_impersonation");
      expect(flat).toContain("LINK-eurtxkit");
    });

    it("records the data_exfiltration false positive as measured, not predicted", () => {
      expect(flat).toContain("https://blog.example.com/download?data=report2024");
      expect(flat).toContain("0.30");
      // And keeps the narrow marker fix separate from the doctrine.
      expect(flat).toContain("not a substitute for the ruling");
    });

    it("names the whole family inside THIS block, not somewhere else in §1.1", () => {
      // Scoped deliberately: a section-wide count would be satisfied by the
      // family table in §5 or by any earlier mention, and pass for the wrong
      // reason — the trap the path-layer block above documents.
      const gated = CHECKS.filter((c) => c.agentGated === true).map((c) => c.id);
      const named = gated.filter((id) => flat.includes(`\`${id}\``));
      expect(named.length).toBe(gated.length);
    });

    it("adds the agent-mode layer to the list of what §1.1 has settled", () => {
      // §1.1 lists what it does NOT settle; a reader scanning for "is agent mode
      // decided?" found a gate, a weight and silence. Bounded at the next
      // paragraph so a later mention cannot satisfy it.
      const openFlat = section
        .slice(openList, section.indexOf("**The rule.**", openList))
        .replace(/\s+/g, " ");
      expect(openFlat.length).toBeGreaterThan(200);
      expect(openFlat).toContain("Nothing in this section is open");
      expect(openFlat).toContain("the agent-mode layer");
    });
  });

  // LINK-mgnbgicq. §1.1 carried a heading — "One boundary this section does NOT
  // yet settle" — whose single entry was the RFC 6761 set, framed as
  // CONTEXT-DEPENDENT names. That framing was the wrong axis and had to be
  // replaced rather than merely answered: it is false of `.invalid` and `.alt`
  // (no referent anywhere) and false in the other direction of `.localhost`
  // (RFC 6761 §6.3 mandates loopback). A settlement that leaves the rejected
  // framing standing is one a re-derivation walks straight back into.
  describe("§1.1 settles the reserved special-use names", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));
    const blockStart = section.indexOf("**Reserved special-use names, settled");
    const block = section.slice(blockStart, section.indexOf("**The rule.**", blockStart));
    const flat = block.replace(/^\s*>\s?/gm, "").replace(/\s+/g, " ");

    it("the block exists and the slice is not empty (anti-vacuity)", () => {
      expect(blockStart).toBeGreaterThan(-1);
      expect(flat.length).toBeGreaterThan(1000);
      expect(flat).toContain("LINK-mgnbgicq");
    });

    it("the old open-boundary heading is GONE, not merely answered elsewhere", () => {
      expect(section).not.toContain("One boundary this section does NOT yet settle");
    });

    it("states the uniform predicate verbatim, and the DETECTOR states the same one", () => {
      // The predicate is the whole claim. Getting it wrong ships a false one, so
      // the doc and the code are pinned to the same string rather than to two
      // paraphrases that drift.
      const predicate =
        "reserved, never delegated in the global DNS root, never publicly resolvable";
      expect(flat).toContain(predicate);
      expect(inspect("https://foo.invalid/").reasons[0]?.detail).toContain(predicate);
    });

    it("records CONTEXT-DEPENDENCE as the REJECTED framing, with both counterexamples", () => {
      expect(flat).toContain("rejected");
      // False in one direction: names with no referent anywhere.
      expect(flat).toContain("`.invalid`");
      expect(flat).toContain("`.alt`");
      // False in the other: RFC 6761 §6.3 mandates loopback for `.localhost`.
      expect(flat).toContain("least context-dependent name");
    });

    it("routes the class to the FOURTH RULE at weight 0, not to the three forms", () => {
      expect(flat).toContain("none** of the three forms");
      expect(flat).toContain("fourth rule");
      expect(flat).toContain("weight 0");
      expect(REASON_CODES.special_use_name.weight).toBe(0);
      expect(REASON_CODES.special_use_name.scoring).toBe(false);
    });

    it("says WEIGHTS_VERSION does not move, and it did not", () => {
      expect(flat).toContain("`WEIGHTS_VERSION`");
      expect(flat).toContain("does not move");
      // `1.19` was the live stamp when `special_use_name` landed. The prose's
      // claim is that THIS change did not move it, which an equality against the
      // live stamp cannot express once any later change legitimately does
      // (LINK-lquravtj took it to `1.20`, a scoring code at weight 0.35). Assert
      // the direction, the same resolution semantic-tier-retirement.test.ts
      // already reached for SCHEMA_VERSION.
      expect(Number.parseFloat(WEIGHTS_VERSION)).toBeGreaterThanOrEqual(1.19);
      // And the schema DID move, because a new reason code is a closed-domain
      // change (§6.4). Both halves or the sentence is half-true.
      //
      // `1.11` is the version `special_use_name` REGISTERED under — a fact about
      // the past, so the prose keeps the literal. The equality against the LIVE
      // stamp was wrong to pair with it: it asserted that no reason code has been
      // added since, which every later code makes false (LINK-lquravtj added
      // `idna_protocol_violation` at `1.12`). Assert the ordering instead, which
      // is the half that stays true. The strong guard for "a new code moves the
      // schema" is the PINNED_REASON_CODES block below, which is the one the
      // test's own comment calls the guard that bites.
      expect(flat).toContain("schema `1.11`");
      expect(Number.parseFloat(SCHEMA_VERSION)).toBeGreaterThanOrEqual(1.11);
    });

    it("excludes the example DOMAINS, and states the reasoning that draws the line", () => {
      expect(flat).toContain("second-level");
      expect(flat).toContain("delegated");
      expect(flat).toContain("`example.com`");
      // The doc's claim, checked against the code rather than trusted.
      for (const host of ["example.com", "example.net", "example.org"]) {
        expect(inspect(`https://${host}/`).reasons.map((r) => r.code)).not.toContain(
          "special_use_name",
        );
      }
      expect(inspect("https://foo.example/").reasons.map((r) => r.code)).toContain(
        "special_use_name",
      );
    });

    it("pins the cloud-metadata collision decision, and the code implements it", () => {
      expect(flat).toContain("suppresses itself");
      expect(flat).toContain("metadata.google.internal");
      const codes = inspect("http://metadata.google.internal/").reasons.map((r) => r.code);
      expect(codes).toContain("ip_cloud_metadata");
      expect(codes).not.toContain("special_use_name");
    });

    it("carves out `.onion` label syntax as OUT of scope and still open", () => {
      // It is form 3 and therefore SCORING-eligible. A weight-0 code must not be
      // read as having decided it.
      expect(flat).toContain("`.onion`");
      expect(flat).toContain("form 3");
      expect(flat).toContain("Not decided here.");
    });

    it("says it does not decide LINK-qqwfpxvu sideways, and why both halves are needed", () => {
      expect(flat).toContain("LINK-qqwfpxvu");
      expect(flat).toContain("Nothing here scores");
      expect(flat).toContain("neither suffices alone");
    });
  });

  // LINK-sarsncoh / LINK-ftljzcjh. The declined sanitize() / cleaned-URL API.
  // This block is pinned for a reason the other §1.1 settlements do not have:
  // there is NO mechanical gate behind it. public-api-contract.test.ts pins the
  // metadata/experimental/data subpaths to exact key sets but checks root only
  // as a superset of experimental (see "linklint root — legacy advanced
  // compatibility surface" in that file: a per-key toHaveProperty loop, not a
  // key-set equality), so a new root export reddens nothing and a catalog in a
  // local const moves no SCHEMA_VERSION. The prose IS the guard, and an unpinned
  // guard is a deletable one — the same reasoning the path-layer block above
  // records. What these assertions can hold is that the record still exists and
  // still argues the CLASS; they cannot hold the judgment, and a test that
  // merely matched /sanitize/ would pass on a paragraph saying the opposite,
  // which is why every check below is anchored on the reasoning instead.
  describe("§1.1 settles the cleaned-URL output", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));
    const blockStart = section.indexOf("**Handing back a modified URL, settled");
    const blockEnd = section.indexOf("Nothing in this section is open", blockStart);
    const block = section.slice(blockStart, blockEnd);

    // Same trap the path-layer and agent-mode blocks document: the load-bearing
    // sentences below hard-wrap mid-claim, so a raw substring match against the
    // document finds NOTHING while still reading as a passing assertion. Strip
    // any leading `> ` / `*` marker per line, then flatten whitespace. Every
    // assertion below runs against `flat`. Swapping `flat` for `block` here
    // turns this describe red, which is how the flattening was shown to bite.
    const flat = block
      .replace(/^\s*(?:>|\*)\s?/gm, "")
      .replace(/\s+/g, " ");

    it("the block exists and the slice is not empty (anti-vacuity)", () => {
      expect(blockStart).toBeGreaterThan(-1);
      expect(blockEnd).toBeGreaterThan(blockStart);
      expect(flat.length).toBeGreaterThan(1000);
      expect(flat).toContain("LINK-sarsncoh");
      // The positive anchor for every absence check below: the request must be
      // named, or a rename passes the whole block vacuously.
      expect(flat).toContain("`sanitize()`");
    });

    it("declines it on the world-claim, and records the return-type reading as NOT the reason", () => {
      // This is the wording constraint the decision turned on. Recorded as a
      // product-contract objection ("a second contract", "a lossy output"), the
      // next proposal arrives with a version stamp and the record has no answer.
      expect(flat).toContain(
        "the list doing the removing asserts something linklint cannot settle from the string",
      );
      expect(flat).toContain("those query keys do not affect the resource the URL addresses");
      expect(flat).toContain("claim (b)");
      // The unregistered-namespace argument, which is what a curated filter list
      // cannot clear and `decodeEmbeddedWrapper`'s exact vendor formats can.
      expect(flat).toContain("prefix glob");
      expect(flat).toContain("not an enumeration");
      expect(flat).toContain("§6.1.5");
    });

    it("cites the code that already ruled it, so the record is not merely an opinion", () => {
      // Spans the paragraph break, so the code precedent is pinned as THIS
      // record's evidence rather than as a nearby aside that survives the
      // block being gutted. It also spans a leading `*` emphasis marker, which
      // is the half of the normalization above that whitespace-flattening
      // alone does not handle: without the marker strip this assertion fails.
      expect(flat).toContain(
        "It is claim (b), pointed at the query string. " +
          "The repo had already ruled this in code, silently.",
      );
      expect(flat).toContain("canonicalizeUrl");
      expect(flat).toContain("`@linklint/online/mirrors`");
      expect(flat).toContain("preserves path and query verbatim");
      expect(flat).toContain("decodeEmbeddedWrapper");
      expect(flat).toContain("utm_source");
      // §8's half: enforcement is the consumer's job. Cited rather than
      // duplicated, so the argument lives in exactly one place.
      expect(flat).toContain("§8");
      expect(flat).toContain("enforcement is the consumer's job");
    });

    it("forecloses the weight-0 fallback, or it gets proposed next", () => {
      expect(flat).toContain("tracking_parameters_present");
      expect(flat).toContain("weight 0");
      expect(flat).toContain("strip the world-claim");
    });

    it("declines the CLASS rather than the proposal's API shape", () => {
      expect(flat).toContain("{ status, url, removed[] }");
      expect(flat).toContain("version stamp");
      expect(flat).toContain("not settleable from the string");
      expect(flat).toContain("stated non-goal and not a gap");
    });

    it("records that the mechanical gate does not catch a future one", () => {
      expect(flat).toContain("packages/core/test/public-api-contract.test.ts");
      expect(flat).toContain("superset of `experimental`");
      expect(flat).toContain("`SCHEMA_VERSION`");
    });

    it("joins the settles-list, which is where a proposer looks for a decided class", () => {
      // Recording the block without listing it leaves the class undiscoverable
      // to anyone scanning "is this already decided?" — the exact absence
      // LINK-pralkaeo had to go back and fill for combosquatting.
      const listFlat = section
        .slice(blockEnd, section.indexOf("**The rule.**", blockEnd))
        .replace(/\s+/g, " ");
      expect(listFlat.length).toBeGreaterThan(200);
      expect(listFlat).toContain("should therefore not be re-filed");
      expect(listFlat).toContain("the cleaned-URL output");
    });

    it("the README carries the product-facing half and defers rather than restating", () => {
      const listStart = readme.indexOf("Concretely, linklint is not:");
      expect(listStart).toBeGreaterThan(-1);
      const listFlat = readme
        .slice(listStart, readme.indexOf("\n### ", listStart))
        .replace(/^\s*(?:>|-|\*)\s?/gm, "")
        .replace(/\s+/g, " ");
      expect(listFlat).toContain("A URL cleaner or rewriter.");
      // Hard-wraps mid-sentence in the README, so this one is only reachable
      // through the flattening above.
      expect(listFlat).toContain(
        "There is no `sanitize()`: you get a verdict about the string you passed in",
      );
      expect(listFlat).toContain("stated non-goal");
      // It must point at the canonical section rather than re-argue it: two
      // copies of the reasoning is the rot this repo has recorded twice.
      expect(listFlat).toContain("docs/architecture.md` §1.1");
      expect(listFlat).not.toContain("prefix glob");
      expect(listFlat).not.toContain("canonicalizeUrl");
    });
  });

  // LINK-uyoocslu. §5 listed "Agent-gated" as a seventh detector family with no
  // scope note, so the family read as a seventh kind of evidence rather than as
  // a caller-declared context. The families table is asserted elsewhere in this
  // file; what was missing is the pointer to the boundary.
  it("§5 says what the agent-gated family may claim and points at §1.1", () => {
    const start = architectureDoc.indexOf("## 5. Detectors");
    const flat = architectureDoc
      .slice(start, architectureDoc.indexOf("\n## 6.", start))
      .replace(/\s+/g, " ");
    expect(flat.length).toBeGreaterThan(500);
    expect(flat).toContain("§1.1");
    expect(flat).toContain("agentMode");
    expect(flat).toContain("caller-declared context");
  });

  // LINK-uyoocslu. The ALSO-REQUIRED half. Non-agent entries in
  // docs/reason-codes.md cite §1.1 by section number repeatedly; the four
  // agent-gated entries cited it ZERO times, each substituting a "Why it's a
  // signal" paragraph framed entirely in consumer consequence. That absence is
  // how the family kept its unexamined charter — a reader arriving at
  // `prompt_injection_url` had no route to the boundary.
  describe("docs/reason-codes.md — every agent-gated entry cites §1.1", () => {
    const gated = CHECKS.filter((c) => c.agentGated === true).flatMap((c) => c.emits);

    it("there is at least one agent-gated code to check (anti-vacuity)", () => {
      expect(gated.length).toBeGreaterThan(0);
    });

    it.each(gated)("`%s`'s entry cites architecture §1.1", (code) => {
      const heading = `### \`${code}\``;
      const at = reasonCodesDoc.indexOf(heading);
      expect(at).toBeGreaterThan(-1);
      // Bounded at the next heading of EITHER level: the last entry in a
      // section is followed by an `## ` heading, and slicing only on `### `
      // would swallow the whole next section into the match surface.
      const ends = [reasonCodesDoc.indexOf("\n### ", at + 1), reasonCodesDoc.indexOf("\n## ", at + 1)]
        .filter((i) => i > -1)
        .sort((a, b) => a - b);
      const next = ends[0] ?? -1;
      const entry = reasonCodesDoc
        .slice(at, next === -1 ? undefined : next)
        .replace(/^\s*>\s?/gm, "")
        .replace(/\s+/g, " ");
      // Anti-vacuity: an empty or truncated slice would pass every match below.
      expect(entry.length).toBeGreaterThan(400);
      expect(entry).toContain("§1.1");
      // The cross-reference has to carry the ruling, not just the section number.
      expect(entry).toContain("LINK-uyoocslu");
    });
  });

  // LINK-riupozbo. Two arguments linklint had earned but never stated. Both are
  // load-bearing under challenge and both are deletable without breaking a test
  // unless pinned: the cloaking argument is the only reason offline-first is a
  // CORRECTNESS property rather than a privacy one, and the CWE-20 quote is the
  // citable answer to "why not an allowlist".
  it("§1.1 states the cloaking-immunity argument for offline-first", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));

    expect(section).toContain("CrawlPhish");
    expect(section).toContain("PhishFarm");
    // The claim is immunity by construction, not a difficulty gradient.
    expect(section).toContain("structural immunity");
    // It must not silently widen into claim (b) while making the argument.
    expect(section.toLowerCase()).toContain("buys nothing against claim (b)");
  });

  it("§1.1 quotes CWE-20 on denylists including the caveat half", () => {
    const start = architectureDoc.indexOf("### 1.1 Scope of claim");
    const section = architectureDoc.slice(start, architectureDoc.indexOf("\n## 2.", start));

    expect(section).toContain("CWE-20");

    // The quote is a wrapped markdown blockquote, so match it with the "> "
    // prefixes and line breaks flattened — otherwise a reflow breaks the test
    // without changing a word of the citation.
    const quoted = section.replace(/^\s*>\s?/gm, "").replace(/\s+/g, " ");

    // The convenient half.
    expect(quoted).toContain("denylists can be useful for detecting potential attacks");
    // The half that makes quoting it honest — dropping this turns a defensible
    // position into the overclaim §1.1 exists to prevent.
    expect(quoted).toContain("Do not rely exclusively on looking for malicious or malformed inputs");
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

describe("§6's `status: \"invalid\"` invariant matches real inspect() output", () => {
  // LINK-qtenxsfi. §1.1's cited codes are pinned at their quoted weights above,
  // but the Key-invariants block under §6 had no guard at all — which is exactly
  // how it rotted. It stated `status: "invalid"` → "`parse_error` reason,
  // `checksRun: []`" as unconditional consequences, and both halves have been
  // false since `buildInvalidResult` (`src/schema/serialize.ts`) started
  // reporting structural findings that predate the parse failure: `parse_error`
  // is the FALLBACK for when nothing else explains it, and a findings-bearing
  // invalid result runs the lexical layer. The doc kept the pre-fourth-rule text
  // and nothing in the repository could contradict it.
  //
  // Anchored on the doc text and on live output — never on line numbers — so
  // both a reworded doc and a changed serializer land here.
  const invariantsStart = architectureDoc.indexOf("\nKey invariants:");
  const invariants = architectureDoc.slice(
    invariantsStart,
    architectureDoc.indexOf("\n### 6.1 ", invariantsStart),
  );

  // The bullet is one source line; take it whole so an assertion cannot be
  // satisfied by wording that lives in a different invariant.
  const invalidBullet =
    invariants.split("\n").find((line) => line.startsWith('- `status: "invalid"`')) ?? "";

  it("the Key-invariants block still carries an invalid-status bullet", () => {
    // Guards against a silently vacuous sweep: if the block or the bullet is
    // renamed away, every assertion below would pass on an empty string.
    expect(invariantsStart).toBeGreaterThan(-1);
    expect(invariants).toContain("- `score: 0` → `severity: \"info\"`");
    expect(invalidBullet.length).toBeGreaterThan(0);
  });

  it("the bullet no longer states the two halves the serializer falsified", () => {
    // The exact shipped conjunction. Restoring it must turn this red.
    expect(invalidBullet).not.toMatch(/`parse_error` reason, `checksRun: \[\]`/);
    // `parse_error` must be described as the fallback it is, not as the reason
    // an invalid result carries.
    expect(invalidBullet.toLowerCase()).toContain("fallback");
    // And the findings-bearing shape must be stated, not merely implied.
    expect(invalidBullet).toContain('`["lexical"]`');
  });

  it("the two halves that DO hold are stated: score and severity are null", () => {
    expect(invalidBullet).toContain("`score: null`");
    expect(invalidBullet).toContain("`severity: null`");
    expect(invalidBullet).toContain("not** benign");
  });

  it("the block states what an invalid result MAY carry, as an applicable rule", () => {
    // Two engineers read the old silence oppositely — weight-0 reports only, vs.
    // weights on a null score being inert decoration. Neither is the contract,
    // and the block must now say so rather than leave it to be re-litigated.
    expect(invariants).toContain("What an invalid result may carry");
    expect(invariants).toContain("ambiguous_authority");
    // The grounding: `aggregate()` is on the ok path only, so a weight here is
    // per-finding evidence and never an input to arithmetic.
    expect(invariants).toContain("aggregate()");
  });

  // LIVE HALF — the doc text above is only worth pinning if it is true of the
  // shipped serializer. These are the two shapes `buildInvalidResult` produces.
  it("a findings-bearing invalid result reports findings and runs the lexical layer", () => {
    for (const url of ["https:///evil.com", "https://ex ample.com"]) {
      const result = inspect(url);
      expect(result.status, url).toBe("invalid");
      expect(result.score, url).toBeNull();
      expect(result.severity, url).toBeNull();
      // Not empty, and NOT parse_error: the documented fallback must not fire
      // when a detector already explained the failure.
      expect(result.reasons.length, url).toBeGreaterThan(0);
      expect(result.reasons.map((r) => r.code), url).not.toContain("parse_error");
      expect(result.checksRun, url).toEqual(["lexical"]);
      expect(result.checksSkipped, url).toEqual(["resolution", "reputation"]);
    }
  });

  it("an invalid result may carry a SCORING weight, at the registry value", () => {
    // The worked case the doc quotes. If this ever collapses to weight 0 the
    // "not weight-0 annotations only" rule stops being true of the code.
    const result = inspect("https:///evil.com");
    const ambiguous = result.reasons.find((r) => r.code === "ambiguous_authority");
    expect(ambiguous).toBeDefined();
    expect(ambiguous?.weight).toBeCloseTo(REASON_CODES.ambiguous_authority.weight, 5);
    expect(ambiguous?.weight).toBeGreaterThan(0);
    // And the weight is evidence, not arithmetic: nothing aggregated it.
    expect(result.score).toBeNull();
  });

  it("`parse_error` with an empty checksRun is the fallback shape only", () => {
    for (const url of ["not a url at all", "", "http://"]) {
      const result = inspect(url);
      expect(result.status, url).toBe("invalid");
      expect(result.score, url).toBeNull();
      expect(result.severity, url).toBeNull();
      expect(result.reasons.map((r) => r.code), url).toEqual(["parse_error"]);
      expect(result.reasons[0]?.weight, url).toBe(0);
      expect(result.checksRun, url).toEqual([]);
      expect(result.checksSkipped, url).toEqual(["lexical", "resolution", "reputation"]);
    }
  });
});

describe("an adopted decision record cites its implementing ticket", () => {
  // LINK-hsoazwuu, stating the root cause of the LINK-tbqeqqvv failure as a rule.
  //
  // §6.1.1 shipped in PR #122 describing the adopted fold-gated escalation in the
  // PRESENT TENSE while its implementation ticket sat unimplemented for weeks.
  // From that moment every downstream reader — doc, tracker, epic — saw an
  // adopted, documented, working mechanism, and nothing in the repo could
  // contradict it. The trailer §6.1.1 now carries was added retrospectively;
  // this makes it mandatory, so a decision record without one is VISIBLY
  // unfinished instead of silently false.
  //
  // The guard is deliberately narrow: it fires only on the explicit
  // `**… — ADOPTED.**` marker, which is the point at which a record starts
  // making a present-tense claim about behavior. Prose that merely uses the word
  // "adopted" is untouched.
  const ADOPTION_MARKER = /\*\*[^*]*—\s*ADOPTED\.?\*\*/g;
  const TICKET_TRAILER = /\*\*(?:Implemented|Pending) \(`LINK-[a-z0-9]+`\)/;

  it("every ADOPTED block in architecture.md names the ticket that implements it", () => {
    const markers = [...architectureDoc.matchAll(ADOPTION_MARKER)];

    // If this drops to zero the regex has drifted away from the doc's style and
    // the guard is silently vacuous — the exact failure mode it exists to catch.
    expect(markers.length).toBeGreaterThan(0);

    for (const marker of markers) {
      const start = marker.index;
      // The record runs to the next heading of any level.
      const nextHeading = architectureDoc.slice(start).search(/\n#{2,4} /);
      const record = architectureDoc.slice(
        start,
        nextHeading === -1 ? undefined : start + nextHeading,
      );

      // Reported with the marker text so a failure names the offending record.
      expect(
        TICKET_TRAILER.test(record) ? "" : marker[0],
        `adopted record has no **Implemented (\`LINK-…\`)** or **Pending (\`LINK-…\`)** trailer`,
      ).toBe("");
    }
  });
});

describe("the ReasonCode registry is pinned to the SCHEMA_VERSION it registered under", () => {
  // LINK-zzydqrkd. The adopted bump matrix (docs/architecture.md §6.4) places
  // CLOSED value domains inside `SCHEMA_VERSION`'s ownership, and `ReasonCode`
  // — publicly exported, `keyof typeof REASON_CODES` — is the central one. The
  // matrix's own worked case says so: a new reason code bumps the schema.
  //
  // A prose grep for "no `SCHEMA_VERSION` bump" is the WEAK guard for that rule:
  // three such statements in architecture.md (§6.1.1, §6.1.2, §6.3) are correct
  // under the matrix, so the grep cannot tell a legitimate no-bump note from a
  // defect. This is the guard that bites. The
  // registry key set is checked in beside the version it was registered under,
  // so a code cannot be added, renamed, or removed without either moving
  // SCHEMA_VERSION or turning this red.
  //
  // Not hypothetical: commit `5813e01` added `fqdn_root_label` to the registry
  // with `src/schema/base.ts` and `src/scoring/weights.ts` both untouched, and
  // nothing in the repository could contradict it. This is the assertion that
  // would have caught it.
  //
  // Maintenance is one edit: on a real bump, re-stamp BOTH constants below in
  // the same commit. That is deliberate — a pin that may outlive its version is
  // a pin that silently stops checking, which is the failure mode the whole
  // guarantee register exists to prevent.
  // Proved to bite on a REMOVAL as well as an addition (LINK-eurtxkit): deleting
  // `api_endpoint_impersonation` from the registry with `SCHEMA_VERSION` left at
  // `1.8` turned this red with `{ added: [], removed: ["api_endpoint_impersonation"] }`
  // before the bump was applied. Both directions of the closed domain are guarded.
  // Re-confirmed on a MULTI-code removal (LINK-brsntven): dropping `risky_tld`
  // and `bait_tokens` with `SCHEMA_VERSION` left at `1.9` turned this red with
  // `{ added: [], removed: ["bait_tokens", "risky_tld"] }` in the commit before
  // the bump.
  // Re-confirmed AGAIN on a single addition (LINK-mgnbgicq): registering
  // `special_use_name` with `SCHEMA_VERSION` left at `1.10` turned this red with
  // `{ added: ["special_use_name"], removed: [] }` before the bump to `1.11`.
  // Re-confirmed a FIFTH time (LINK-dyqyhtgo): registering `header_shaped_token`
  // with `SCHEMA_VERSION` left at `1.12` turned this red with
  // `{ added: ["header_shaped_token"], removed: [] }` before the bump to `1.13`.
  // Five confirmations now, across both directions and both cardinalities.
  const PINNED_SCHEMA_VERSION = "1.13";

  /** Every `REASON_CODES` key as of `PINNED_SCHEMA_VERSION`, sorted. */
  const PINNED_REASON_CODES: readonly string[] = [
  "ambiguous_authority",
  "ambiguous_numeric_host",
  "ascii_homoglyph",
  "bidi_override",
  "brand_homoglyph",
  "brand_idna_collapse",
  "brand_locale_collapse",
  "confusable_char",
  "confusable_in_path",
  "content_type_mismatch",
  "control_char",
  "credential_harvesting",
  "dangerous_scheme",
  "data_exfiltration",
  "embedded_domain_in_subdomain",
  "encoding_obfuscation",
  "excessive_subdomain_depth",
  "file_extension_tld",
  "fqdn_root_label",
  "header_shaped_token",
  "homograph_latin_skeleton",
  "homograph_skeleton_collision",
  "host_denied",
  "host_length_unresolvable",
  "host_not_allowlisted",
  "https_downgrade_observed",
  "idn_host",
  "idna_mapping_ambiguity",
  "idna_protocol_violation",
  "invisible_char",
  "ip_cloud_metadata",
  "ip_link_local",
  "ip_loopback",
  "ip_obfuscation",
  "ip_private",
  "ip_reserved",
  "locale_case_ambiguity",
  "low_byte_truncation",
  "malware_url_listed",
  "mixed_script",
  "normalization_delta",
  "open_redirect_observed",
  "open_redirect_param",
  "parse_error",
  "percent_encoding_malformed",
  "port_denied",
  "prompt_injection_url",
  "punycode_malformed",
  "scheme_denied",
  "separator_lookalike",
  "special_use_name",
  "ssrf_cloud_metadata",
  "suspicious_extension",
  "tld_denied",
  "tld_not_allowlisted",
  "userinfo_present",
  "verified_phish_listed",
  "young_domain_brand_risk",
  ];

  const registryCodes = Object.keys(REASON_CODES).sort();

  it("the pin is not vacuous — a non-empty, sorted, duplicate-free key set", () => {
    // Without this, emptying the array would "fix" a failure by disabling the
    // guard, and an unsorted pin would fail for a reason that is not drift.
    expect(PINNED_REASON_CODES.length).toBeGreaterThan(0);
    expect([...PINNED_REASON_CODES]).toEqual([...PINNED_REASON_CODES].sort());
    expect(new Set(PINNED_REASON_CODES).size).toBe(PINNED_REASON_CODES.length);
  });

  it("the pin is stamped with the CURRENT SCHEMA_VERSION", () => {
    expect(
      SCHEMA_VERSION,
      "SCHEMA_VERSION moved without re-stamping the reason-code pin below it. " +
        "Update PINNED_SCHEMA_VERSION and PINNED_REASON_CODES together, in the " +
        "commit that bumps the schema (docs/architecture.md §6.4).",
    ).toBe(PINNED_SCHEMA_VERSION);
  });

  it("the registry key set is exactly the set pinned to this SCHEMA_VERSION", () => {
    const added = registryCodes.filter((code) => !PINNED_REASON_CODES.includes(code));
    const removed = PINNED_REASON_CODES.filter((code) => !registryCodes.includes(code));

    expect(
      { added, removed },
      "`ReasonCode` is a CLOSED, publicly exported value domain, so this change " +
        "owes a SCHEMA_VERSION bump (docs/architecture.md §6.4). Bump " +
        "SCHEMA_VERSION in src/schema/base.ts, then re-stamp both constants here.",
    ).toEqual({ added: [], removed: [] });
  });
});

describe("the SCHEMA_VERSION bump matrix is stated once and its contradictions are gone", () => {
  // LINK-zzydqrkd. Four sites answered "when does SCHEMA_VERSION bump?" and they
  // did not agree: `schema/base.ts` said every contract change including additive
  // ones, while `schema/options.ts`, §6's invariant list and `docs/scoring.md`
  // each excused the additive `Reason.suppressed` field. base.ts won. These
  // assertions are what stops the losing sentence from being written back — the
  // usual way a settled question quietly reopens.
  const optionsSrc = readFileSync(
    join(REPO_ROOT, "packages", "core", "src", "schema", "options.ts"),
    "utf8",
  );
  const baseSrc = readFileSync(
    join(REPO_ROOT, "packages", "core", "src", "schema", "base.ts"),
    "utf8",
  );
  const changelog = readFileSync(join(REPO_ROOT, "CHANGELOG.md"), "utf8");

  const matrixStart = architectureDoc.indexOf("### 6.4 Version stamps");
  const matrix = architectureDoc.slice(
    matrixStart,
    architectureDoc.indexOf("\n## 7. ", matrixStart === -1 ? 0 : matrixStart),
  );

  it("§6.4 exists and is not an empty slice", () => {
    // Guards against a vacuous sweep: every assertion below reads `matrix`.
    expect(matrixStart).toBeGreaterThan(-1);
    expect(matrix.length).toBeGreaterThan(500);
  });

  it("the surviving rule is the one in base.ts, stated there unchanged", () => {
    expect(baseSrc).toContain("Bumped on every contract change — additive minor");
  });

  it("§6.4 states the matrix: what each stamp owns", () => {
    for (const stamp of [
      "`SCHEMA_VERSION` (`schema/base.ts`)",
      "`ENRICHMENT_SCHEMA_VERSION` (`schema/enrich.ts`)",
      "`WEIGHTS_VERSION` (`scoring/weights.ts`)",
      "`DataVersions` (`data/versions.ts`)",
      "package version + `CHANGELOG.md`",
    ]) {
      expect(matrix).toContain(stamp);
    }
    expect(matrix).toContain("including an additive one");
  });

  it("§6.4 carries the tie-break: closedness is the registry's call, not the type's", () => {
    // Without this sentence the matrix is ambiguous on its own central case:
    // `Reason.code` is `string` on the wire and `ReasonCode` in the registry.
    expect(matrix).toContain(
      "Closedness is decided by the documented registry, not by the TypeScript",
    );
    expect(matrix).toContain("`keyof typeof REASON_CODES`");
  });

  it("§6.4 answers the three worked cases", () => {
    expect(matrix).toContain("a new `checksSkipped` token");
    expect(matrix).toContain("a new reason code");
    expect(matrix).toContain("a new enrichment cause");
  });

  it("§6.4 records the dissent that lost, so it is not re-proposed", () => {
    expect(matrix).toContain("The dissent, recorded");
    expect(matrix.toUpperCase()).toContain("BREAKING-ONLY");
    // The checkable facts the dissent rested on must travel with it, or the
    // paragraph reads as a dismissal rather than a decision.
    expect(matrix).toContain("`packages/cli/src` and `packages/mcp/src`");
  });

  it("the dissent's central fact is still true of the tree", () => {
    // "nothing consumes schemaVersion" is a claim about the repository, and a
    // recorded dissent resting on a stale fact is worse than no record at all.
    for (const pkg of ["cli", "mcp"]) {
      const files: string[] = [];
      const walk = (path: string) => {
        for (const entry of readdirSync(path, { withFileTypes: true })) {
          const child = join(path, entry.name);
          if (entry.isDirectory()) walk(child);
          else if (entry.name.endsWith(".ts")) files.push(child);
        }
      };
      walk(join(REPO_ROOT, "packages", pkg, "src"));
      expect(files.length).toBeGreaterThan(0);
      const consumers = files.filter((f) => readFileSync(f, "utf8").includes("schemaVersion"));
      expect(consumers).toEqual([]);
    }
  });

  it("the three contrary claims stay deleted", () => {
    // The exact shipped wording of each, matched with whitespace flattened. All
    // three sites are hard-wrapped and two of the sentences wrapped MID-CLAIM,
    // so a raw substring check silently matched nothing — verified by putting
    // each sentence back: the flattened form reddens, the raw one did not.
    const flat = (text: string) => text.replace(/\s+/g, " ");
    expect(flat(architectureDoc)).not.toContain("needs no `SCHEMA_VERSION` bump");
    expect(flat(scoringDoc)).not.toContain("no `SCHEMA_VERSION` bump is needed");
    expect(flat(optionsSrc)).not.toContain(
      "additive and backward-compatible — no `SCHEMA_VERSION` bump",
    );
    // And each site now carries the matrix's actual answer instead of silence.
    for (const text of [architectureDoc, scoringDoc, optionsSrc]) {
      expect(text).toContain("§6.4");
    }
  });

  it("the CHANGELOG names both historical misses instead of baselining them", () => {
    // Recording 1.7 as "the reconciled baseline" without naming the two commits
    // that missed a bump would launder a defect into a clean starting point.
    expect(changelog).toContain("5813e01");
    expect(changelog).toContain("fqdn_root_label");
    expect(changelog).toContain("a077eeb");
    expect(changelog).toContain("`Reason.suppressed`");
    expect(changelog).toContain("reconciled baseline");
    // The one and only reason neither is retro-bumped.
    expect(changelog).toContain("0.1.0-dev.0");
  });
});
