import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";
import { CHECKS } from "../src/detectors/checks.js";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import { AGENT_CORPUS } from "./corpus/corpus.js";

/**
 * The agent-gated reason codes that exist ONLY under the gate (the V4 family).
 * `ssrf_cloud_metadata` is agent-gated too but is deliberately not here: it is
 * an ESCALATION of a code that fires in either mode, so the byte-identical-
 * default assertions below (which demand the code be absent with the gate off)
 * apply to it in a different shape — see the grounded-escalation block.
 */
const AGENT_REASON_CODES = [
  "prompt_injection_url",
  "credential_harvesting",
  "data_exfiltration",
] as const;

/** Every agent-gated check id, derived — the family shrank from five to four. */
const GATED_CHECK_IDS = CHECKS.filter((c) => c.agentGated === true).map((c) => c.id);

/**
 * V4a — the agentMode observability contract (Option B). agentMode is an explicit
 * INPUT (reproducible: same (url, options) → same result), and:
 *
 *  1. Byte-identical default — inspect(url) === inspect(url, { agentMode: false }),
 *     verdict AND bookkeeping (checksRun, checksSkipped, score, reasons).
 *  2. Observable when on — agentMode:true with ≥1 gated check evaluated puts the
 *     "agent" channel token in checksRun, after lexical/policy.
 *  3. Gated-off checks are NOT listed in checksSkipped.
 *  4. Invalid-input path is unaffected.
 */

const INJECTION = "https://example.com/agent?role=system&prompt=ignore%20everything";
const BENIGN = "https://www.example.com/dashboard?page=2";

describe("agentMode — byte-identical default (load-bearing)", () => {
  const cases = [INJECTION, BENIGN, "https://paypal.com@evil.ru/", "javascript:alert(1)"];

  it.each(cases)("inspect(%s) deep-equals inspect(%s, { agentMode: false })", (url) => {
    expect(inspect(url, { agentMode: false })).toEqual(inspect(url));
  });

  it.each(cases)("default never carries the agent channel token: %s", (url) => {
    expect(inspect(url).checksRun).not.toContain("agent");
    expect(inspect(url, { agentMode: false }).checksRun).not.toContain("agent");
  });

  it("default never lists the gated detector in checksSkipped", () => {
    expect(inspect(INJECTION).checksSkipped).not.toContain("lexical:prompt_injection_url");
    expect(inspect(INJECTION).checksSkipped).not.toContain("agent");
    // The gated detector being off must not fire its reason either.
    expect(inspect(INJECTION).reasons.map((r) => r.code)).not.toContain("prompt_injection_url");
  });
});

describe("agentMode:true — observable channel token", () => {
  it("an injection URL puts 'agent' in checksRun AND fires prompt_injection_url", () => {
    const r = inspect(INJECTION, { agentMode: true });
    expect(r.checksRun).toContain("agent");
    expect(r.reasons.map((x) => x.code)).toContain("prompt_injection_url");
  });

  it("a benign URL with agentMode:true still shows 'agent' in checksRun, no false reason", () => {
    const r = inspect(BENIGN, { agentMode: true });
    expect(r.checksRun).toContain("agent");
    expect(r.reasons.map((x) => x.code)).not.toContain("prompt_injection_url");
  });

  it("channel order is [lexical, agent] with no policy configured", () => {
    expect(inspect(BENIGN, { agentMode: true }).checksRun).toEqual(["lexical", "agent"]);
  });

  it("channel order is [lexical, policy, agent] when all three run", () => {
    const r = inspect(BENIGN, { agentMode: true, denyTlds: ["com"] });
    expect(r.checksRun).toEqual(["lexical", "policy", "agent"]);
  });

  it("does NOT list the gated detector in checksSkipped when it ran cleanly", () => {
    const r = inspect(INJECTION, { agentMode: true });
    expect(r.checksSkipped).not.toContain("lexical:prompt_injection_url");
  });
});

// V4b — api_endpoint_impersonation was the second agent-gated detector and is
// DELETED (LINK-eurtxkit, schema 1.9 / weights 1.18). Its firing condition was
// `API_BRAND_DOMAINS.get(token)` — a watchlist lookup over contingent commercial
// facts — corroborated only by an `api`/`apis` label or a fixed route prefix,
// both of which are ordinary syntax. §1.1 calls that claim (b) wearing claim
// (a)'s clothes. What follows is the deletion record: the four rows that carried
// the argument, asserted at their POST-deletion values so a re-introduction has
// to argue with them. (The pre-deletion values are in the commit that added
// them.)
const API_IMPOSTER = "https://api.openai-com.io/v1/chat/completions";

describe("agentMode — api_endpoint_impersonation is deleted (LINK-eurtxkit)", () => {
  it("the code is gone from the registry and cannot be emitted", () => {
    expect(Object.keys(REASON_CODES)).not.toContain("api_endpoint_impersonation");
    expect(CHECKS.map((c) => c.id)).not.toContain("api_endpoint_impersonation");
  });

  it("the former flagship impostor host now scores 0 in BOTH modes", () => {
    for (const r of [inspect(API_IMPOSTER), inspect(API_IMPOSTER, { agentMode: true })]) {
      expect(r.score).toBe(0);
      expect(r.reasons).toHaveLength(0);
      expect(r.checksSkipped).not.toContain("lexical:api_endpoint_impersonation");
    }
  });

  it("api.openai-login.com scores 0 — it was 0.50 under agentMode on the lookup alone", () => {
    const r = inspect("https://api.openai-login.com", { agentMode: true });
    expect(r.score).toBe(0);
    expect(r.reasons).toHaveLength(0);
  });

  it("api.acme-login.com — the unlisted-token CONTROL — is UNMOVED at 0", () => {
    // It read 0 before the deletion and reads 0 after. The pair above and here
    // is the whole point: two structurally identical hosts scored differently
    // only because one token is on a commercial watchlist.
    const r = inspect("https://api.acme-login.com", { agentMode: true });
    expect(r.score).toBe(0);
    expect(r.reasons).toHaveLength(0);
  });

  it("api.0penai.com/v1/chat/completions — the STRUCTURAL case — is UNMOVED at 0.80 in plain mode", () => {
    // A digit demonstrably folds to a letter, so `brand_homoglyph` stands on
    // `skel !== raw` and the watchlist only NAMES the target. Nothing the
    // deletion touched is load-bearing here, and no agent gate is needed.
    const r = inspect("https://api.0penai.com/v1/chat/completions");
    expect(r.score).toBeCloseTo(0.8, 5);
    expect(r.severity).toBe("high");
    expect(r.reasons.map((x) => x.code)).toContain("brand_homoglyph");
  });

  it("api.openai.com.evil.io/v1/chat/completions — the DOUBLE-SCORE is gone: agent now equals plain", () => {
    // The deleted code read the SAME `openai` label that
    // `embedded_domain_in_subdomain` had already scored and stacked a second
    // 0.50 on it, taking 0.50/medium to 0.75/high with no new evidence. Both
    // modes now state the structural fact exactly once.
    const plain = inspect("https://api.openai.com.evil.io/v1/chat/completions");
    const agent = inspect("https://api.openai.com.evil.io/v1/chat/completions", {
      agentMode: true,
    });
    expect(plain.score).toBeCloseTo(0.5, 5);
    expect(plain.severity).toBe("medium");
    expect(plain.reasons.map((x) => x.code)).toEqual(["embedded_domain_in_subdomain"]);
    expect(agent.score).toBe(plain.score);
    expect(agent.severity).toBe(plain.severity);
    expect(agent.reasons.map((x) => x.code)).toEqual(plain.reasons.map((x) => x.code));
  });
});

// V4c — credential_harvesting is the third agent-gated detector. Same gating
// contract: byte-identical default, observable + fires under agentMode.
const CRED_HARVEST = "https://account-verify.example.com/oauth/authorize?client_id=abc";

describe("agentMode — credential_harvesting gating contract", () => {
  it("default is byte-identical to agentMode:false for an OAuth-shape impostor host", () => {
    expect(inspect(CRED_HARVEST, { agentMode: false })).toEqual(inspect(CRED_HARVEST));
  });

  it("default neither fires the code nor lists it in checksSkipped / carries the agent token", () => {
    const r = inspect(CRED_HARVEST);
    expect(r.reasons.map((x) => x.code)).not.toContain("credential_harvesting");
    expect(r.checksSkipped).not.toContain("lexical:credential_harvesting");
    expect(r.checksRun).not.toContain("agent");
  });

  it("agentMode:true puts 'agent' in checksRun AND fires credential_harvesting", () => {
    const r = inspect(CRED_HARVEST, { agentMode: true });
    expect(r.checksRun).toContain("agent");
    expect(r.reasons.map((x) => x.code)).toContain("credential_harvesting");
  });

  // CONVERTED (LINK-brsntven). The inverse provider allowlist is gone, so the
  // claim is inverted: a real provider carries the same shape and is reported
  // for it, at weight 0. The gating contract itself is unchanged — the code is
  // still silent without agentMode, asserted above.
  it("a known OAuth provider host reports the same shape, at weight 0", () => {
    const r = inspect("https://github.com/login/oauth/authorize?client_id=abc", {
      agentMode: true,
    });
    expect(r.reasons.map((x) => x.code)).toContain("credential_harvesting");
    expect(r.reasons.find((x) => x.code === "credential_harvesting")?.weight).toBe(0);
    expect(r.score).toBe(0);
  });
});

// V4d — data_exfiltration is the fourth agent-gated detector. Same gating
// contract: byte-identical default, observable + fires under agentMode.
const EXFIL = "https://collect.example.com/p?exfil=secretdata";

describe("agentMode — data_exfiltration gating contract", () => {
  it("default is byte-identical to agentMode:false for an exfil-shape URL", () => {
    expect(inspect(EXFIL, { agentMode: false })).toEqual(inspect(EXFIL));
  });

  it("default neither fires the code nor lists it in checksSkipped / carries the agent token", () => {
    const r = inspect(EXFIL);
    expect(r.reasons.map((x) => x.code)).not.toContain("data_exfiltration");
    expect(r.checksSkipped).not.toContain("lexical:data_exfiltration");
    expect(r.checksRun).not.toContain("agent");
  });

  it("agentMode:true puts 'agent' in checksRun AND fires data_exfiltration", () => {
    const r = inspect(EXFIL, { agentMode: true });
    expect(r.checksRun).toContain("agent");
    expect(r.reasons.map((x) => x.code)).toContain("data_exfiltration");
  });

  it("a benign URL does NOT fire data_exfiltration even under agentMode", () => {
    const r = inspect("https://www.example.com/dashboard?page=2", { agentMode: true });
    expect(r.reasons.map((x) => x.code)).not.toContain("data_exfiltration");
  });
});

// V4e — the Option-B gating contract held FAMILY-WIDE across the agent corpus
// (every deceptive row that opts into agentMode). With agentMode OFF each input
// is byte-identical to today (no agent reason code, no "agent" channel token,
// agent codes never appear in checksSkipped). With agentMode ON the row's
// expected agent reason fires and checksRun carries "agent".
describe("agentMode — family-wide gating contract over the agent corpus", () => {
  // LINK-brsntven took the three non-escalation codes to weight 0, so their
  // corpus rows are now labelled `info` rather than `deceptive`. The gating
  // contract is about which reasons appear in which mode and is orthogonal to
  // the weight, so the row selection widens to both labels rather than
  // narrowing to the one remaining deceptive code — narrowing would have
  // silently stopped exercising three quarters of the family.
  const deceptiveAgentRows = AGENT_CORPUS.filter(
    (r) =>
      (r.label === "deceptive" || r.label === "info") &&
      r.options?.agentMode === true &&
      (r.expectReasons?.length ?? 0) > 0,
  );

  it("the corpus exercises all three agent reporting reason codes", () => {
    const covered = new Set(deceptiveAgentRows.flatMap((r) => r.expectReasons ?? []));
    for (const code of AGENT_REASON_CODES) expect(covered).toContain(code);
  });

  it.each(deceptiveAgentRows.map((r) => [r.input, r] as const))(
    "agentMode OFF is byte-identical, agent-silent, and never skip-lists agent codes: %s",
    (_input, row) => {
      const off = inspect(row.input);
      expect(inspect(row.input, { agentMode: false })).toEqual(off);
      expect(off.checksRun).not.toContain("agent");
      const offCodes = off.reasons.map((r) => r.code);
      for (const code of AGENT_REASON_CODES) {
        expect(offCodes).not.toContain(code);
        expect(off.checksSkipped).not.toContain(`lexical:${code}`);
      }
      expect(off.checksSkipped).not.toContain("agent");
    },
  );

  it.each(deceptiveAgentRows.map((r) => [r.input, r] as const))(
    "agentMode ON carries the agent channel token and fires the expected reason: %s",
    (_input, row) => {
      const on = inspect(row.input, { agentMode: true });
      expect(on.checksRun).toContain("agent");
      const onCodes = on.reasons.map((r) => r.code);
      for (const code of row.expectReasons ?? []) expect(onCodes).toContain(code);
    },
  );
});

// LINK-uyoocslu — the charter (architecture §1.1, "Agent mode, settled"). Three
// facts about the family that the doctrine leans on and nothing asserted:
//
//  1. The family is exactly four checks. The ruling table in §1.1 is written
//     against that number; it was five until LINK-eurtxkit.
//  2. `ssrf_cloud_metadata` is GROUNDED because it is an escalation — the fact
//     it reports is settled with the gate OFF, by `ip_cloud_metadata` (reported
//     at weight 0 since LINK-bwqhvjcs, architecture §6.1.10 — a destination fact
//     is reported, not scored), and the gate moves the weight rather than the
//     finding set. If the always-on
//     code ever stops firing, the escalation stops being grounded and the §1.1
//     ruling silently becomes false.
//  3. The other three exist ONLY under the gate. That is the diagnostic §1.1
//     names: the gate, not a string property, is doing the epistemic work.
describe("agentMode — the family is exactly the four §1.1 rules on", () => {
  it("four agent-gated checks, and the deleted fifth is not among them", () => {
    expect(GATED_CHECK_IDS).toEqual([
      "prompt_injection_url",
      "credential_harvesting",
      "data_exfiltration",
      "ssrf_cloud_metadata",
    ]);
    expect(GATED_CHECK_IDS).not.toContain("api_endpoint_impersonation");
  });

  it("every gated check's reason code is a real registry code", () => {
    for (const id of CHECKS.filter((c) => c.agentGated === true).flatMap((c) => c.emits)) {
      expect(Object.keys(REASON_CODES)).toContain(id);
    }
  });
});

describe("agentMode — ssrf_cloud_metadata is a GROUNDED escalation (LINK-uyoocslu)", () => {
  // Both spellings: the IANA-reserved literal and the vendor-published name
  // that LINK-hvawpgos added. §1.1 rules on both together.
  const ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
  ];

  it.each(ENDPOINTS)("the underlying fact is reported with the gate OFF: %s", (url) => {
    const off = inspect(url);
    expect(off.reasons.map((r) => r.code)).toContain("ip_cloud_metadata");
    // Reported, never scored, since LINK-bwqhvjcs (architecture §6.1.10).
    expect(off.reasons.find((r) => r.code === "ip_cloud_metadata")?.weight).toBe(0);
    expect(off.score).toBe(0);
    expect(off.severity).toBe("info");
    // Condition 1 of the escalation charter: nothing about the gate is needed
    // to settle WHAT this address is.
    expect(off.reasons.map((r) => r.code)).not.toContain("ssrf_cloud_metadata");
  });

  it.each(ENDPOINTS)("the gate adds weight, not a new subject: %s", (url) => {
    const off = inspect(url);
    const on = inspect(url, { agentMode: true });
    // Condition 2: the finding set grows by exactly the escalation code, and
    // every reason the default verdict carried is still carried.
    const added = on.reasons.map((r) => r.code).filter((c) => !off.reasons.some((o) => o.code === c));
    expect(added).toEqual(["ssrf_cloud_metadata"]);
    for (const r of off.reasons) expect(on.reasons.map((x) => x.code)).toContain(r.code);
    expect(on.score).toBe(1);
    expect(on.severity).toBe("critical");
  });

  it("the other three gated codes exist ONLY under the gate — the contrast §1.1 draws", () => {
    // Still true, and since LINK-brsntven it no longer costs anything: the three
    // report at weight 0, so a finding that exists only under the gate can no
    // longer spend the caller's declaration to move a score.
    const onlyGated: Array<[string, string]> = [
      ["prompt_injection_url", INJECTION],
      ["credential_harvesting", CRED_HARVEST],
      ["data_exfiltration", EXFIL],
    ];
    for (const [code, url] of onlyGated) {
      // Nothing at all is reported with the gate off: the gate is not
      // re-weighting a settled fact, it is creating the finding.
      expect(inspect(url).reasons.map((r) => r.code)).not.toContain(code);
      expect(inspect(url, { agentMode: true }).reasons.map((r) => r.code)).toContain(code);
    }
  });
});

// LINK-uyoocslu — the narrow marker fix, which is independent of the doctrine.
// `data` is an ordinary English word and a very common parameter name; it sat in
// EXFIL_MARKER_PARAMS beside `exfil`/`beacon`/`dump`/`leak`/`payload`, and a
// plain download link scored 0.30/medium under agent mode on nothing else.
describe("data_exfiltration — the `data` marker false positive (LINK-uyoocslu)", () => {
  const FP = "https://blog.example.com/download?data=report2024";

  it("an ordinary `data=` parameter does not fire, in either mode", () => {
    for (const r of [inspect(FP), inspect(FP, { agentMode: true })]) {
      expect(r.reasons.map((x) => x.code)).not.toContain("data_exfiltration");
      expect(r.score).toBe(0);
      expect(r.severity).toBe("info");
    }
  });

  it("the Safelinks spelling `&data=05|01` does not fire either", () => {
    // Microsoft's link rewriter puts `data=` in every URL it touches; the
    // repository's own online fixtures carry the shape.
    const url = "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2F&data=05%7C01";
    expect(inspect(url, { agentMode: true }).reasons.map((x) => x.code)).not.toContain(
      "data_exfiltration",
    );
  });

  it("the remaining markers are untouched — this is a set edit, not a disable", () => {
    for (const marker of ["exfil", "beacon", "dump", "leak", "payload"]) {
      const r = inspect(`https://collect.example.com/p?${marker}=secret`, { agentMode: true });
      expect(r.reasons.map((x) => x.code)).toContain("data_exfiltration");
    }
  });

  it("the overlong-opaque-token branch is untouched", () => {
    const blob = "A1b2C3d4E5f6G7h8".repeat(16);
    const r = inspect(`https://collect.example.com/p?data=${blob}`, { agentMode: true });
    // Still caught — by LENGTH and OPAQUENESS, which is a property of the value
    // rather than of the parameter's English name.
    expect(r.reasons.map((x) => x.code)).toContain("data_exfiltration");
  });
});

describe("agentMode — invalid-input path is unaffected", () => {
  it("invalid input is byte-identical with and without agentMode", () => {
    const invalid = "http://"; // unparseable
    expect(inspect(invalid, { agentMode: true })).toEqual(inspect(invalid));
    expect(inspect(invalid, { agentMode: false })).toEqual(inspect(invalid));
  });

  it("invalid input never carries the agent token", () => {
    expect(inspect("http://", { agentMode: true }).checksRun).not.toContain("agent");
  });
});
