import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REASON_CODES } from "../src/schema/reason-codes.js";
import { REPO_ROOT } from "./doc-sweep.js";

/**
 * LINK-etvaztem — the "destination ports are unrestricted" section of
 * [`docs/safe-transport.md`](../../../docs/safe-transport.md), held against the
 * code it describes.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS SECTION GETS A PIN WHEN MOST DECISION PROSE DOES NOT
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Most of that document explains what the transport does; a reader who doubts
 * it can run the transport. This section is different in kind: it is the
 * RECORD OF A DECLINE (`LINK-rfjeztxh` decided 2-0 against a destination-port
 * allowlist), and its load-bearing content is a set of ABSENCES — no
 * `allowedPorts` field, no `prohibited-port` cause, no port value reaching the
 * address classifier. An absence has no runtime behavior to observe, so nothing
 * a reader can execute contradicts the prose once it stops being true.
 *
 * The failure mode is concrete rather than hypothetical. The proposal this
 * section refuses is the kind that gets re-filed, and if a later author accepts
 * some version of it, the section does not merely go stale — it becomes an
 * ACTIVE MISDIRECTION, telling the next reader that a decision stands after it
 * was reversed, and telling a consumer their ports are unrestricted while the
 * code refuses one. A record of a decline is worth less than nothing if it can
 * outlive the decline silently.
 *
 * `LINK-wutunnbk` is the precedent that settles it: the single sentence behind
 * two shipped fail-opens was prose nothing could contradict. So "prose is
 * enough" is argued here, not assumed, and the answer is that it is not enough
 * for the mechanical half. What is NOT asserted is the reasoning — that
 * blinding an inspector on `:8080` inverts its goal is a judgment, and no test
 * can hold a judgment. Only the five checkable facts the prose leans on are
 * pinned:
 *
 *   1. neither policy interface carries a port field;
 *   2. neither transport cause vocabulary carries a port code;
 *   3. `pinDestination` is handed no port, so the address decision is
 *      port-independent by construction and not by measurement;
 *   4. `redirect-chain.ts` hands `options.authorize` the hop URL, so the seam
 *      the doc offers as the alternative really exists;
 *   5. core's `port_denied` really is weight-0 advisory, so calling it advisory
 *      is not a promise the registry contradicts.
 *
 * `TRANSPORT_SCHEMA_VERSION` is deliberately NOT re-asserted here:
 * `packages/online/test/transport-outcome-registry.test.ts` already holds the
 * stamp and this document together, and a second copy of that pin would drift
 * from the first.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * HARD-WRAP TRAP — read before adding an assertion below
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Every sentence quoted here is hard-wrapped at 80 columns in the source, so a
 * raw `toContain` against the file bytes matches NOTHING and passes VACUOUSLY —
 * a green assertion that tests the absence of its own subject. `flatten()`
 * collapses whitespace and strips blockquote markers first, and its bite was
 * proved by mutation: substituting the raw document for the flattened one turns
 * every prose assertion in this file RED.
 */

const DOC_PATH = "docs/safe-transport.md";
const SECTION_HEADING = "## Destination ports are unrestricted, deliberately";
const NEXT_HEADING = "## Mandatory cumulative budgets";

const doc = readFileSync(join(REPO_ROOT, DOC_PATH), "utf8");

/** Collapse hard wraps and blockquote markers. See the trap note above. */
function flatten(text: string): string {
  return text.replace(/^\s*>\s?/gm, "").replace(/\s+/g, " ").trim();
}

function onlineSource(relative: string): string {
  return readFileSync(join(REPO_ROOT, "packages", "online", "src", relative), "utf8");
}

const policySource = onlineSource("transport/policy.ts");
const tlsTypesSource = onlineSource("transport/tls-types.ts");
const registrySource = onlineSource("transport/outcome-registry.ts");
const pinSource = onlineSource("transport/pin.ts");
const redirectSource = onlineSource("resolution/redirect-chain.ts");

/** The `readonly <name>:` fields of one exported interface, in source order. */
function interfaceFields(source: string, name: string): string[] {
  const start = source.indexOf(`export interface ${name} {`);
  if (start < 0) return [];
  const end = source.indexOf("\n}", start);
  const body = source.slice(start, end < 0 ? undefined : end);
  return [...body.matchAll(/^\s{2}readonly (\w+)/gm)].map((match) => match[1] as string);
}

/** The string literals of one `const <name> = [...] as const` value array. */
function constStringArray(source: string, name: string): string[] {
  const start = source.indexOf(`${name} = [`);
  if (start < 0) return [];
  const end = source.indexOf("] as const", start);
  if (end < 0) return [];
  return [...source.slice(start, end).matchAll(/"([a-z0-9-]+)"/g)].map(
    (match) => match[1] as string,
  );
}

describe("safe-transport port policy — the section exists and says what it says", () => {
  const headingAt = doc.indexOf(SECTION_HEADING);
  const nextAt = doc.indexOf(NEXT_HEADING);

  it("finds the section (guards every assertion below against a silent retitle)", () => {
    expect(
      headingAt,
      `${DOC_PATH} no longer contains "${SECTION_HEADING}". The port-policy ` +
        "record was renamed or removed; re-point this pin or re-open LINK-rfjeztxh.",
    ).toBeGreaterThanOrEqual(0);
    expect(nextAt).toBeGreaterThan(headingAt);
  });

  const section = flatten(doc.slice(headingAt, nextAt));

  it("carries a section of real substance, not a stub", () => {
    expect(section.length).toBeGreaterThan(1500);
  });

  it.each([
    "Destination ports carry no policy of their own, on the fetch path and on the TLS-observation path alike.",
    "There is no `allowedPorts` field on `TransportPolicy` or on `TlsInspectionPolicy`, no `prohibited-port` cause in either vocabulary",
    "`pinDestination` takes a hostname and a resolver, and `classifyTransportAddress` takes one address string; no port value reaches either.",
    "`resolution/redirect-chain.ts` calls `options.authorize()` with each hop's URL, port included.",
    "`port_denied` is `scoring: false` at weight 0",
  ])("states: %s", (sentence) => {
    expect(section).toContain(sentence);
  });

  it("keeps the reasoning, not only the outcome — a bare refusal invites a re-file", () => {
    // The three findings LINK-rfjeztxh turned on. Named by their distinguishing
    // token so a rewrite that drops one of the three reddens here.
    expect(section).toContain(":8443");
    expect(section).toContain("authorization-required");
    expect(section).toContain("architecture.md) §8");
  });
});

describe("safe-transport port policy — no port restriction exists to describe", () => {
  it("reads both policy interfaces at all (guards a vacuous absence check)", () => {
    expect(interfaceFields(policySource, "TransportPolicy")).toContain("maxHops");
    expect(interfaceFields(tlsTypesSource, "TlsInspectionPolicy")).toContain("maxChainDepth");
  });

  it.each([
    ["TransportPolicy", () => interfaceFields(policySource, "TransportPolicy")],
    ["TlsInspectionPolicy", () => interfaceFields(tlsTypesSource, "TlsInspectionPolicy")],
  ])("%s carries no port field", (name, fields) => {
    expect(
      fields().filter((field) => /port/i.test(field)),
      `${name} gained a port field. docs/safe-transport.md records that destination ` +
        "ports are unrestricted (LINK-rfjeztxh, decided 2-0). Reverse the decision in " +
        "the tracker and rewrite that section before shipping this.",
    ).toEqual([]);
  });

  it("reads both cause vocabularies at all (guards a vacuous absence check)", () => {
    expect(constStringArray(registrySource, "TRANSPORT_CAUSE_CODE_VALUES")).toContain(
      "prohibited-address",
    );
    expect(constStringArray(registrySource, "TLS_OBSERVATION_CAUSE_CODE_VALUES")).toContain(
      "prohibited-address",
    );
  });

  it.each(["TRANSPORT_CAUSE_CODE_VALUES", "TLS_OBSERVATION_CAUSE_CODE_VALUES"])(
    "%s carries no port cause",
    (name) => {
      expect(
        // Kebab TOKEN, not substring: `unsup-port-ed-scheme` matched a naive
      // /port/ and made this assertion fail against a vocabulary that has no
      // port cause at all. An over-broad absence check is a false alarm today
      // and a rewritten-to-vacuous check tomorrow.
      constStringArray(registrySource, name).filter((code) => /(?:^|-)ports?(?:-|$)/.test(code)),
        `${name} gained a port cause. That is a published CLOSED vocabulary under ` +
          "guarantee F16, so it would also move TRANSPORT_SCHEMA_VERSION — and it " +
          "would contradict the port-policy section of docs/safe-transport.md.",
      ).toEqual([]);
    },
  );

  it("keeps the address decision port-independent by construction", () => {
    // The doc's strongest claim: a port allowlist removes no address the
    // classifier admits, BECAUSE no port ever reaches the classifier. That is a
    // property of the signature, not of a measurement at two sample ports.
    const start = pinSource.indexOf("export async function pinDestination(");
    expect(start, "pinDestination moved or was renamed; re-point this pin.").toBeGreaterThanOrEqual(
      0,
    );
    const signature = pinSource.slice(start, pinSource.indexOf("): Promise<PinResult>", start));
    expect(signature).toContain("hostname: string");
    // PARAMETER NAMES only. The TYPES mention `ResolverPort`, so testing the
    // whole signature text for /port/i failed against a signature that takes no
    // port — the same substring trap `unsupported-scheme` sprang above.
    const parameters = [...signature.matchAll(/^\s{2}(\w+):/gm)].map((match) => match[1] as string);
    expect(parameters).toEqual(["resolver", "hostname", "signal"]);
    expect(
      parameters.some((parameter) => /port/i.test(parameter)),
      "pinDestination now takes a port. The address layer's port-independence is " +
        "what docs/safe-transport.md leans on to say a port allowlist adds nothing.",
    ).toBe(false);
    expect(pinSource).toContain("classifyTransportAddress(answer.address)");
  });
});

describe("safe-transport port policy — the alternatives the doc offers are real", () => {
  it("hands options.authorize the hop URL, port and all", () => {
    expect(
      redirectSource.includes("options.authorize("),
      "redirect-chain.ts no longer calls options.authorize; docs/safe-transport.md " +
        "offers that callback as the enforcing seam for a caller's own port policy.",
    ).toBe(true);
    expect(flatten(redirectSource)).toContain("await options.authorize({ url: currentUrl, hop,");
  });

  it("keeps core's port axis advisory — weight 0, non-scoring, policy layer", () => {
    expect(REASON_CODES.port_denied.weight).toBe(0);
    expect(REASON_CODES.port_denied.scoring).toBe(false);
    expect(REASON_CODES.port_denied.layer).toBe("policy");
  });
});
