import type { InspectOptions, InspectResult } from "./schema/types.js";
import { describeParseFailure } from "./parse/failure.js";
import { parsePrepared } from "./parse/parse.js";
import { prepare } from "./parse/prepare.js";
import { tokenizeRawUrl } from "./parse/raw-tokens.js";
import { DETECTORS } from "./detectors/registry.js";
import { STRUCTURAL_SCANS } from "./detectors/structural.js";
import {
  buildInvalidResult,
  buildOkResult,
  type CollectedFinding,
} from "./schema/serialize.js";
import { policyConfigured, runPolicy } from "./policy/policy.js";
import { suppressConfigured } from "./scoring/suppress.js";
import { normalizeOptions } from "./parse/runtime.js";
import { authorityRegion } from "./parse/authority-region.js";
import { intakeOptions } from "./schema/options.js";

/**
 * Best-effort echo of a non-string input for the `input` field, which the result
 * schema pins to `string`. `String()` is itself partial — it throws on an object
 * whose `toString` throws and on a Proxy that traps `get` — so the catch keeps
 * this total by construction. Unrepresentable inputs echo as `""`.
 */
function coerceInput(value: unknown): string {
  try {
    return String(value);
  } catch {
    return "";
  }
}

/**
 * Inspect a single URL or bare hostname. Synchronous, zero-network, never throws
 * (FR-LIB-2, FR-IN-4, NFR-PERF-1). Returns the stable versioned schema for every
 * input — `status: "ok"` for anything parseable, `status: "invalid"` otherwise.
 *
 * The never-throws guarantee is **unconditional**, not string-only: a non-string
 * returns `status: "invalid"` rather than a `TypeError` (LINK-zsbeqtcr).
 */
export function inspect(input: string, rawOptions: InspectOptions = {}): InspectResult {
  // Option intake (LINK-sjsxfqoo). The same argument that TypeScript types is
  // untyped by the time it gets here: JSON config, MCP tool input, a plain-JS
  // caller, options widened through a variable. Keys we do not recognize used to
  // be dropped in silence, so `{ allowHost: [...] }` — the singular typo —
  // returned a result byte-identical to one where no policy was ever requested.
  // That failure is OPEN, in the channel whose whole purpose is restriction.
  //
  // The loss is now REPORTED, not rejected: `intakeOptions` names each dropped
  // key as `options:<key>` in checksSkipped (and an unusable argument as bare
  // `options`), reusing the channel and the `<namespace>:<id>` token grammar the
  // policy and detector loops already use. Rejecting by THROWING is not
  // available — inspect()'s never-throws guarantee is unconditional (A1 /
  // LINK-zsbeqtcr) — and would in any case put the try/catch obligation on the
  // callers least likely to have one.
  //
  // These tokens are seeded ahead of everything else because intake precedes
  // every check, and they must reach BOTH result paths: an input that fails to
  // parse must still report the option the caller lost.
  const intake = intakeOptions(rawOptions);
  const optionSkipped = intake.skipped;
  const options = intake.options;

  // Contract guard (FR-IN-4). TypeScript types `input` as string, but a plain-JS
  // caller — or `JSON.parse` output — can hand us null/undefined/a number, and
  // the whole premise is that inspect() is safe on *fully* untrusted input.
  // Throwing here would put the try/catch obligation on exactly the callers least
  // likely to have one, and an uncaught TypeError inside a link-checking hook
  // fails **open** — the precise failure this tool exists to prevent. A non-string
  // is not benign: it fails closed as `invalid` (score/severity null), which a
  // fail-closed consumer must already reject.
  if (typeof input !== "string") {
    return buildInvalidResult(
      coerceInput(input),
      [],
      `input is not a string (got ${input === null ? "null" : typeof input})`,
      optionSkipped,
    );
  }
  // Structural scans over the raw input. They run independently of
  // parse() so they can flag the very inputs parse() discards (backslash, empty
  // authority, multi-colon host, delimiter look-alikes, encoded control chars)
  // instead of losing the signal to `invalid`.
  const runtime = normalizeOptions(options);
  const structural: CollectedFinding[] = [];
  // Structural scans run before parse, so this skip list must exist ahead of the
  // parse branch and feed both result paths. A failed scan is recorded with the
  // same `lexical:<id>` shape the parsed-detector loop uses below (FR-D-13).
  const structuralSkipped: string[] = [];
  const prepared = prepare(input);
  const rawTokens = tokenizeRawUrl(prepared);
  // Every structural scan needs the authority region — compute it once and share.
  const scanCtx = { input, prepared, runtime, authority: authorityRegion(prepared, rawTokens) };
  for (const scan of STRUCTURAL_SCANS) {
    try {
      structural.push(...scan.run(scanCtx));
    } catch {
      // A scan must never abort inspection (FR-D-13). Record the skip so the
      // score is reported as a lower bound rather than silently swallowing it.
      structuralSkipped.push(`lexical:${scan.id}`);
    }
  }

  let ctx;
  try {
    ctx = prepared === "" ? null : parsePrepared(input, prepared, runtime, rawTokens);
  } catch {
    // Parsing must be total — any unexpected failure is treated as invalid input.
    // The invalid path's bare `"lexical"` checksSkipped entry already states that
    // the entire lexical layer (structural scans included) was not fully applied,
    // so per-scan `lexical:<id>` skips are deliberately not threaded here — doing
    // so would change the cucumber-pinned invalid CSV value. (LINK-hastsuzd)
    //
    // The scheme-naming detail is deliberately NOT passed here either: this
    // branch is an unexpected internal failure, and "the authority region is not
    // a host" would name a cause nothing established. Naming the wrong failure
    // is worse than the generic fallback (LINK-iuzphbnp).
    return buildInvalidResult(input, structural, undefined, optionSkipped);
  }
  // Unparseable input: still explain itself if the authority was ambiguous.
  // When no detector explains it, `parse_error` is the fallback — and per §1.1's
  // fourth rule it must name what failed rather than stand in for the whole
  // verdict, so the scheme token the tokenizer did recover is passed through
  // the serializer's existing `parseErrorDetail` channel (LINK-iuzphbnp).
  // Schemeless input yields `undefined` here and keeps the generic string.
  if (ctx === null) {
    return buildInvalidResult(input, structural, describeParseFailure(rawTokens), optionSkipped);
  }

  const findings: CollectedFinding[] = [...structural];
  // Seed with the intake skips, then any structural-scan skips, so both reach
  // checksSkipped on the OK path in the order they actually happened: reading
  // the options precedes every check.
  const skippedDetectors: string[] = [...optionSkipped, ...structuralSkipped];

  // Agent channel (FR-AGENT-*): agent-gated detectors are an explicit opt-in
  // (InspectOptions.agentMode). When off they are silently not evaluated — NOT
  // listed in checksSkipped (an available-but-disabled feature channel, not a
  // skipped layer). `agentRan` mirrors `policyRan`: it records that ≥1 gated
  // check was actually evaluated, gating the `agent` token in checksRun so the
  // default path stays byte-identical to today.
  const agentMode = options.agentMode === true;
  let agentRan = false;

  for (const detector of DETECTORS) {
    if (detector.agentGated) {
      if (!agentMode) continue;
      agentRan = true;
    }
    try {
      for (const f of detector.run(ctx)) {
        findings.push({ code: f.code, detail: f.detail, ...(f.confusables ? { confusables: f.confusables } : {}) });
      }
    } catch {
      // A detector-local failure must not abort inspection (FR-D-13). The score
      // becomes a lower bound and the detector is recorded as skipped.
      skippedDetectors.push(`lexical:${detector.id}`);
    }
  }

  // Policy channel (FR-POLICY-*): a separate, caller-configured set of axes that
  // annotate without scoring (layer "policy", weight 0). It runs only when the
  // caller configured a policy field — otherwise the result is byte-identical to
  // today (no `policy` in checksRun, no policy reasons).
  //
  // Failures are reported per axis (LINK-ymprmvhr). `runPolicy` guards each
  // descriptor, so a throwing axis costs only itself and is named
  // `policy:<axis id>` in checksSkipped — the same token shape the detector
  // loops use (`lexical:<id>`), and for the same reason: the channel token
  // ("policy") and a skip token can then never be confused for each other. The
  // channel counts as run only if at least one axis completed, so "policy"
  // never appears in checksRun and checksSkipped at once.
  let policyFindings: CollectedFinding[] = [];
  let policyRan = false;
  if (policyConfigured(options)) {
    try {
      const outcome = runPolicy(ctx);
      policyFindings = outcome.findings;
      policyRan = outcome.anyAxisRan;
      for (const axisId of outcome.skippedAxes) skippedDetectors.push(`policy:${axisId}`);
    } catch {
      // Backstop. `runPolicy` contains its own axes, so reaching here means the
      // dispatcher itself failed and no axis verdict exists — the whole channel
      // is skipped and unnamed. Kept because inspect()'s never-throws guarantee
      // (FR-D-13) must not depend on a callee's internal discipline.
      skippedDetectors.push("policy");
    }
  }

  // Caller false-positive escape hatch (FR — architecture §9): a general
  // suppression channel that annotates matched reasons `suppressed` and zeroes
  // their scoring weight. Configured whenever `suppressReasons` is present; when
  // absent the result is byte-identical to today (no `suppression` in checksRun,
  // no `suppressed` markers). The rules themselves ride on `ctx.runtime`.
  const suppressRan = suppressConfigured(options);

  return buildOkResult(
    ctx,
    findings,
    skippedDetectors,
    policyFindings,
    policyRan,
    agentRan,
    suppressRan,
  );
}
