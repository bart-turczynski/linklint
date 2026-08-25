import type { Detector, DetectorFinding } from "./types.js";
import {
  classifyHost,
  classifyMetadataHostname,
  cloudEndpointPhrase,
  endpointLocator,
} from "./ip-classification.js";

/**
 * `ssrf_cloud_metadata`. Agent-gated escalation for the cloud metadata endpoint.
 * Reuses the shared `classifyHost` range logic; rationale and examples live in
 * docs/reason-codes.md.
 *
 * The endpoint is described through the SHARED `cloudEndpointPhrase`, not a
 * second hand-written noun. This detector previously called every match "the
 * cloud instance-metadata endpoint", which is wrong for the rows that are not an
 * IMDS — Azure's WireServer channel above all (LINK-mjbrzxeo). One phrase
 * function means fixing the taxonomy once fixes it in both places.
 *
 * BY NAME AS WELL AS BY ADDRESS (LINK-hvawpgos). The endpoint is reached by a
 * vendor-published hostname at least as often as by its address —
 * `metadata.google.internal` is the spelling in Google's own curl examples — and
 * until this landed that spelling produced a `0.00` verdict with no reasons
 * while `169.254.169.254` blocked. An agent that refuses one and fetches the
 * other has not been protected from anything.
 *
 * Both spellings are answered here through the same two-line shape, so the
 * agent-mode escalation cannot come to a different conclusion from the always-on
 * classifier about what an endpoint IS. `classifyMetadataHostname` performs no
 * lookup: it is a whole-host equality test against `data/cloud-metadata.ts`,
 * which is why `inspect()` stays zero-network. `endpointLocator` is what keeps
 * the emitted detail from claiming otherwise.
 */
export const ssrfCloudMetadata: Detector = {
  id: "ssrf_cloud_metadata",
  layer: "lexical",
  agentGated: true,
  run(ctx): DetectorFinding[] {
    const c = classifyMetadataHostname(ctx.host) ?? classifyHost(ctx.host);
    if (!c || c.bucket !== "ip_cloud_metadata") return [];
    return [
      {
        code: "ssrf_cloud_metadata",
        detail:
          `agent context: host '${c.shown}' is ${cloudEndpointPhrase(c)} ` +
          `(${endpointLocator(c)}) — an in-flight SSRF credential-theft target, blocked`,
      },
    ];
  },
};
