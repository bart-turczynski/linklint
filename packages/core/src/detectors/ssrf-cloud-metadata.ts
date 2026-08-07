import type { Detector, DetectorFinding } from "./types.js";
import { classifyHost, cloudEndpointPhrase } from "./ip-classification.js";

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
 */
export const ssrfCloudMetadata: Detector = {
  id: "ssrf_cloud_metadata",
  layer: "lexical",
  agentGated: true,
  run(ctx): DetectorFinding[] {
    const c = classifyHost(ctx.host);
    if (!c || c.bucket !== "ip_cloud_metadata") return [];
    return [
      {
        code: "ssrf_cloud_metadata",
        detail:
          `agent context: host '${c.shown}' is ${cloudEndpointPhrase(c)} ` +
          `(${c.canonical}) — an in-flight SSRF credential-theft target, blocked`,
      },
    ];
  },
};
