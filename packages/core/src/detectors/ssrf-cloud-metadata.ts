import type { Detector, DetectorFinding } from "./types.js";
import { classifyHost } from "./ip-classification.js";

/**
 * `ssrf_cloud_metadata`. Agent-gated escalation for the cloud metadata endpoint.
 * Reuses the shared `classifyHost` range logic; rationale and examples live in
 * docs/reason-codes.md.
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
          `agent context: host '${c.shown}' is the cloud instance-metadata endpoint ` +
          `(${c.canonical}) — an in-flight SSRF credential-theft target, blocked`,
      },
    ];
  },
};
