import type { Detector, DetectorFinding } from "./types.js";
import { classifyHost } from "./ip-classification.js";

/**
 * `ssrf_cloud_metadata` (scoring, BLOCKER weight 1.0). AGENT-GATED escalation:
 * runs only when `InspectOptions.agentMode` is true. In an agent / tool-use
 * context a URL whose host is the cloud instance-metadata endpoint
 * (169.254.169.254, fd00:ec2::254, and IPv4-in-IPv6 embeddings of it) is an
 * in-flight SSRF credential-theft attempt with no defensible purpose, so it
 * BLOCKS — the weight saturates the score to critical.
 *
 * It STACKS on the always-on `ip_cloud_metadata` (0.75): that classifier states
 * the fact (host is the metadata endpoint, lands high), this states the
 * agent-context verdict (block). Default (non-agent) callers — log scanners,
 * cloud-ops tooling that legitimately names the endpoint — never see this and
 * keep the high, overridable `ip_cloud_metadata` verdict.
 *
 * Reuses the shared `classifyHost` range logic — no IP parsing here. Pure,
 * synchronous, no network/fs.
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
