# @linklint/mcp

A thin, **local-only** [MCP](https://modelcontextprotocol.io) server over the
[`linklint`](../core) core. It lets an LLM agent **check a URL before it fetches
it** — fully offline, deterministic, no telemetry. By default the MCP tools match
`inspect(url)` exactly. Pass `agentMode: true` when the caller is an agent/tool-use
workflow and should run the agent-gated detector channel.

## Tools

| Tool           | Input                                      | Returns                         |
| -------------- | ------------------------------------------ | ------------------------------- |
| `check_url`    | `{ url: string, agentMode?: boolean }`     | the core `InspectResult` schema |
| `check_domain` | `{ domain: string, agentMode?: boolean }`  | same schema (alias of check_url) |

Both return the **exact** core schema — the adapter never reimplements or forks
detector/scoring logic. The agent reads `severity` (`info`→`critical`), `score`,
and named `reasons`, and gates on them: treat `high`/`critical` as do-not-fetch,
and `status: "invalid"` as **not-checked** (do not assume safe).

`agentMode` defaults to `false`, so disabled agent-gated checks are not reported
as skipped and the output stays byte-identical to core `inspect(url)`. With
`agentMode: true`, the tools pass `{ agentMode: true }` through to core and enable
the V4 agent-family checks (`prompt_injection_url`, `api_endpoint_impersonation`,
`credential_harvesting`, `data_exfiltration`) plus the cloud-metadata SSRF
escalation (`ssrf_cloud_metadata`).

## Run

```bash
linklint-mcp        # stdio server
```

### Claude Code / Claude Desktop config

```json
{
  "mcpServers": {
    "linklint": { "command": "linklint-mcp" }
  }
}
```

## Guarantees

- **No outbound network** and **no telemetry** (v1, FR-MCP-2). Nothing about an
  inspected URL leaves the process.
- **Read-only** tools (`readOnlyHint`).

## License

MIT.
