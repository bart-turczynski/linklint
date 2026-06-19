# @linklint/mcp

A thin, **local-only** [MCP](https://modelcontextprotocol.io) server over the
[`linklint`](../core) core. It lets an LLM agent **check a URL before it fetches
it** — fully offline, deterministic, no telemetry.

## Tools

| Tool           | Input              | Returns                          |
| -------------- | ------------------ | -------------------------------- |
| `check_url`    | `{ url: string }`  | the core `InspectResult` schema  |
| `check_domain` | `{ domain: string }` | same schema (alias of check_url) |

Both return the **exact** core schema — the adapter never reimplements or forks
detector/scoring logic. The agent reads `severity` (`info`→`critical`), `score`,
and named `reasons`, and gates on them: treat `high`/`critical` as do-not-fetch,
and `status: "invalid"` as **not-checked** (do not assume safe).

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
