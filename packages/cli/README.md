# @linklint/cli

A thin, **offline** command-line interface over the [`linklint`](../core) core.
It lets you **check a URL for deception before you fetch it** — fully offline,
deterministic, no telemetry.

## Usage

```bash
linklint check <url...>          # inspect one or more URLs
linklint check --json <url...>   # machine-readable JSON array of full results
```

### Flags

| Flag                  | Effect                                                        |
| --------------------- | ------------------------------------------------------------ |
| `--json`              | emit a JSON array of the full `InspectResult` objects        |
| `--fail-on <sev>`     | severity threshold for a non-zero exit (default `high`)       |
| `--allow-invalid`     | treat unparseable URLs as a pass rather than a failure        |
| `--quiet`             | one line per URL                                              |
| `--no-color`          | disable ANSI color                                            |
| `--offline`           | reserved no-op in v1 (accepted and ignored)                  |
| `--help`, `--version` | print usage / version and exit 0                             |

## Exit codes

- **0** — every URL is below the `--fail-on` threshold and none invalid (or
  invalid allowed).
- **1** — any URL meets/exceeds the threshold, **or** any URL is invalid (unless
  `--allow-invalid`). Fail-closed: an unparseable URL is **not** assumed safe.
- **2** — usage error (unknown flag, bad `--fail-on`, no URLs given).

## Guarantees

- **No outbound network** and **no telemetry** (v1). Nothing about an inspected
  URL leaves the process.

## License

MIT.
