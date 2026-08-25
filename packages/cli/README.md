# @linklint/cli

A thin, **offline** command-line interface over the [`linklint`](../core) core.
It lets you **check a URL for deception before you fetch it** — fully offline,
deterministic, no telemetry.

## Usage

```bash
linklint check <url...>          # inspect one or more URLs
linklint check                   # read URLs from stdin (one per line) when piped
linklint check --json <url...>   # machine-readable JSON array of full results
linklint batch <file>            # inspect URLs from a file (one per line)
```

Files and stdin skip blank lines and lines starting with `#`.

### Flags

| Flag                  | Effect                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------- |
| `--json`              | emit a JSON array of the full `InspectResult` objects                                       |
| `--fail-on <sev>`     | severity threshold for a non-zero exit (default `high`)                                     |
| `--allow-invalid`     | treat unparseable URLs as a pass rather than a failure                                      |
| `--agent`             | enable agent-gated detectors (prompt-injection, credential-harvesting, data-exfiltration, cloud-metadata SSRF escalation) |
| `--allow-idn`         | permit internationalized (Unicode/punycode) domains (default: block at `high`)              |
| `--idn-allow <domain>`| exempt one registrable domain from the IDN block (repeatable)                               |
| `--deny-tld <tld>`     | report a weight-0 `tld_denied` for this TLD (repeatable)                                    |
| `--allow-tld <tld>`    | report a weight-0 `tld_not_allowlisted` for any other TLD (repeatable)                      |
| `--quiet`             | one line per URL                                                                            |
| `--no-color`          | disable ANSI color                                                                          |
| `--offline`           | reserved no-op in v1 (accepted and ignored)                                                 |
| `--help`, `--version` | print usage / version and exit 0                                                            |

## Exit codes

- **0** — every URL is below the `--fail-on` threshold and none invalid (or
  invalid allowed).
- **1** — any URL meets/exceeds the threshold, **or** any URL is invalid (unless
  `--allow-invalid`). Fail-closed: an unparseable URL is **not** assumed safe.
- **2** — usage error (unknown flag, bad `--fail-on`, no URLs given).

## Guarantees

- **No outbound network** and **no telemetry** (v1). Nothing about an inspected
  URL leaves the process.

## Library API

`@linklint/cli` supports a small root-only library API for tests and thin
wrappers:

```ts
import { parseCli, renderResults, resolveExitCode, run } from '@linklint/cli';
```

Supported exports are the argument parser, line parser, renderers, exit-policy
helpers/constants, `run`, `main`, `USAGE`, `CLI_VERSION`, and `UsageError`.
Deep imports are not supported; the executable remains the `linklint` bin.

## License

MIT.
