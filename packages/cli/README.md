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
| `--quiet`             | one line per URL                                                                            |
| `--no-color`          | disable ANSI color                                                                          |
| `--offline`           | reserved no-op in v1 (accepted and ignored)                                                 |
| `--help`, `--version` | print usage / version and exit 0                                                            |

### Policy flags

The policy channel is **caller-supplied judgment**, reported at weight `0`: each
flag adds a policy reason to the verdict and never moves the deception score.
linklint ships no built-in high-abuse TLD, host or port list — these flags are
where that judgment lives (`docs/architecture.md` §1.1, §6.1.5). Every
`<value>` flag is repeatable, and each is the CLI form of the identically-named
`inspect()` option.

Repeat the flag once per value — the same goes for `--idn-allow` above. A comma,
semicolon, vertical bar or whitespace inside a single value is a usage error
rather than a separator: `--deny-tld "com ru"` is one value, the literal string
`com ru`, which matches no TLD, so the CLI refuses it and points at `--deny-tld
com --deny-tld ru`. Whitespace _around_ a value is still just padding, on the
value flags whose option routes through the core's list normalizer: `--deny-tld
" com"` matches `.com`, and `--idn-allow " münchen.de "` exempts `münchen.de`.

| Flag                          | Option                  | Effect                                                                                   |
| ----------------------------- | ----------------------- | ---------------------------------------------------------------------------------------- |
| `--deny-tld <tld>`            | `denyTlds`              | report `tld_denied` for this TLD                                                           |
| `--allow-tld <tld>`           | `allowTlds`             | report `tld_not_allowlisted` for any other TLD                                             |
| `--deny-host <host>`          | `denyHosts`             | report `host_denied` for this registrable domain (covers its subdomains)                   |
| `--allow-host <host>`         | `allowHosts`            | report `host_not_allowlisted` for any other registrable domain                             |
| `--deny-scheme <scheme>`      | `denySchemes`           | report `scheme_denied` for this scheme (e.g. `javascript`, `data`)                         |
| `--allow-scheme <scheme>`     | `allowSchemes`          | report `scheme_denied` for any other scheme (e.g. an https-only policy)                    |
| `--deny-port <port>`          | `denyPorts`             | report `port_denied` for this explicit port; the value must be an integer `0`–`65535`      |
| `--deny-non-standard-ports`   | `denyNonStandardPorts`  | report `port_denied` for any explicit port that is not the scheme's default                |

```bash
# annotate a known shortener without changing what the score says about it
linklint check --deny-host bit.ly https://bit.ly/3xAmPl3

# corporate lockdown: only these domains, only https, only standard ports
linklint check --allow-host mycompany.com --allow-scheme https \
  --deny-non-standard-ports https://vendor.io:8443/
```

Port and scheme axes only look at what the URL states explicitly: a URL with no
port does not emit `port_denied`, and a schemeless input does not emit
`scheme_denied`.

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
