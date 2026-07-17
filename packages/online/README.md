# @linklint/online

Explicit, caller-composed Node/server capabilities for `linklint`.

The package is being delivered capability by capability. Importing it performs
no network I/O, and the existing `linklint`, `@linklint/cli`, and
`@linklint/mcp` packages remain offline. Destination transport is not available
until the DNS-pinned authorization boundary is implemented and exported.

The repository includes deterministic resolver, connector, HTTP, and clock
fixtures for transport tests. They are internal test infrastructure rather than
a supported package export; production code cannot discover or enable them.

See [`docs/online-runtime-boundary.md`](../../docs/online-runtime-boundary.md)
for the accepted ownership and authorization contract.
