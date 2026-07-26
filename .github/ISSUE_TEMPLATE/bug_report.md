---
name: Bug report
about: Report incorrect or unexpected behavior
title: ''
labels: bug
assignees: ''
---

<!--
Reporting a URL that linklint SHOULD have flagged but didn't? Use the
"Missed deceptive URL (false negative)" template instead.

Found input that makes inspect() throw, hang, or exhaust memory? That breaks
linklint's central safety guarantee — please report it privately via the
Security tab. See SECURITY.md.
-->

## Describe the bug

A clear and concise description of what the bug is.

## Reproducible example

The single most helpful thing you can provide — a minimal snippet we can run.

```ts
import { inspect } from 'linklint';

inspect('...');
```

## Expected behavior

What you expected to happen.

## Actual behavior

What happened instead. Paste the full result object or CLI output if relevant.

## Environment

- linklint version:
- Node version:
- OS:
- Surface: <!-- library / CLI / MCP server / @linklint/online -->
