---
name: Missed deceptive URL (false negative)
about: A URL you consider deceptive that linklint scores 0.00
title: 'False negative: '
labels: false-negative
assignees: ''
---

<!--
Please read "What linklint does not do" in the README first:
https://github.com/bart-turczynski/linklint#what-linklint-does-not-do

linklint claims to detect STRUCTURAL anomalies, not to know which words are
brands. A URL like `paypal-login.com` scores 0.00 by design — every label is a
real, correctly spelled word in a normal arrangement. That is a documented
boundary, not a bug.

Report it here anyway if you are unsure. We would rather see it twice.
-->

## The URL

<!-- Use a real, complete URL. Defang it if you prefer: hxxps://evil[.]com -->

```
```

## What linklint returned

<!-- Output of: npx linklint check --json '<url>' -->

```json
```

## What is structurally wrong with the string

<!--
The key question. Point at the part of the string itself that is malformed,
disguised, or inconsistent with how URLs normally work — for example a digit
standing in for a letter, a disguised separator, or a real domain buried in the
subdomain.

If the answer is "nothing is malformed, but I know that brand and this is
obviously an impersonation," that is the semantic claim linklint explicitly does
not make. Say so — it is still useful signal about where people expect the
boundary to be, and it helps us write clearer docs.
-->

## Version

<!-- Output of: npx linklint --version, and your Node version -->
