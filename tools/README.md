# Data-build tools

Scripts that regenerate version-pinned data tables bundled into `@linklint/core`.
Generated files are committed (they are source the library imports) but must
**never be hand-edited** — re-run the relevant script instead.

## `build-confusables.mjs` — UTS#39 confusables (E1)

Generates `packages/core/src/data/confusables.generated.ts` from the official
[Unicode Security Mechanisms](https://www.unicode.org/reports/tr39) confusables
list.

```bash
# Regenerate from the pinned Unicode version (downloads confusables.txt):
node tools/build-confusables.mjs

# Or parse a local copy (offline / reproducible):
node tools/build-confusables.mjs --input path/to/confusables.txt

# CI / pre-commit guard — fail if the committed output is stale:
node tools/build-confusables.mjs --check
```

(Also available as `pnpm data:confusables` from the repo root.)

**Pinned source.** Unicode **16.0.0**, to match the IDNA/tldts baseline:
`https://www.unicode.org/Public/security/16.0.0/confusables.txt`. The generated
file records the source URL, version, and a `sha256` of the exact bytes parsed,
so any regeneration is verifiable. Bump `UNICODE_VERSION` in the script to move
to a newer release (e.g. 17.0.0) deliberately.

**Curated subset (OQ-1 / NFR-DATA-2/3).** Rather than ship the full ~6,300-row
table, the script filters to the high-risk cross-script subset that drives domain
homographs:

- **source** — a single non-ASCII Letter/Mark/Number (the shape of a character
  that can appear in a host label or path and impersonate ASCII);
- **target** — an all-ASCII-alphanumeric prototype (single letters/digits, plus
  multi-codepoint lookalikes such as `æ → ae` or `rn → m`).

This keeps the default `inspect()` bundle compact (~1,400 entries) while covering
Cyrillic/Greek/fullwidth/mathematical/etc. lookalikes. The annotation is
**informational only** (weight 0, FR-D-15/16): single-script legitimate IDNs
still score 0 (SC-2) because the cross-script de-noiser that actually scores is
`mixed_script`, not raw confusable annotation.

**License.** The confusables data is published under the Unicode Terms of Use
(permissive, attribution) — MIT-compatible to bundle. Attribution is recorded in
the generated file header.
