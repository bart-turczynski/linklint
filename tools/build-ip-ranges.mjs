#!/usr/bin/env node
// @ts-check
/**
 * Data-build script for the IANA special-purpose IP ranges (LINK-qvsrmrzv / S3).
 *
 * Parses the IANA IPv4 and IPv6 Special-Purpose Address Registries (CSV) and
 * emits a longest-prefix-match table at
 * packages/core/src/data/ip-ranges.generated.ts.
 *
 *   node tools/build-ip-ranges.mjs                    # regenerate from the
 *                                                     # committed snapshots
 *   node tools/build-ip-ranges.mjs --fetch            # refresh the snapshots
 *                                                     # from IANA, then rebuild
 *   node tools/build-ip-ranges.mjs --input-v4 <file> --input-v6 <file>
 *   node tools/build-ip-ranges.mjs --check            # fail if output is stale
 *
 * Do NOT hand-edit the generated file. Re-run this script to regenerate it.
 *
 * Unlike build-confusables.mjs, the DEFAULT mode is offline: the two registry
 * CSVs are committed under tools/data/, so a regeneration (and therefore the
 * --check drift guard, which ip-ranges.test.ts runs) is byte-reproducible with
 * no network. `--fetch` is the deliberate act of moving the pin forward.
 *
 * BUCKET MAPPING (the curation layered on top of the registry). The registry has
 * no loopback/private/link-local taxonomy — only a Name and a set of boolean
 * columns — so the mapping is by NAME first, then by `Globally Reachable`:
 *
 *   Loopback…                        → ip_loopback
 *   Private-Use | Unique-Local       → ip_private
 *   Link Local | Link-Local Unicast  → ip_link_local
 *   Documentation…                   → NO BUCKET (curated, see below)
 *   transition wrapper prefixes      → NO BUCKET (curated, see below)
 *   Globally Reachable = True        → NO BUCKET (an ordinary address)
 *   everything else                  → ip_reserved
 *
 * The two curated NO-BUCKET classes are deliberate precision decisions, not
 * registry data:
 *
 *  1. DOCUMENTATION (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
 *     2001:db8::/32, 3fff::/20). A documentation address is inert — it is not an
 *     SSRF target and naming one is not deception — so it earns no signal.
 *  2. TRANSITION WRAPPERS (::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48,
 *     2001::/32 Teredo, 2002::/16 6to4). These prefixes are routing envelopes,
 *     not destination classes: what matters is the IPv4 inside them, which
 *     parse/ip.ts recovers for the low-32 wrappers and ip-classification.ts
 *     classifies directly. Bucketing the envelope itself would flag
 *     `[64:ff9b::808:808]` (NAT64 doing its ordinary job for public 8.8.8.8) as
 *     reserved. Unwrapping the remaining wrappers is tracked separately.
 *
 * Rows that map to NO BUCKET are still EMITTED, because longest-prefix-match
 * needs them: 192.0.0.9/32 and 192.0.0.10/32 (globally reachable) are carve-outs
 * INSIDE the non-global 192.0.0.0/24, and 2001::/32 is a carve-out inside
 * 2001::/23. A flat first-match list cannot express that; a null bucket at a
 * longer prefix can.
 *
 * NOT IN THESE REGISTRIES: multicast (224.0.0.0/4, ff00::/8) lives in the
 * separate IANA Multicast Address Space registries. It is added as an explicit
 * non-registry overlay in packages/core/src/data/ip-ranges.ts, alongside the
 * cloud-metadata overlay.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// ── Pinned sources ───────────────────────────────────────────────────────────
const SOURCE_V4 =
  "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv";
const SOURCE_V6 =
  "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv";
/** Snapshot date of the committed CSVs — stamped into dataVersions.ipRanges. */
const SNAPSHOT_DATE = "2026-07-25";
const VERSION_ID = `iana-special-purpose-${SNAPSHOT_DATE}`;

const __dirname = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT_V4 = resolve(__dirname, "data/iana-ipv4-special-registry-1.csv");
const SNAPSHOT_V6 = resolve(__dirname, "data/iana-ipv6-special-registry-1.csv");
const OUT_PATH = resolve(__dirname, "../packages/core/src/data/ip-ranges.generated.ts");

const args = process.argv.slice(2);
const checkOnly = args.includes("--check");
const doFetch = args.includes("--fetch");
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};
const inputV4 = flag("--input-v4");
const inputV6 = flag("--input-v6");

// ── CSV ──────────────────────────────────────────────────────────────────────
/**
 * RFC 4180 CSV reader. Both registries contain QUOTED FIELDS WITH EMBEDDED
 * NEWLINES (the multi-RFC citations), so a line-splitting parser silently
 * corrupts them — 26 real rows arrive as 27/28 raw lines.
 */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch !== '"') {
        field += ch;
      } else if (text[i + 1] === '"') {
        field += '"';
        i++;
      } else {
        quoted = false;
      }
      continue;
    }
    if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch !== "\r") field += ch;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c.trim() !== ""));
}

/**
 * Strip IANA footnote markers (`[1]`, `[2]`, …) and collapse the newlines that
 * quoted fields carry. Address blocks arrive as `192.0.0.0/24 [2]` and
 * `2002::/16 [3]`; `Globally Reachable` holds `False [1]` and `N/A [3]`, not
 * clean booleans. Only DIGIT-ONLY brackets are stripped, so `[RFC791]` and
 * `[RFC Errata 1752]` in the citation column survive intact.
 */
function clean(value) {
  return value
    .replace(/\[\d+\]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// ── Address parsing ──────────────────────────────────────────────────────────
/** `10.0.0.0/8` → { base: uint32, prefix: 8 }. */
function parseIpv4Cidr(cidr) {
  const [addr, len] = cidr.split("/");
  const octets = addr.split(".");
  if (octets.length !== 4) throw new Error(`bad IPv4 block: ${cidr}`);
  let base = 0;
  for (const o of octets) {
    const n = Number(o);
    if (!/^\d{1,3}$/.test(o) || n > 255) throw new Error(`bad IPv4 block: ${cidr}`);
    base = base * 256 + n;
  }
  const prefix = Number(len);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`bad IPv4 prefix: ${cidr}`);
  }
  base = base >>> 0;
  // The table's matcher assumes the base is prefix-aligned; an unaligned row
  // would silently never match part of its own range.
  const masked = prefix === 0 ? 0 : (base >>> (32 - prefix)) << (32 - prefix);
  if ((masked >>> 0) !== base) throw new Error(`IPv4 block not prefix-aligned: ${cidr}`);
  return { base, prefix };
}

/** `64:ff9b::/96` → { base: 8 hextets, prefix: 96 }. */
function parseIpv6Cidr(cidr) {
  const [addr, len] = cidr.split("/");
  const prefix = Number(len);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    throw new Error(`bad IPv6 prefix: ${cidr}`);
  }
  const groups = (s) => (s === "" ? [] : s.split(":").map((h) => parseInt(h, 16)));
  const gap = addr.indexOf("::");
  let base;
  if (gap < 0) {
    base = groups(addr);
  } else {
    const left = groups(addr.slice(0, gap));
    const right = groups(addr.slice(gap + 2));
    base = [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
  }
  if (base.length !== 8 || base.some((h) => !Number.isInteger(h) || h < 0 || h > 0xffff)) {
    throw new Error(`bad IPv6 block: ${cidr}`);
  }
  // Same alignment guard as IPv4, per hextet.
  for (let i = 0; i < 8; i++) {
    const bits = Math.min(16, Math.max(0, prefix - i * 16));
    const mask = bits === 0 ? 0 : (0xffff << (16 - bits)) & 0xffff;
    if ((base[i] & mask) !== base[i]) throw new Error(`IPv6 block not prefix-aligned: ${cidr}`);
  }
  return { base, prefix };
}

// ── Bucket mapping (see the header comment for the full rationale) ───────────
/** Registry NAMEs that are transition wrappers, not destination classes. */
const WRAPPER_NAMES = new Set([
  "ipv4-mapped address",
  "ipv4-ipv6 translat.",
  "teredo",
  "6to4",
]);

function bucketFor(name, globallyReachable) {
  const n = name.toLowerCase();
  if (n.startsWith("loopback")) return { bucket: "ip_loopback", why: "" };
  if (n === "private-use" || n === "unique-local") return { bucket: "ip_private", why: "" };
  if (n === "link local" || n === "link-local unicast") return { bucket: "ip_link_local", why: "" };
  if (n.startsWith("documentation")) return { bucket: null, why: "curated: documentation, inert" };
  if (WRAPPER_NAMES.has(n)) return { bucket: null, why: "curated: transition wrapper" };
  if (globallyReachable.toLowerCase() === "true") return { bucket: null, why: "globally reachable" };
  return { bucket: "ip_reserved", why: "" };
}

// ── Parse a registry into table rows ─────────────────────────────────────────
function parseRegistry(text, family) {
  const [header, ...records] = parseCsv(text);
  const col = (label) => {
    const i = header.findIndex((h) => clean(h).toLowerCase() === label);
    if (i < 0) throw new Error(`missing column '${label}' — source format may have changed`);
    return i;
  };
  const iBlock = col("address block");
  const iName = col("name");
  const iRfc = col("rfc");
  const iReach = col("globally reachable");

  const rows = [];
  for (const record of records) {
    const name = clean(record[iName] ?? "");
    const rfc = clean(record[iRfc] ?? "");
    const reach = clean(record[iReach] ?? "");
    const { bucket, why } = bucketFor(name, reach);
    // One cell may hold SEVERAL blocks ("192.0.0.170/32, 192.0.0.171/32").
    for (const block of clean(record[iBlock] ?? "").split(",")) {
      const cidr = block.trim();
      if (cidr === "") continue;
      const { base, prefix } =
        family === "v4" ? parseIpv4Cidr(cidr) : parseIpv6Cidr(cidr);
      rows.push({ cidr, base, prefix, bucket, name, rfc, why });
    }
  }
  if (rows.length === 0) throw new Error("no rows parsed — source format may have changed");

  // Longest-prefix-match by construction: a linear scan of this array returns
  // the most specific match first. Ties broken by base for a stable rendering.
  rows.sort((a, b) => {
    if (b.prefix !== a.prefix) return b.prefix - a.prefix;
    const ka = family === "v4" ? [a.base] : a.base;
    const kb = family === "v4" ? [b.base] : b.base;
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i];
    return 0;
  });
  return rows;
}

// ── Render ───────────────────────────────────────────────────────────────────
const hex8 = (n) => `0x${n.toString(16).padStart(8, "0")}`;

function renderRow(row, family) {
  const base =
    family === "v4"
      ? hex8(row.base)
      : `[${row.base.map((h) => `0x${h.toString(16)}`).join(", ")}]`;
  const bucket = row.bucket === null ? "null" : JSON.stringify(row.bucket);
  const trailer = row.why === "" ? row.cidr : `${row.cidr} — ${row.why}`;
  return (
    `  { base: ${base}, prefix: ${row.prefix}, bucket: ${bucket}, ` +
    `name: ${JSON.stringify(row.name)}, rfc: ${JSON.stringify(row.rfc)} }, // ${trailer}`
  );
}

function render(v4, v6, meta) {
  const bucketed = (rows) => rows.filter((r) => r.bucket !== null).length;
  return `// AUTO-GENERATED by tools/build-ip-ranges.mjs — DO NOT EDIT.
// Regenerate with: pnpm data:ip-ranges  (node tools/build-ip-ranges.mjs)
//
// Sources (IANA Special-Purpose Address Registries, snapshot ${SNAPSHOT_DATE}):
//   ${SOURCE_V4}
//   sha256: ${meta.sha4}  (${meta.bytes4} bytes, ${v4.length} ranges, ${bucketed(v4)} bucketed)
//   ${SOURCE_V6}
//   sha256: ${meta.sha6}  (${meta.bytes6} bytes, ${v6.length} ranges, ${bucketed(v6)} bucketed)
//
// The parsed snapshots are committed at tools/data/*.csv, so this file is
// byte-reproducible offline; ip-ranges.test.ts runs the --check drift guard.
//
// The digests above are taken over the COMMITTED snapshots, which are
// LF-normalized. IANA serves these files with CRLF row terminators, so a fresh
// download hashes differently — convert with \`tr -d '\\r'\` (or equivalent) before
// comparing. Normalizing is deliberate: this repo is LF-only (.gitattributes,
// plus a mixed-line-ending pre-commit hook whose --fix=auto would otherwise
// rewrite the LF newlines that appear INSIDE quoted CSV fields, corrupting the
// data). Row counts are identical either way.
//
// License: IANA registry data is public domain (no restrictions on reuse).
//
// Rows are sorted by DESCENDING prefix length: a linear scan returns the
// longest-prefix (most specific) match first. \`bucket: null\` is a real,
// load-bearing entry — a globally-reachable or curated-inert carve-out INSIDE a
// broader special-purpose block (192.0.0.9/32 inside 192.0.0.0/24, 2001::/32
// inside 2001::/23). See tools/build-ip-ranges.mjs for the bucket mapping.
//
// NOT INCLUDED: multicast (224.0.0.0/4, ff00::/8) is registered in the separate
// IANA Multicast Address Space registries; it is overlaid in ./ip-ranges.ts.

/** Version id stamped into dataVersions.ipRanges. */
export const IP_RANGES_VERSION = ${JSON.stringify(VERSION_ID)};

/** Range buckets a special-purpose block can map to (metadata is not one). */
export type IpRangeBucket = "ip_loopback" | "ip_link_local" | "ip_private" | "ip_reserved";

/** One IPv4 range. \`base\` is the network address as a uint32. */
export interface Ipv4RangeRow {
  readonly base: number;
  readonly prefix: number;
  /** null = matches, but earns NO bucket (carve-out). */
  readonly bucket: IpRangeBucket | null;
  readonly name: string;
  /** RFC citation, carried verbatim from the registry into the reason detail. */
  readonly rfc: string;
}

/** One IPv6 range. \`base\` is the network address as 8 hextets. */
export interface Ipv6RangeRow {
  readonly base: readonly number[];
  readonly prefix: number;
  /** null = matches, but earns NO bucket (carve-out). */
  readonly bucket: IpRangeBucket | null;
  readonly name: string;
  /** RFC citation, carried verbatim from the registry into the reason detail. */
  readonly rfc: string;
}

export const IPV4_SPECIAL_RANGES: readonly Ipv4RangeRow[] = [
${v4.map((r) => renderRow(r, "v4")).join("\n")}
];

export const IPV6_SPECIAL_RANGES: readonly Ipv6RangeRow[] = [
${v6.map((r) => renderRow(r, "v6")).join("\n")}
];
`;
}

async function download(url, dest) {
  process.stderr.write(`Fetching ${url} …\n`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
  const text = await res.text();
  writeFileSync(dest, text);
  return text;
}

async function main() {
  let raw4;
  let raw6;
  if (doFetch) {
    raw4 = await download(SOURCE_V4, SNAPSHOT_V4);
    raw6 = await download(SOURCE_V6, SNAPSHOT_V6);
  } else {
    raw4 = readFileSync(inputV4 ?? SNAPSHOT_V4, "utf8");
    raw6 = readFileSync(inputV6 ?? SNAPSHOT_V6, "utf8");
  }

  const v4 = parseRegistry(raw4, "v4");
  const v6 = parseRegistry(raw6, "v6");
  const out = render(v4, v6, {
    sha4: createHash("sha256").update(raw4).digest("hex"),
    sha6: createHash("sha256").update(raw6).digest("hex"),
    bytes4: Buffer.byteLength(raw4),
    bytes6: Buffer.byteLength(raw6),
  });

  if (checkOnly) {
    const current = readFileSync(OUT_PATH, "utf8");
    if (current !== out) {
      process.stderr.write("ip-ranges.generated.ts is STALE — re-run pnpm data:ip-ranges.\n");
      process.exit(1);
    }
    process.stderr.write(`OK — ${v4.length} IPv4 + ${v6.length} IPv6 ranges up to date.\n`);
    return;
  }

  writeFileSync(OUT_PATH, out);
  process.stderr.write(`Wrote ${v4.length} IPv4 + ${v6.length} IPv6 ranges to ${OUT_PATH}\n`);
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err}\n`);
  process.exit(1);
});
