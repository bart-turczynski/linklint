/**
 * LINK-geygvedm — contract tests for `tools/check-release-version.mjs`, the gate
 * standing in front of the one irreversible job in `.gitlab-ci.yml`.
 *
 * WHAT IS PINNED. Not the filesystem walk, which has nothing to decide, but the
 * decision: that a tag and the manifests must agree, that the four packages must
 * agree with each other, and that neither failure can be rendered as a pass.
 * npm versions are immutable, so every case below is one a release cannot
 * recover from after the fact.
 */
import { describe, expect, it } from "vitest";
// @ts-expect-error — plain ESM tool script, deliberately dependency-free so the
// release gate runs on bare `node` before any install has happened.
import { checkReleaseVersion, readManifests, versionFromTag } from "../../tools/check-release-version.mjs";

const at = (version: string) => [
  { name: "linklint", version },
  { name: "@linklint/cli", version },
  { name: "@linklint/mcp", version },
  { name: "@linklint/online", version },
];

describe("versionFromTag", () => {
  it("strips a leading v", () => {
    expect(versionFromTag("v1.2.3")).toBe("1.2.3");
  });

  it("accepts a bare version", () => {
    expect(versionFromTag("1.2.3")).toBe("1.2.3");
  });

  it("strips only the first v, so a prerelease tag survives intact", () => {
    expect(versionFromTag("v0.1.0-dev.0")).toBe("0.1.0-dev.0");
  });
});

describe("checkReleaseVersion", () => {
  it("passes when the tag and every manifest agree", () => {
    const { code, message } = checkReleaseVersion("v1.2.3", at("1.2.3"));
    expect(code).toBe(0);
    expect(message).toContain("all 4 packages at 1.2.3");
  });

  it("fails when the tag names a version the manifests do not carry", () => {
    // The failure this prevents: `v0.2.0` publishes 0.1.0, and the tag then
    // names a release that does not exist at the registry.
    expect(checkReleaseVersion("v0.2.0", at("0.1.0")).code).toBe(1);
  });

  it("fails when the packages are not in lockstep, naming the offender", () => {
    // The failure this prevents is the worse of the two: pnpm rewrites
    // `workspace:*` at pack time, so a lagging dependent ships pinned to a
    // `linklint` version that was never published, and the install breaks for
    // everyone until a new release goes out.
    const drifted = [...at("1.2.3").slice(0, 3), { name: "@linklint/online", version: "1.2.2" }];
    const { code, message } = checkReleaseVersion("v1.2.3", drifted);
    expect(code).toBe(1);
    expect(message).toContain("! @linklint/online 1.2.2");
    expect(message).not.toContain("! linklint 1.2.3");
  });

  it("reports 2, not 0, when there is no tag to check against", () => {
    // "could not check" must never read as "all clear" — the same three-way
    // convention as check-upstream.ts and audit-dependencies.ts.
    expect(checkReleaseVersion("", at("1.2.3")).code).toBe(2);
  });

  it("reports 2, not 0, when no manifests were found", () => {
    expect(checkReleaseVersion("v1.2.3", []).code).toBe(2);
  });
});

describe("the shipped workspace", () => {
  it("is in lockstep, so it is taggable as it stands", () => {
    const manifests = readManifests();
    expect(manifests).toHaveLength(4);
    const versions = new Set(manifests.map((m: { version: string }) => m.version));
    expect([...versions]).toHaveLength(1);
  });
});
