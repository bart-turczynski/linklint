import { describe, expect, it } from "vitest";
import { inspect } from "../src/index.js";

const codes = (input: string) => inspect(input).reasons.map((r) => r.code);
const detail = (input: string): string =>
  inspect(input).reasons.find((r) => r.code === "suspicious_extension")?.detail ?? "";

describe("I1 suspicious_extension — dangerous executable downloads", () => {
  it("a direct .exe download fires", () => {
    expect(codes("https://files.example.com/setup.exe")).toContain("suspicious_extension");
    expect(detail("https://files.example.com/setup.exe")).toContain(".exe");
  });

  it("a direct .scr download fires", () => {
    expect(codes("https://example.com/downloads/screensaver.scr")).toContain(
      "suspicious_extension",
    );
  });

  it("a deceptive double-extension .pdf.exe fires and is named as double", () => {
    const input = "https://cdn.evil.io/invoice.pdf.exe";
    expect(codes(input)).toContain("suspicious_extension");
    const d = detail(input);
    expect(d).toContain("double-extension");
    expect(d).toContain(".pdf.exe");
  });

  it("a double-extension .doc.scr fires", () => {
    expect(codes("https://evil.io/report.doc.scr")).toContain("suspicious_extension");
  });

  it("query/fragment are ignored (uses path only)", () => {
    expect(codes("https://example.com/setup.exe?ref=foo#top")).toContain("suspicious_extension");
    // a dangerous extension only in the query, not the path, does NOT fire
    expect(codes("https://example.com/page?file=setup.exe")).not.toContain("suspicious_extension");
  });

  it("scores >= medium on its own (weight 0.5)", () => {
    const r = inspect("https://files.example.com/setup.exe");
    expect(["medium", "high", "critical"]).toContain(r.severity);
  });
});

describe("I1 suspicious_extension — must not over-flag (SC-2)", () => {
  const benign = [
    "https://example.com/login", // ordinary page path, no extension
    "https://example.com/logo.png", // an image
    "https://github.com/x/archive/main.zip", // .zip archive is NOT dangerous
    "https://example.com/", // bare root, no segment
    "https://example.com", // empty path
    "https://example.com/files/", // trailing slash, extensionless segment
    "https://example.com/report.", // trailing dot, no real extension
    "https://example.com/exe/page", // extension-looking dir mid-path, last seg has none
  ];
  for (const input of benign) {
    it(`no suspicious_extension for ${JSON.stringify(input)}`, () => {
      expect(codes(input)).not.toContain("suspicious_extension");
    });
  }
});
