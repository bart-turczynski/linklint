import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Unit + corpus tests live colocated in the core package and under tests/.
    include: ["packages/**/test/**/*.test.ts", "tests/**/*.test.ts"],
    environment: "node",
  },
});
