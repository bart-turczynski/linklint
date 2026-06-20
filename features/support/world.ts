import { setWorldConstructor, World } from "@cucumber/cucumber";
import type { InspectResult } from "../../packages/core/src/index.js";

/** Shared world: holds the input under inspection and the resulting verdict. */
export class LinklintWorld extends World {
  input = "";
  result!: InspectResult;
  /** Verdict obtained via the MCP tool (SC-3 scenarios). */
  mcpVerdict!: InspectResult;
  /** The agent's fetch decision derived from the MCP verdict. */
  willFetch = false;
  /**
   * No-policy baseline for the same input, captured by the policy steps so a
   * scenario can assert that configuring policy left `score`/`severity`
   * unchanged (the channel-separation invariant).
   */
  baseline?: InspectResult;
}

setWorldConstructor(LinklintWorld);
