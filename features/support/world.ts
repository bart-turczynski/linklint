import { setWorldConstructor, World } from "@cucumber/cucumber";
import type { InspectResult } from "../../packages/core/src/index.js";
import type { ResponseStep } from "./resolution.js";
import type { TransportFixtureHarness } from "../../packages/online/src/testing/index.js";

/** Shared world: holds the input under inspection and the resulting verdict. */
export class LinklintWorld extends World {
  input = "";
  result!: InspectResult;
  /**
   * Layer 2 resolution acceptance state: the scripted hop responses and any
   * non-public DNS overrides collected by Given steps, plus the fixture harness
   * built by the When step (held so a scenario can assert it was exhausted).
   */
  hops: ResponseStep[] = [];
  resolveOverrides: Record<string, string> = {};
  harness?: TransportFixtureHarness;
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
