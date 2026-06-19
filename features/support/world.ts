import { setWorldConstructor, World } from "@cucumber/cucumber";
import type { InspectResult } from "../../packages/core/src/index.js";

/** Shared world: holds the input under inspection and the resulting verdict. */
export class LinklintWorld extends World {
  input = "";
  result!: InspectResult;
}

setWorldConstructor(LinklintWorld);
