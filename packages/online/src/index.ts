/**
 * Explicit Node/server online capabilities for linklint.
 *
 * The package root owns public online configuration, consent, source metadata,
 * and composition APIs (see docs/online-runtime-boundary.md). It ships the
 * blocking online-source contract (M2) that every provider adapter must declare
 * and satisfy. Concrete transport, resolution, and provider capabilities live
 * under their own subpaths. Importing this package has no side effects and
 * performs no network I/O.
 */

export * from "./sources/index.js";
