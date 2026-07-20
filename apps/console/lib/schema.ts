// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Render-safe validation of on-disk records.
//
// A signed policy/registry/receipt record is NOT fully schema-checked by the library:
// verifyChain authenticates signatures + chain links and validates REQUIRED fields, but
// OPTIONAL string fields (admin-add `name`, role `description`), the envelope, and registry
// record shape can still hold a non-string. Casting such a record through a TypeScript
// interface and rendering it throws "Objects are not valid as a React child" and 500s the
// whole page — past the fault banner. These guards let the loaders keep only render-safe
// values and turn anything malformed into a reported fault instead of a crash.

/** Extract a human-readable message from a caught error. Shared so fault text stays consistent
 *  across the write path, the store, and the audit loader. */
export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export const isStr = (x: unknown): x is string => typeof x === "string";
export const isOptStr = (x: unknown): x is string | undefined => x === undefined || typeof x === "string";
export const isStrArray = (x: unknown): x is string[] => Array.isArray(x) && x.every(isStr);
export const isFiniteNum = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x);

/** Every field the Admins page / admin form reads must be a string (name is optional). */
export function isRenderSafeAdmin(a: unknown): boolean {
  const o = a as Record<string, unknown> | null;
  return !!o && isStr(o.public_key) && isOptStr(o.name);
}

/** Every field the Roles page / role forms read. */
export function isRenderSafeRole(r: unknown): boolean {
  const o = r as Record<string, unknown> | null;
  return !!o && isStr(o.id) && isStr(o.name) && isStrArray(o.members) && isOptStr(o.description);
}

/** Every field the Rules page reads. */
export function isRenderSafeRule(r: unknown): boolean {
  const o = r as Record<string, unknown> | null;
  return (
    !!o &&
    isStr(o.id) &&
    isStr(o.name) &&
    isStrArray(o.roles) &&
    isFiniteNum(o.quorum) &&
    (o.default === "approve" || o.default === "reject") &&
    isFiniteNum(o.timeout_seconds) &&
    isOptStr(o.action) &&
    isOptStr(o.risk_tier)
  );
}

/** Every field the Approvers page reads (actor label + fingerprints of the keys). */
export function isRenderSafeApprover(a: unknown): boolean {
  const o = a as { actor?: unknown; keys?: unknown } | null;
  return !!o && isStr(o.actor) && isStrArray(o.keys);
}
