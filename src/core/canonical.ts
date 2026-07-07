// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

/**
/**
 * Bound on nesting depth. counter-sign envelopes are shallow; this only exists
 * so a hostile, deeply-nested object handed to a verifier cannot blow the
 * stack (a denial-of-service). Verifiers treat the resulting throw as "invalid".
 */
const MAX_DEPTH = 64;

/**
 * Canonical JSON serialization used for all counter-sign signatures:
 * object keys sorted lexicographically at every depth, no insignificant
 * whitespace, UTF-8 bytes. `undefined` members are omitted; non-finite
 * numbers are rejected. This is what gets signed — both sides must
 * produce byte-identical output for the same value.
 */
export function canonicalize(value: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) throw new RangeError("cannot canonicalize: value nested too deeply");
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("cannot canonicalize non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((v) => canonicalize(v === undefined ? null : v, depth + 1)).join(",")}]`;
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record)
        .filter((k) => record[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(record[k], depth + 1)}`).join(",")}}`;
    }
    default:
      throw new TypeError(`cannot canonicalize value of type ${typeof value}`);
  }
}
