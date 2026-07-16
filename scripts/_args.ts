// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// Shared CLI argument helpers for the counter-sign scripts, so `--flag value`
// parsing and error-exit behaviour stay identical across every command.

/**
 * The value after `--name` on argv (verbatim — base64url ed25519 keys CAN start with
 * "--", so the value is NOT filtered by prefix), or undefined if the flag is absent or
 * is the last token. A caller that must distinguish "flag present but valueless" from
 * "flag absent" uses has() alongside this (e.g. `has("x") && arg("x") === undefined`).
 */
export function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

/** True iff the boolean flag `--name` is present. */
export function has(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

/** Print a message to stderr and exit with `code` (default 1). */
export function die(msg: string, code = 1): never {
  process.stderr.write(msg + "\n");
  process.exit(code);
}
