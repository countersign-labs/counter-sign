// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// Shared CLI argument helpers for the counter-sign scripts, so `--flag value`
// parsing and error-exit behaviour stay identical across every command.

/**
 * The value after `--name` on argv, or undefined if the flag is absent OR its value is
 * missing. A missing value is one where the next token is itself a `--flag` (or argv
 * ends), so `--actor --decision approve` does not silently read "--decision" as the
 * actor. (These CLIs' values — keys, paths, actors, decisions — never start with `--`.)
 */
export function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const value = process.argv[i + 1];
  return value === undefined || value.startsWith("--") ? undefined : value;
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
