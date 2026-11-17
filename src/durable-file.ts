// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

/**
 * Small file helpers shared by every append-only JSONL file counter-sign keeps
 * (the receipt log, its Intent sidecar, the pending-decision store):
 *
 *  - `durableAppend` writes whole lines and flushes them to stable storage
 *    (`fdatasync`) before it resolves, so nothing is acted on that a power cut
 *    could still take back. The first write to a new file also flushes its
 *    directory, so the file itself survives.
 *  - `repairTornTail` handles the one thing a crash in mid-append can leave
 *    behind: a last line with no newline. A whole entry that only lost its
 *    newline gets the newline back. Anything else is moved, byte for byte, into
 *    a quarantine file next to the log, and the log is cut back to its last whole
 *    line. A bad line in the MIDDLE is never touched here; that stays a hard
 *    fault for the reader to report. Only the single writer of a file may call
 *    it, from its write path (it truncates the file): a reader never repairs,
 *    it only reports what `splitTornTail` finds.
 */

import { createHash } from "node:crypto";
import { mkdir, open, readFile, stat, truncate } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "./core/canonical.js";
import { toB64url } from "./core/keys.js";

/** What `repairTornTail` moved aside. Also the shape of one quarantine-file line (plus `bytes_b64`). */
export interface TornTail {
  /** zero-based line index the torn bytes would have been (the count of whole lines before them) */
  line: number;
  /** byte offset in the file where the torn bytes started (the file was cut back to here) */
  offset: number;
  /** number of bytes moved aside */
  length: number;
  /** the intent_id the torn bytes mention, when one can be read from them; "" otherwise */
  intent_id: string;
}

/** One line of a quarantine file. */
export interface QuarantineRecord extends TornTail {
  /** when the repair ran (ISO 8601) */
  repaired_at: string;
  /** base64url SHA-256 of the moved bytes */
  sha256: string;
  /** the moved bytes, base64 */
  bytes_b64: string;
}

/** Flush a directory entry (best effort: some platforms cannot open or fsync a directory). */
export async function syncDir(dir: string): Promise<void> {
  let fh;
  try {
    fh = await open(dir, "r");
    await fh.sync();
  } catch {
    // Windows and some network filesystems refuse; the file data itself is still flushed.
  } finally {
    await fh?.close().catch(() => {});
  }
}

/**
 * Append `data` (whole, newline-terminated lines) to `path`, creating the file
 * and its directory if needed. With `fsync`, the data is flushed with
 * `fdatasync` before this resolves, and a newly created file's directory is
 * flushed too. Any error (including a failed flush) rejects.
 */
export async function durableAppend(path: string, data: string, fsync: boolean): Promise<void> {
  let created = false;
  if (fsync) {
    try {
      await stat(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      created = true;
    }
  }
  await mkdir(dirname(path), { recursive: true });
  const fh = await open(path, "a");
  try {
    await fh.writeFile(data, "utf8");
    if (fsync) await fh.datasync();
  } finally {
    await fh.close();
  }
  if (created) await syncDir(dirname(path));
}

/** Best-effort intent_id from torn bytes (the field may be cut, so a regex, not JSON). */
function intentIdIn(text: string): string {
  return /"intent_id"\s*:\s*"([0-9a-fA-F-]{36})"/.exec(text)?.[1] ?? "";
}

function isWholeObject(text: string): boolean {
  try {
    const v = JSON.parse(text);
    return typeof v === "object" && v !== null && !Array.isArray(v);
  } catch {
    return false;
  }
}

/**
 * Repair a torn last line in an append-only JSONL file. Returns what was moved
 * aside, or null when nothing was (no file, a clean file, or a whole last entry
 * that only lacked its newline, which is completed in place).
 *
 * Order matters for crash safety: the quarantine record is written and flushed
 * BEFORE the log is cut, so a crash between the two leaves the bytes in both
 * places (the next repair records them again), never in neither.
 */
export async function repairTornTail(path: string, quarantinePath: string, fsync: boolean): Promise<TornTail | null> {
  let buf: Buffer;
  try {
    buf = await readFile(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const cut = buf.lastIndexOf(0x0a) + 1; // 0 when there is no newline at all
  const tail = buf.subarray(cut);
  const text = tail.toString("utf8");
  if (text.trim() === "") return null;
  if (isWholeObject(text)) {
    // The entry is complete; only its newline was lost. Finish the line.
    await durableAppend(path, "\n", fsync);
    return null;
  }
  const head = buf.subarray(0, cut).toString("utf8");
  const line = head.split("\n").filter((l) => l.trim() !== "").length;
  const torn: TornTail = { line, offset: cut, length: tail.length, intent_id: intentIdIn(text) };
  const record: QuarantineRecord = {
    ...torn,
    repaired_at: new Date().toISOString(),
    sha256: toB64url(createHash("sha256").update(tail).digest()),
    bytes_b64: tail.toString("base64"),
  };
  await durableAppend(quarantinePath, canonicalize(record) + "\n", fsync);
  await truncate(path, cut);
  if (fsync) {
    const fh = await open(path, "r+");
    try {
      await fh.datasync();
    } finally {
      await fh.close();
    }
  }
  return torn;
}

/** Read every record in a quarantine file ([] if there is none). Unreadable lines are skipped. */
export async function readQuarantine(quarantinePath: string): Promise<QuarantineRecord[]> {
  let text: string;
  try {
    text = await readFile(quarantinePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const out: QuarantineRecord[] = [];
  for (const l of text.split("\n")) {
    if (!l.trim()) continue;
    try {
      out.push(JSON.parse(l) as QuarantineRecord);
    } catch {
      // A torn quarantine line is itself a crash leftover; skip it rather than block the audit.
    }
  }
  return out;
}

/**
 * Split JSONL text into its whole lines. A last segment with no newline that does
 * not parse is an append still in flight (or a crash leftover not yet repaired),
 * so it is left out rather than reported as corruption; every other line is
 * returned for the caller to parse strictly.
 */
export function wholeLines(text: string): string[] {
  return splitTornTail(Buffer.from(text, "utf8")).lines;
}

/**
 * Split a JSONL file's bytes into its lines and, separately, a torn last
 * segment: one with no newline that is not a whole JSON object. READ ONLY: this
 * never changes the file. The torn segment is described as `repairTornTail`
 * would describe it, so a reader can report what a writer would later move.
 */
export function splitTornTail(buf: Buffer): { lines: string[]; torn?: TornTail } {
  const cut = buf.lastIndexOf(0x0a) + 1; // 0 when there is no newline at all
  const tail = buf.subarray(cut).toString("utf8");
  const head = buf.subarray(0, cut).toString("utf8");
  if (tail.trim() === "" || isWholeObject(tail)) return { lines: (head + tail).split("\n") };
  const lines = head.split("\n");
  const line = lines.filter((l) => l.trim() !== "").length;
  return { lines, torn: { line, offset: cut, length: buf.length - cut, intent_id: intentIdIn(tail) } };
}

/**
 * Give a whole last entry its lost newline, and nothing else: if the file does
 * not end with a newline, its last segment parses as a whole JSON object, and
 * `accept` says that object is the entry the caller expects there (it gets the
 * object and the parsed line before it, or undefined when there is none), append
 * "\n" (flushed with `fsync`) and return true. Otherwise the file is left
 * exactly as it is (false). Never truncates, never moves anything. For a
 * writer's append path only, never a read.
 */
export async function completeLastLine(
  path: string,
  fsync: boolean,
  accept: (last: unknown, before: unknown) => boolean,
): Promise<boolean> {
  if (await endsClean(path)) return false;
  const buf = await readFile(path);
  const cut = buf.lastIndexOf(0x0a);
  const tail = buf.subarray(cut + 1).toString("utf8");
  if (tail.trim() === "" || !isWholeObject(tail)) return false;
  let before: unknown;
  if (cut >= 0) {
    const lines = buf.subarray(0, cut).toString("utf8").split("\n").filter((l) => l.trim() !== "");
    if (lines.length) {
      try {
        before = JSON.parse(lines[lines.length - 1]);
      } catch {
        return false;
      }
    }
  }
  if (!accept(JSON.parse(tail), before)) return false;
  await durableAppend(path, "\n", fsync);
  return true;
}

/**
 * True when the file is missing, empty, or ends with a newline: nothing torn is
 * at its end, so an append can go straight on. One small read, for the writer's
 * check before each append.
 */
export async function endsClean(path: string): Promise<boolean> {
  let fh;
  try {
    fh = await open(path, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw err;
  }
  try {
    const { size } = await fh.stat();
    if (size === 0) return true;
    const last = Buffer.alloc(1);
    await fh.read(last, 0, 1, size - 1);
    return last[0] === 0x0a;
  } finally {
    await fh.close();
  }
}
