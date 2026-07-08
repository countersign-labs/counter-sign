// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "./core/canonical.js";
import { verifyCountersignature, type VerifyOptions } from "./core/countersignature.js";
import { CountersignError } from "./core/errors.js";
import { toB64url } from "./core/keys.js";
import type { Countersignature, Intent, Resolution } from "./core/types.js";

/**
 * A place decisions are durably remembered. counter-sign never persists on its
 * own — hand a runtime one of these and every resolved Intent's receipts are
 * written where it is installed. Implement it over anything (a file, SQLite, a
 * log pipeline, a SIEM); the only contract is that `record` durably stores the
 * receipts it is given.
 */
export interface ReceiptSink {
  /** Durably record every receipt that produced a Resolution. */
  record(resolution: Resolution): Promise<void> | void;
}

/**
 * One line of a chained log: a receipt, its position, and a hash of the entry
 * before it. `prev` links every entry to its predecessor, so the sequence
 * cannot be reordered, and no entry inserted or removed, without breaking the
 * chain. The Countersignature inside is byte-for-byte the portable receipt —
 * the envelope is log metadata, never part of the signed artifact.
 */
export interface ChainEntry {
  /** zero-based position in the log */
  seq: number;
  /** base64url SHA-256 of the previous entry's canonical form; the genesis anchor for `seq` 0 */
  prev: string;
  /** the portable receipt this entry commits */
  receipt: Countersignature;
}

/** A checkpointed chain head — the length and tip hash you can anchor externally. */
export interface ChainHead {
  length: number;
  /** base64url SHA-256 of the last entry (or the genesis anchor for an empty log) */
  hash: string;
}

/** The result of walking the hash chain over the stored entries. */
export interface ChainReport {
  /** true when the chain is unbroken (and consistent with `expectedHead`, if given) */
  intact: boolean;
  length: number;
  /** first entry index where the chain breaks, if any */
  brokenAt?: number;
  reason?: "unchained-entry" | "bad-seq" | "broken-link" | "bad-genesis" | "truncated" | "diverged";
}

/** One problem found while re-verifying a stored receipt. */
export interface ReceiptFault {
  /** zero-based line index in the log */
  index: number;
  intent_id: string;
  actor: string;
  reason: "invalid-signature" | "untrusted-key" | "unknown-intent";
}

/** The result of re-verifying an entire ReceiptLog. */
export interface ReceiptLogReport {
  total: number;
  valid: number;
  faults: ReceiptFault[];
  /** completeness: the hash chain over the entries (edit / insert / reorder / delete evidence) */
  chain: ChainReport;
  /** true when every receipt verified AND the chain is intact */
  ok: boolean;
}

export interface VerifyAllOptions extends VerifyOptions {
  /**
   * The Intents these receipts are expected to decide. When supplied, every
   * receipt's `intent_id` must appear here — this is check (2) from the spec,
   * binding a receipt to its Intent; a receipt for an unknown Intent is faulted.
   */
  intents?: readonly Intent[];
  /**
   * A chain head captured earlier (see `head()`). Anchoring it externally is
   * how you detect *tail truncation*: a forward chain alone cannot tell that
   * the most recent entries were lopped off, because what remains is still
   * internally consistent. Checkpoint the head somewhere the operator cannot
   * quietly rewrite, and a shortened log is caught here.
   */
  expectedHead?: ChainHead;
}

/** The chain's genesis `prev`: a fixed, version-domain-separated anchor. */
const CHAIN_GENESIS = sha256b64url("countersign-receipt-chain-v0.1");

function sha256b64url(data: string): string {
  return toB64url(createHash("sha256").update(data, "utf8").digest());
}

/** The link hash of one entry: base64url SHA-256 over its canonical JSON. */
function linkHash(obj: unknown): string {
  return sha256b64url(canonicalize(obj));
}

function isChainEntry(o: unknown): o is ChainEntry {
  return (
    typeof o === "object" &&
    o !== null &&
    typeof (o as ChainEntry).seq === "number" &&
    typeof (o as ChainEntry).prev === "string" &&
    typeof (o as ChainEntry).receipt === "object" &&
    (o as ChainEntry).receipt !== null
  );
}

function isBareReceipt(o: unknown): o is Countersignature {
  return (
    typeof o === "object" &&
    o !== null &&
    typeof (o as Countersignature).decision === "string" &&
    typeof (o as Countersignature).signature === "string" &&
    typeof (o as Countersignature).intent_id === "string"
  );
}

/** Extract the portable receipt from a log line (chained entry or legacy bare receipt). */
function extractReceipt(obj: unknown): Countersignature {
  if (isChainEntry(obj)) return obj.receipt;
  if (isBareReceipt(obj)) return obj;
  throw new CountersignError("receipt log line is neither a chained entry nor a receipt");
}

interface ParsedLine {
  obj: unknown;
  /** link hash of this line, for chaining the next */
  hash: string;
}

/** Walk the chain; return the first break, or intact. Pure over parsed lines. */
function walkChain(lines: ParsedLine[], expectedHead?: ChainHead): ChainReport {
  let prev = CHAIN_GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const { obj, hash } = lines[i];
    if (!isChainEntry(obj)) return { intact: false, length: lines.length, brokenAt: i, reason: "unchained-entry" };
    if (obj.seq !== i) return { intact: false, length: lines.length, brokenAt: i, reason: "bad-seq" };
    if (obj.prev !== prev)
      return { intact: false, length: lines.length, brokenAt: i, reason: i === 0 ? "bad-genesis" : "broken-link" };
    prev = hash;
  }
  if (expectedHead) {
    if (lines.length < expectedHead.length)
      return { intact: false, length: lines.length, brokenAt: lines.length, reason: "truncated" };
    const at = lines[expectedHead.length - 1];
    const headHash = at ? at.hash : CHAIN_GENESIS;
    if (headHash !== expectedHead.hash)
      return { intact: false, length: lines.length, brokenAt: expectedHead.length - 1, reason: "diverged" };
  }
  return { intact: true, length: lines.length };
}

/**
 * An append-only, hash-chained, tamper-evident memory of decisions, stored
 * where the runtime is installed. Each line is the canonical JSON of a
 * {@link ChainEntry} — a receipt plus a hash of the entry before it — so the
 * file is a portable approval history that proves two distinct things offline,
 * with no trust in the process that wrote it:
 *
 *  1. **Authenticity** — every receipt is a genuine Countersignature
 *     (`verifyAll`, using the signatures).
 *  2. **Completeness** — the entries have not been edited, reordered, inserted,
 *     or deleted mid-stream (`verifyChain`, using the `prev` links).
 *
 * A forward chain cannot, by itself, detect that the *newest* entries were
 * truncated — what remains still links cleanly. Capture `head()` and anchor it
 * somewhere the operator cannot silently rewrite, then pass it as
 * `expectedHead` to catch truncation too.
 *
 * The log is opt-in. Pass one to `wrapAction({ receiptLog })` and every resolved
 * Intent — an approval, a veto, or a timeout Default — is recorded before the
 * guarded action runs. Omit it and counter-sign stays stateless.
 *
 * Write order within a process is preserved (writes are queued, so concurrent
 * records never interleave and each links onto the last). This is a
 * single-writer log: point separate processes at separate files, or put a real
 * store behind the ReceiptSink interface. Reading a file written by an older
 * (unchained) version still works; `verifyChain` reports such entries as
 * `unchained-entry`.
 */
export class ReceiptLog implements ReceiptSink {
  private tail: Promise<void> = Promise.resolve();
  private ensuredDir = false;
  /** in-memory chain head, lazily recovered from the file on first write */
  private headState?: { count: number; lastHash: string };

  constructor(public readonly filePath: string) {}

  /** Append a single receipt as one chained entry. */
  append(cs: Countersignature): Promise<void> {
    return this.write([cs]);
  }

  /**
   * Append every receipt that produced a Resolution — contiguously and in
   * order, each its own chained entry: the N approvals of a quorum, the single
   * veto, or the timeout Default. Rejections are recorded too; a blocked action
   * is part of the history, not an absence from it.
   */
  record(resolution: Resolution): Promise<void> {
    return resolution.countersignatures.length ? this.write(resolution.countersignatures) : Promise.resolve();
  }

  /**
   * Read every stored receipt, in write order. Returns `[]` if the log does not
   * exist yet. Throws if a line is corrupt — audit corruption is never silent.
   */
  async read(): Promise<Countersignature[]> {
    return (await this.parseLines()).map((l) => extractReceipt(l.obj));
  }

  /** Group stored receipts by the Intent they decide, preserving write order. */
  async history(): Promise<Map<string, Countersignature[]>> {
    const byIntent = new Map<string, Countersignature[]>();
    for (const cs of await this.read()) {
      const list = byIntent.get(cs.intent_id) ?? [];
      list.push(cs);
      byIntent.set(cs.intent_id, list);
    }
    return byIntent;
  }

  /** The current chain head — checkpoint it externally to detect later truncation. */
  async head(): Promise<ChainHead> {
    const lines = await this.parseLines();
    return { length: lines.length, hash: lines.length ? lines[lines.length - 1].hash : CHAIN_GENESIS };
  }

  /**
   * Verify completeness: walk the `prev` links and confirm the sequence has not
   * been edited, reordered, inserted into, or deleted from the middle. Pass a
   * previously-anchored `expectedHead` to also detect tail truncation. Returns a
   * report naming the first break rather than throwing.
   */
  async verifyChain(expectedHead?: ChainHead): Promise<ChainReport> {
    return walkChain(await this.parseLines(), expectedHead);
  }

  /**
   * Re-verify the whole log — both authenticity and completeness in one pass.
   * Every receipt's signature is checked; with `trustedKeys`, each must have
   * been signed by an authority you trust; with `intents`, each must decide one
   * of those Intents; and the hash chain is walked (optionally against
   * `expectedHead`). `ok` is true only when no receipt faulted AND the chain is
   * intact.
   */
  async verifyAll(opts: VerifyAllOptions = {}): Promise<ReceiptLogReport> {
    const knownIds = opts.intents ? new Set(opts.intents.map((i) => i.intent_id)) : undefined;
    const lines = await this.parseLines();
    const chain = walkChain(lines, opts.expectedHead);
    const faults: ReceiptFault[] = [];
    lines.forEach((line, index) => {
      const cs = extractReceipt(line.obj);
      let reason: ReceiptFault["reason"] | undefined;
      if (!verifyCountersignature(cs)) reason = "invalid-signature";
      else if (opts.trustedKeys !== undefined && !verifyCountersignature(cs, { trustedKeys: opts.trustedKeys }))
        reason = "untrusted-key";
      else if (knownIds && !knownIds.has(cs.intent_id)) reason = "unknown-intent";
      if (reason) faults.push({ index, intent_id: cs.intent_id, actor: cs.actor, reason });
    });
    return { total: lines.length, valid: lines.length - faults.length, faults, chain, ok: faults.length === 0 && chain.intact };
  }

  /** Read + parse every line into `{ obj, hash }`; throws loud on a corrupt line. */
  private async parseLines(): Promise<ParsedLine[]> {
    let text: string;
    try {
      text = await readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const out: ParsedLine[] = [];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      let obj: unknown;
      try {
        obj = JSON.parse(line);
      } catch {
        throw new CountersignError(`receipt log ${this.filePath} is corrupt at line ${i + 1}`);
      }
      out.push({ obj, hash: linkHash(obj) });
    }
    return out;
  }

  /**
   * Serialize writes through a promise chain so concurrent `append`/`record`
   * calls never interleave, and each entry links onto the one before it.
   */
  private write(receipts: Countersignature[]): Promise<void> {
    const run = this.tail.then(
      () => this.appendChained(receipts),
      () => this.appendChained(receipts),
    );
    // Keep the chain from staying rejected; each caller still sees its own error.
    this.tail = run.catch(() => {});
    return run;
  }

  private async appendChained(receipts: Countersignature[]): Promise<void> {
    if (!this.ensuredDir) {
      await mkdir(dirname(this.filePath), { recursive: true });
      this.ensuredDir = true;
    }
    const head = await this.ensureHead();
    let { count, lastHash } = head;
    let out = "";
    for (const receipt of receipts) {
      const entry: ChainEntry = { seq: count, prev: lastHash, receipt };
      const line = canonicalize(entry);
      out += line + "\n";
      lastHash = sha256b64url(line);
      count += 1;
    }
    await appendFile(this.filePath, out);
    this.headState = { count, lastHash };
  }

  /** Recover the chain head from the file once, so appends continue across restarts. */
  private async ensureHead(): Promise<{ count: number; lastHash: string }> {
    if (this.headState) return this.headState;
    const lines = await this.parseLines();
    this.headState = lines.length
      ? { count: lines.length, lastHash: lines[lines.length - 1].hash }
      : { count: 0, lastHash: CHAIN_GENESIS };
    return this.headState;
  }
}
