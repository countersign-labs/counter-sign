// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "./core/canonical.js";
import { verifyCountersignature, type VerifyOptions } from "./core/countersignature.js";
import { CountersignError } from "./core/errors.js";
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

/** One problem found while re-verifying a stored receipt. */
export interface ReceiptFault {
  /** zero-based line index in the log */
  index: number;
  intent_id: string;
  actor: string;
  /** `invalid-signature` | `untrusted-key` | `unknown-intent` */
  reason: "invalid-signature" | "untrusted-key" | "unknown-intent";
}

/** The result of re-verifying an entire ReceiptLog. */
export interface ReceiptLogReport {
  total: number;
  valid: number;
  faults: ReceiptFault[];
  /** true when every stored receipt verified */
  ok: boolean;
}

export interface VerifyAllOptions extends VerifyOptions {
  /**
   * The Intents these receipts are expected to decide. When supplied, every
   * receipt's `intent_id` must appear here — this is check (2) from the spec,
   * binding a receipt to its Intent; a receipt for an unknown Intent is faulted.
   */
  intents?: readonly Intent[];
}

/**
 * An append-only, tamper-evident memory of decisions, stored where the runtime
 * is installed. Each line is the canonical JSON of one Countersignature, so the
 * file *is* a portable approval history: hand it to anyone and they can replay
 * and re-verify every decision offline, without trusting the process that wrote
 * it — the integrity lives in the signatures, not in the storage.
 *
 * The log is opt-in. Pass one to `wrapAction({ receiptLog })` and every resolved
 * Intent — an approval, a veto, or a timeout Default — is recorded before the
 * guarded action runs. Omit it and counter-sign stays stateless, exactly as
 * before.
 *
 * Write order within a process is preserved (writes are queued, so concurrent
 * records never interleave). This is not a cross-process database: point
 * separate processes at separate files, or put a real store behind the
 * ReceiptSink interface.
 */
export class ReceiptLog implements ReceiptSink {
  private tail: Promise<void> = Promise.resolve();
  private ensuredDir = false;

  constructor(public readonly filePath: string) {}

  /** Append a single receipt as one canonical JSON line. */
  append(cs: Countersignature): Promise<void> {
    return this.write(canonicalize(cs) + "\n");
  }

  /**
   * Append every receipt that produced a Resolution — contiguously and in
   * order: the N approvals of a quorum, the single veto, or the timeout
   * Default. Rejections are recorded too; a blocked action is part of the
   * history, not an absence from it.
   */
  record(resolution: Resolution): Promise<void> {
    const lines = resolution.countersignatures.map((cs) => canonicalize(cs) + "\n").join("");
    return lines ? this.write(lines) : Promise.resolve();
  }

  /**
   * Read every stored receipt, in write order. Returns `[]` if the log does not
   * exist yet. Throws if a line is corrupt — audit corruption is never silent.
   */
  async read(): Promise<Countersignature[]> {
    let text: string;
    try {
      text = await readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const out: Countersignature[] = [];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        out.push(JSON.parse(line) as Countersignature);
      } catch {
        throw new CountersignError(`receipt log ${this.filePath} is corrupt at line ${i + 1}`);
      }
    }
    return out;
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

  /**
   * Re-verify the whole log. Every receipt's signature is checked; with
   * `trustedKeys`, each must also have been signed by an authority you trust;
   * with `intents`, each must decide one of those Intents. Returns a report
   * rather than throwing, so a monitor can act on the faults it finds.
   */
  async verifyAll(opts: VerifyAllOptions = {}): Promise<ReceiptLogReport> {
    const knownIds = opts.intents ? new Set(opts.intents.map((i) => i.intent_id)) : undefined;
    const receipts = await this.read();
    const faults: ReceiptFault[] = [];
    receipts.forEach((cs, index) => {
      let reason: ReceiptFault["reason"] | undefined;
      if (!verifyCountersignature(cs)) reason = "invalid-signature";
      else if (opts.trustedKeys !== undefined && !verifyCountersignature(cs, { trustedKeys: opts.trustedKeys }))
        reason = "untrusted-key";
      else if (knownIds && !knownIds.has(cs.intent_id)) reason = "unknown-intent";
      if (reason) faults.push({ index, intent_id: cs.intent_id, actor: cs.actor, reason });
    });
    return { total: receipts.length, valid: receipts.length - faults.length, faults, ok: faults.length === 0 };
  }

  /**
   * Serialize writes through a promise chain so concurrent `append`/`record`
   * calls never interleave partial lines in the file, and land in call order.
   */
  private write(data: string): Promise<void> {
    const run = this.tail.then(
      () => this.writeRaw(data),
      () => this.writeRaw(data),
    );
    // Keep the chain from staying rejected; each caller still sees its own error.
    this.tail = run.catch(() => {});
    return run;
  }

  private async writeRaw(data: string): Promise<void> {
    if (!this.ensuredDir) {
      await mkdir(dirname(this.filePath), { recursive: true });
      this.ensuredDir = true;
    }
    await appendFile(this.filePath, data);
  }
}
