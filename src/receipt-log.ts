// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "./core/canonical.js";
import { normalizeActor, verifyCountersignature, type VerifyOptions } from "./core/countersignature.js";
import { DEFAULT_TIMEOUT_ACTOR } from "./core/defaults.js";
import { assertIntentInvariants, verifyIntent } from "./core/intent.js";
import { isWebAuthnCredential } from "./core/webauthn.js";
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
 * before it. `prev` links every entry to its predecessor. The chain is KEYLESS
 * (plain SHA-256, no secret), so it detects accidental corruption and naive
 * edits — but a writer who tampers can recompute every downstream `prev` and
 * produce an intact-looking chain. Real tamper-evidence comes only from
 * verifying against an externally-anchored `head()` (see the class doc). The
 * Countersignature inside is byte-for-byte the portable receipt — the envelope
 * is log metadata, never part of the signed artifact.
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
  reason: "invalid-signature" | "untrusted-key" | "unknown-intent" | "unverified-intent" | "missing-webauthn-policy" | "malformed";
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
   * Optional allowlist of agent public keys whose Intents you trust. When set, a
   * supplied Intent is only used for its approver bindings if its agent key is in
   * this set — so an attacker cannot slip in a self-consistent Intent signed by an
   * agent key you never authorized. Independent of the Intent's own signature check.
   */
  trustedAgentKeys?: readonly string[];
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
    // receipt must be a Countersignature-shaped object, not an array or garbage
    isBareReceipt((o as ChainEntry).receipt)
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
 * An append-only, hash-chained memory of decisions, stored where the runtime is
 * installed. Each line is the canonical JSON of a {@link ChainEntry} — a receipt
 * plus a hash of the entry before it. It gives two DIFFERENT guarantees, and it
 * is important not to conflate them:
 *
 *  1. **Authenticity (keyed, standalone).** Every receipt is a genuine
 *     Countersignature — `verifyAll` checks each ed25519 signature against the
 *     trusted authority key. This holds with no trust in the writer, because the
 *     signatures are keyed: a forged/altered receipt fails, full stop.
 *  2. **Completeness (relative to an anchor).** `verifyChain` walks the `prev`
 *     links. The chain is KEYLESS, so on its own it catches accidental
 *     corruption and lazy edits but NOT a deliberate rewrite: a writer can
 *     recompute every downstream hash and pass `verifyChain`. Real
 *     tamper-evidence requires capturing `head()` and anchoring it somewhere the
 *     writer cannot reach, then verifying against it (`expectedHead`) — that
 *     catches any edit, reorder, insertion, deletion, or truncation at/below the
 *     anchor (`diverged`/`truncated`). Do NOT market this log as standalone
 *     tamper-evident; the anchor is the mechanism. (A keyed, self-anchoring
 *     chain — a signed head per append — is a roadmap item.)
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
    // An Intent's approver bindings are only a trust anchor if the Intent ITSELF
    // authenticates — otherwise a tampered archived Intent (approver key swapped,
    // signature now invalid) would let a fake receipt signed by the replacement key
    // read as valid. Keep only Intents whose invariants hold AND whose agent
    // signature verifies (and, if pinned, whose agent key is trusted). A supplied
    // Intent that fails is dropped so its receipts fault as `unverified-intent`
    // rather than being checked against attacker-chosen bindings.
    let intentsById: Map<string, Intent> | undefined;
    const unverifiedIntentIds = new Set<string>();
    if (opts.intents) {
      intentsById = new Map();
      for (const i of opts.intents) {
        let authentic = false;
        try {
          assertIntentInvariants(i);
          authentic = verifyIntent(i) && (!opts.trustedAgentKeys || opts.trustedAgentKeys.includes(i.agent?.public_key));
        } catch {
          authentic = false;
        }
        if (authentic) intentsById.set(i.intent_id, i);
        else if (typeof i?.intent_id === "string") unverifiedIntentIds.add(i.intent_id);
      }
    }
    const lines = await this.parseLines();
    const chain = walkChain(lines, opts.expectedHead);
    const faults: ReceiptFault[] = [];
    lines.forEach((line, index) => {
      let cs: Countersignature;
      try {
        cs = extractReceipt(line.obj);
      } catch {
        // A line that is neither a chained entry nor a receipt is a fault to
        // REPORT, not an exception that aborts the whole audit.
        faults.push({ index, intent_id: "", actor: "", reason: "malformed" });
        return;
      }
      let reason: ReceiptFault["reason"] | undefined;
      // (1) Integrity: the receipt verifies under its own embedded key (or, for a
      // passkey receipt, the WebAuthn assertion — needs the RP policy or it fails closed).
      // A passkey receipt with no policy supplied CANNOT be verified — report that
      // distinctly rather than as `invalid-signature`, so an audit that simply forgot
      // to pass `webauthn` doesn't read as a tamper alarm on untampered receipts.
      if (isWebAuthnCredential(cs.public_key) && !opts.webauthn) reason = "missing-webauthn-policy";
      else if (!verifyCountersignature(cs, { webauthn: opts.webauthn })) reason = "invalid-signature";
      else {
        const intent = intentsById?.get(cs.intent_id);
        if (intentsById && !intent) {
          // A receipt whose Intent was supplied but did NOT authenticate faults as
          // `unverified-intent`; one whose Intent was never supplied is `unknown-intent`.
          reason = unverifiedIntentIds.has(cs.intent_id) ? "unverified-intent" : "unknown-intent";
        } else if (intent) {
          // (2) Bind the receipt to the Intent's approver — a KEYED receipt must be
          // signed by THAT actor's own bound key, not merely a globally-trusted key
          // (else one trusted approver could forge another's receipt). A vouched
          // approver, or the canonical timeout Default, must be authority-signed. An
          // explicit receipt from an actor NOT in the Intent is a fault outright.
          const approver = intent.approvers.find((a) => normalizeActor(a.actor) === normalizeActor(cs.actor));
          const isTimeoutDefault = cs.policy === "default" && normalizeActor(cs.actor) === DEFAULT_TIMEOUT_ACTOR;
          if (approver && cs.policy !== "approver") {
            // A named approver's receipt is always an "approver" decision. A "default"
            // (or other) policy on it is the timeout-Default label smuggled onto a human
            // slot — verifyResolution rejects exactly this, so the audit must too.
            reason = "untrusted-key";
          } else if (approver?.mode === "keyed") {
            if (!verifyCountersignature(cs, { trustedKeys: approver.public_key, webauthn: opts.webauthn })) reason = "untrusted-key";
          } else if (approver || isTimeoutDefault) {
            if (opts.trustedKeys !== undefined && !verifyCountersignature(cs, { trustedKeys: opts.trustedKeys, webauthn: opts.webauthn })) reason = "untrusted-key";
          } else {
            reason = "untrusted-key"; // actor is not an approver of this Intent
          }
        } else if (opts.trustedKeys !== undefined && !verifyCountersignature(cs, { trustedKeys: opts.trustedKeys, webauthn: opts.webauthn })) {
          // No Intents supplied → fall back to the global trusted-set check.
          reason = "untrusted-key";
        }
      }
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
