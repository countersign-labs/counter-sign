// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalize } from "./core/canonical.js";
import { normalizeActor, verifyCountersignature, type VerifyOptions } from "./core/countersignature.js";
import { DEFAULT_TIMEOUT_ACTOR, deadline } from "./core/defaults.js";
import { assertIntentInvariants, quorumOf, verifyIntent } from "./core/intent.js";
import { credentialKeyMaterial, isValidCredentialDescriptor, isWebAuthnCredential } from "./core/webauthn.js";
import { CountersignError } from "./core/errors.js";
import { isCanonicalPublicKey, toB64url } from "./core/keys.js";
import { completeLastLine, durableAppend, endsClean, readQuarantine, repairTornTail, splitTornTail, wholeLines, type TornTail } from "./durable-file.js";
import type { Approver, Countersignature, Intent, Resolution } from "./core/types.js";

/**
 * A place decisions are durably remembered. counter-sign never persists on its
 * own — hand a runtime one of these and every resolved Intent's receipts are
 * written where it is installed. Implement it over anything (a file, SQLite, a
 * log pipeline, a SIEM); the only contract is that `record` durably stores the
 * receipts it is given.
 */
export interface ReceiptSink {
  /**
   * Durably record every receipt that produced a Resolution. `intent` is the
   * Intent they decide; the runtime passes it so a sink that keeps Intents (see
   * `ReceiptLogOptions.intents`) can store it. A sink may ignore it.
   */
  record(resolution: Resolution, intent?: Intent): Promise<void> | void;
}

/**
 * Where the signed Intents behind a log's receipts are kept. A vouched receipt
 * binds only an `intent_id`, so auditing it later needs the Intent it decides;
 * the receipt log itself stores receipts only. Implement it over anything; the
 * contract is that `put` durably stores the Intent before it resolves, and never
 * lets one `intent_id` be rebound to different content.
 */
export interface IntentStore {
  /** Durably store an Intent. Idempotent for the same Intent; rejects a different Intent under a stored id. */
  put(intent: Intent): Promise<void>;
  get(intentId: string): Promise<Intent | undefined>;
  /** Every stored Intent, in the order first stored. */
  all(): Promise<Intent[]>;
}

/** Options for a file-backed {@link ReceiptLog}. Every option keeps the receipts file format unchanged. */
export interface ReceiptLogOptions {
  /**
   * Flush each append to stable storage (`fdatasync`) before `record()` resolves,
   * so an approval the runtime acts on is already on disk. Default true. Turn it
   * off only for tests and throwaway logs.
   */
  fsync?: boolean;
  /**
   * Opt in to handling a torn last line (a line with no newline that does not
   * parse, left by a crash in mid-append, or an append still being written).
   * Default false: a torn last line makes reads and writes throw, exactly as in
   * 0.2.0.
   *
   * With true, reads skip it and `verifyAll` reports it in `tornTails` (`ok`
   * false), WITHOUT changing the file: a reader never writes. Only this
   * instance's own appends repair: before each append, a torn end is moved into
   * `<file>.quarantine.jsonl` and the log is cut back to its last whole line, so
   * set it on the log's single writer (and on any auditor that should report
   * rather than throw). A bad line in the middle of the file is never repaired;
   * it stays a hard fault.
   */
  repairTornTail?: boolean;
  /**
   * Keep each Intent beside its receipts, so `verifyAll` can audit vouched
   * receipts and timeout Defaults without being handed the Intents. `true` uses
   * a sidecar file, `<file>.intents.jsonl` (one canonical Intent per line,
   * flushed like the log). Or pass any {@link IntentStore}. Off by default.
   */
  intents?: boolean | IntentStore;
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
  reason: "invalid-signature" | "untrusted-key" | "unknown-intent" | "unverified-intent" | "missing-webauthn-policy" | "missing-authority-key" | "malformed";
}

/**
 * A torn last line, as `verifyAll` reports it in {@link ReceiptLogReport.tornTails}.
 * It is not one of the stored entries: the bytes never made a whole line, so a
 * `record()` that wrote them either has not resolved yet or failed, and nothing
 * should have acted on them. It stays reported until the quarantine file is
 * reviewed and archived.
 */
export interface TornTailReport {
  /** zero-based line index the torn bytes would have been */
  index: number;
  /** the intent_id the torn bytes mention, when one can be read from them; "" otherwise */
  intent_id: string;
  /** byte offset in the log where the torn bytes start (or started, before they were moved) */
  offset: number;
  /** number of torn bytes */
  length: number;
  /**
   * true: moved into `<file>.quarantine.jsonl` by the writer. false: still at the
   * end of the log, either a crash leftover the writer has not met yet or an
   * append still being written (look again: it then becomes a whole line).
   */
  quarantined: boolean;
}

/** The result of re-verifying an entire ReceiptLog. */
export interface ReceiptLogReport {
  total: number;
  valid: number;
  faults: ReceiptFault[];
  /** completeness: the hash chain over the entries (edit / insert / reorder / delete evidence) */
  chain: ChainReport;
  /** true when every receipt verified AND the chain is intact (and, when reported, there are no torn tails) */
  ok: boolean;
  /**
   * Torn last lines: the ones moved into quarantine, and one still at the end of
   * the file. Present only when the log opted into `repairTornTail`, or when its
   * quarantine file holds records; otherwise absent, so a report is shaped
   * exactly as in 0.2.0. Any entry makes `ok` false.
   */
  tornTails?: TornTailReport[];
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
   * The runtime authority public key(s) — THE anchor for every authority-signed receipt
   * (vouched approvals and the timeout Default) and for the keyed-slot separation-of-duty
   * check, exactly as verifyResolution's expectedAuthorityPublicKey. Dedicated and
   * distinct from `trustedKeys` (a general allowlist that may legitimately hold approver
   * keys). Supply it to audit authority-signed receipts: WITHOUT it, a vouched/Default
   * receipt cannot be verified and faults as `missing-authority-key` (honest — not
   * silently valid, not a tamper alarm). Pass an ARRAY to audit a log that spans an
   * authority-key rotation (a receipt is accepted if signed by ANY listed key). Each must
   * be canonical ed25519. Only meaningful WITH `intents` — supplying it alone throws.
   */
  authorityKey?: string | readonly string[];
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

/** True when `last` is the entry `head` was taken from: its seq, its hash, and its link to `before`. */
function isHeadEntry(last: unknown, before: unknown, head: { count: number; lastHash: string }): boolean {
  if (!isChainEntry(last) || head.count < 1) return false;
  if (last.seq !== head.count - 1 || linkHash(last) !== head.lastHash) return false;
  const prev = before === undefined ? CHAIN_GENESIS : linkHash(before);
  return last.prev === prev;
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
 * Durability: each append is flushed to stable storage (`fdatasync`) before
 * `record()` resolves, so the guarded action never runs on an approval a power
 * cut could take back (opt out with `fsync: false`). A crash in mid-append can
 * leave a torn last line; by default it makes reads throw, as in 0.2.0. (A
 * last chain entry that only lost its newline is not torn: once the rest of the
 * file reads cleanly, the next append writes the newline first, by default too.) With
 * `repairTornTail: true`, reads skip it and `verifyAll` reports it in
 * `tornTails`, and the writer moves it into `<file>.quarantine.jsonl` before its
 * next append (see `repair()`). Reading never changes the file. A corrupt line
 * anywhere else is never repaired: reads throw, as they always have.
 *
 * Write order within a process is preserved (writes are queued, so concurrent
 * records never interleave and each links onto the last). This is a
 * single-writer log: point separate processes at separate files, or put a real
 * store behind the ReceiptSink interface. Reading a file written by an older
 * (unchained) version still works; `verifyChain` reports such entries as
 * `unchained-entry`.
 */
export class ReceiptLog implements ReceiptSink {
  private tail: Promise<unknown> = Promise.resolve();
  /** in-memory chain head, lazily recovered from the file on first write */
  private headState?: { count: number; lastHash: string };
  private readonly fsync: boolean;
  private readonly repairs: boolean;
  /** where torn tails are moved: `<file>.quarantine.jsonl` */
  readonly quarantinePath: string;
  /** where Intents are kept beside the receipts, when `intents` is set */
  readonly intentStore?: IntentStore;

  constructor(
    public readonly filePath: string,
    opts: ReceiptLogOptions = {},
  ) {
    this.fsync = opts.fsync ?? true;
    this.repairs = opts.repairTornTail ?? false;
    this.quarantinePath = `${filePath}.quarantine.jsonl`;
    if (opts.intents === true) this.intentStore = new FileIntentStore(`${filePath}.intents.jsonl`, { fsync: this.fsync });
    else if (opts.intents) this.intentStore = opts.intents;
  }

  /**
   * Repair the log now: if its last line is torn (a crash in mid-append), move
   * those bytes into {@link quarantinePath} and cut the log back to its last
   * whole line. Returns what was moved, or null. This WRITES to the log: call it
   * only from the log's single writer, never from an auditor (a torn end may be
   * the writer's append still in flight). With `repairTornTail: true` the writer
   * also does this on its own before each append. It never touches a bad line in
   * the middle of the file.
   */
  repair(): Promise<TornTail | null> {
    return this.enqueue(async () => {
      const torn = await repairTornTail(this.filePath, this.quarantinePath, this.fsync);
      this.headState = undefined;
      return torn;
    });
  }

  /**
   * Store an Intent in this log's {@link intentStore} (a no-op without one).
   * Call it when the Intent is issued, so it is on disk even while still pending;
   * `record(resolution, intent)` also stores it, before the receipts.
   */
  async rememberIntent(intent: Intent): Promise<void> {
    if (this.intentStore) await this.intentStore.put(intent);
  }

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
  record(resolution: Resolution, intent?: Intent): Promise<void> {
    if (intent && this.intentStore) {
      // The Intent goes to disk first, so a stored receipt always has its Intent beside it.
      const store = this.intentStore;
      return store.put(intent).then(() => this.record(resolution));
    }
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
   *
   * When the log keeps Intents (`intents` option) and the caller supplies none,
   * the stored Intents are used as `intents`; caller-supplied ones always win.
   * Stored Intents are checked exactly like supplied ones (agent signature, the
   * `trustedAgentKeys` pin), so a tampered sidecar faults, it never vouches.
   *
   * With `repairTornTail: true`, torn last lines (in quarantine, or still at the
   * end of the file) are listed in `tornTails` and make `ok` false. Reading never
   * changes the file.
   */
  async verifyAll(opts: VerifyAllOptions = {}): Promise<ReceiptLogReport> {
    if (opts.intents === undefined && this.intentStore) {
      const stored = await this.intentStore.all();
      if (stored.length) opts = { ...opts, intents: stored };
    }
    // Validate option SHAPES up front. An untyped (JS) caller can pass a malformed value —
    // `null`/a number/a bare object for a string|array option, a single Intent for an array, an
    // empty-string agent pin. Reject each with a clean CountersignError (every other misconfig
    // throws one) rather than let it reach a spread/`.filter`/`for…of` and abort the audit with a
    // raw TypeError, OR silently disable a security pin. `undefined` alone means "absent".
    if (opts.authorityKey !== undefined && typeof opts.authorityKey !== "string" && !Array.isArray(opts.authorityKey))
      throw new CountersignError("verifyAll: authorityKey must be a string or an array of strings");
    if (opts.trustedKeys !== undefined && typeof opts.trustedKeys !== "string" && !Array.isArray(opts.trustedKeys))
      throw new CountersignError("verifyAll: trustedKeys must be a string or an array of strings");
    if (opts.trustedAgentKeys !== undefined && !Array.isArray(opts.trustedAgentKeys))
      throw new CountersignError("verifyAll: trustedAgentKeys must be an array of agent public keys (an empty string does NOT disable the pin)");
    if (opts.intents !== undefined && !Array.isArray(opts.intents))
      throw new CountersignError("verifyAll: intents must be an array of Intents");
    // Symmetric to the option empty-array guards below: an empty `intents` array builds an empty
    // binding map, so every receipt on an honest log faults `unknown-intent` (ok:false) — a false
    // tamper alarm. Reject the likely mistake rather than silently misreport a clean log.
    if (opts.intents && opts.intents.length === 0)
      throw new CountersignError("verifyAll: intents must not be an empty array — omit it to audit without Intent binding, or supply at least one Intent");
    // Normalize the authority key(s) to a canonical set. Each must be canonical, or a
    // keyed slot bound to the canonical authority key slips past the exact-string SoD
    // comparison via a non-canonical alias (base64url is not injective) — the class
    // already closed for the agent/org keys. authorityKey only does anything with
    // `intents` (the authority checks live in the per-Intent branch), so passing it alone
    // would be a silent no-op — throw instead of misleading the auditor.
    const authorityKeys = opts.authorityKey === undefined ? undefined : typeof opts.authorityKey === "string" ? [opts.authorityKey] : [...opts.authorityKey];
    if (authorityKeys) {
      // An EMPTY array would pass `every` vacuously and be truthy, silently disabling the
      // agent!=authority and keyed-slot!=authority checks (`includes` on [] is always
      // false) — the opposite of the advertised anchor. Reject it.
      if (authorityKeys.length === 0)
        throw new CountersignError("verifyAll: authorityKey must not be an empty array — omit it, or supply at least one key");
      if (!authorityKeys.every(isCanonicalPublicKey))
        throw new CountersignError("verifyAll: authorityKey contains a non-canonical ed25519 key");
      if (!opts.intents)
        throw new CountersignError("verifyAll: authorityKey has no effect without `intents` (the authority checks are per-Intent) — omit it or supply intents");
    }
    // Symmetric to the authorityKey empty-array guard: an empty trustedAgentKeys makes the pin
    // `[].includes(agent)` always false, so EVERY supplied Intent is dropped and an honest,
    // untampered log false-faults as `unverified-intent`. Reject it rather than misaudit.
    if (opts.trustedAgentKeys && opts.trustedAgentKeys.length === 0)
      throw new CountersignError("verifyAll: trustedAgentKeys must not be an empty array — omit it, or supply at least one agent key");
    // Symmetric to the authorityKey guard: trustedAgentKeys is consulted ONLY inside the per-Intent
    // `if (opts.intents)` block, so supplying it without `intents` is a silent no-op — the agent pin
    // the auditor asked for never runs and the log gets an integrity-only pass. Throw instead.
    if (opts.trustedAgentKeys && !opts.intents)
      throw new CountersignError("verifyAll: trustedAgentKeys has no effect without `intents` (the agent pin is per-Intent) — omit it or supply intents");
    // Reject a trustedKeys with NO usable key — an empty array, an empty string, or all-empty entries
    // ([], "", [""]) all make the membership check match nothing, faulting every receipt as
    // untrusted-key on an honest log (the same false alarm the array-only guard closed; "" slipped past
    // it because `typeof "" === "string"`). authorityKey has no such hole — its "" fails isCanonicalPublicKey.
    // Normalize ONCE here and build the material Set from the same `tk` — a second normalization site
    // could silently diverge from this guard about what counts as a trusted key. The Set is keyed by
    // credentialKeyMaterial so raw K and its descriptor webauthn-ed25519:K are ONE identity (one key,
    // one holder) in EVERY trustedKeys check — the keyed gate and the no-intents fallback alike.
    let trustedMaterials: Set<string> | undefined;
    if (opts.trustedKeys !== undefined) {
      const tk = typeof opts.trustedKeys === "string" ? [opts.trustedKeys] : opts.trustedKeys;
      // Keep only usable (non-empty STRING) entries. A non-string (e.g. an unset env var reaching an
      // untyped caller as `undefined`) must NOT crash credentialKeyMaterial(undefined) with a raw
      // TypeError mid-audit — it is simply not a trusted key. If nothing usable remains, the allowlist
      // matches nothing (every receipt would fault untrusted-key on an honest log) — reject it as the
      // likely mistake it is, the same clean error [], "", and [""] already get.
      const usable = tk.filter((k): k is string => typeof k === "string" && k !== "");
      if (usable.length === 0)
        throw new CountersignError("verifyAll: trustedKeys must not be empty — omit it, or supply at least one (non-empty) key");
      trustedMaterials = new Set(usable.map(credentialKeyMaterial));
    }
    // An Intent's approver bindings are only a trust anchor if the Intent ITSELF
    // authenticates — otherwise a tampered archived Intent (approver key swapped,
    // signature now invalid) would let a fake receipt signed by the replacement key
    // read as valid. Keep only Intents whose invariants hold AND whose agent
    // signature verifies (and, if pinned, whose agent key is trusted). A supplied
    // Intent that fails is dropped so its receipts fault as `unverified-intent`
    // rather than being checked against attacker-chosen bindings.
    let intentsById: Map<string, Intent> | undefined;
    // Actor→approver lookup cached ONCE per authentic Intent (mirrors verifyResolution's byActor),
    // so the per-receipt loop below is an O(1) get instead of re-scanning + re-normalizing the whole
    // approver list for every receipt (O(N·M)). Reserved default:timeout is excluded, as there too.
    const approversByIntent = new Map<string, Map<string, Approver>>();
    const unverifiedIntentIds = new Set<string>();
    if (opts.intents) {
      intentsById = new Map();
      for (const i of opts.intents) {
        let authentic = false;
        try {
          assertIntentInvariants(i);
          authentic =
            verifyIntent(i) &&
            // Separation of duty (as verifyResolution enforces): an Intent authored BY the
            // authority key is not trusted for its bindings — else the authority-key holder
            // could bind approver keys it controls, sign the receipts, and pass the audit.
            (authorityKeys === undefined || !authorityKeys.includes(i.agent?.public_key)) &&
            (!opts.trustedAgentKeys || opts.trustedAgentKeys.includes(i.agent?.public_key));
        } catch {
          authentic = false;
        }
        if (authentic) {
          intentsById.set(i.intent_id, i);
          const byActor = new Map<string, Approver>();
          for (const a of i.approvers) {
            const na = normalizeActor(a.actor);
            if (na !== DEFAULT_TIMEOUT_ACTOR) byActor.set(na, a);
          }
          approversByIntent.set(i.intent_id, byActor);
        } else if (typeof i?.intent_id === "string") unverifiedIntentIds.add(i.intent_id);
      }
    }
    const { lines, torn: tornNow } = await this.parseFile();
    const chain = walkChain(lines, opts.expectedHead);
    const faults: ReceiptFault[] = [];
    // Torn tails: the quarantined ones, once each (a repair interrupted by a crash may record the
    // same bytes twice), then one still at the end of the file. Read only; nothing is moved here.
    const quarantined = await readQuarantine(this.quarantinePath);
    let torn: TornTailReport[] | undefined;
    if (this.repairs || quarantined.length || tornNow) {
      torn = [];
      const seenTorn = new Set<string>();
      for (const q of quarantined) {
        const key = `${q.offset}:${q.sha256}`;
        if (seenTorn.has(key)) continue;
        seenTorn.add(key);
        torn.push({ index: q.line, intent_id: typeof q.intent_id === "string" ? q.intent_id : "", offset: q.offset, length: q.length, quarantined: true });
      }
      if (tornNow) torn.push({ index: tornNow.line, intent_id: tornNow.intent_id, offset: tornNow.offset, length: tornNow.length, quarantined: false });
    }
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
      // A MALFORMED passkey descriptor (right prefix, corrupt/non-canonical key bytes) is
      // detectable WITHOUT the RP policy — that's a signature/structural fault, not a
      // missing-policy one. Likewise a MISSING or malformed `webauthn` assertion block on
      // a passkey receipt is structural corruption detectable without the policy. Only a
      // STRUCTURALLY COMPLETE passkey receipt (valid descriptor + present assertion block)
      // that merely can't be cryptographically verified without the policy is the honest
      // "missing-webauthn-policy" case.
      const isPasskey = isWebAuthnCredential(cs.public_key);
      const hasWebAuthnBlock = !!cs.webauthn && typeof cs.webauthn.authenticator_data === "string" && typeof cs.webauthn.client_data_json === "string";
      if (isPasskey && (!isValidCredentialDescriptor(cs.public_key) || !hasWebAuthnBlock)) reason = "invalid-signature";
      else if (isPasskey && !opts.webauthn) reason = "missing-webauthn-policy";
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
          const csActor = normalizeActor(cs.actor);
          const approver = approversByIntent.get(intent.intent_id)?.get(csActor);
          const isTimeoutDefault = cs.policy === "default" && csActor === DEFAULT_TIMEOUT_ACTOR;
          // The authority key is THE anchor for every authority-signed receipt (vouched
          // approvals + the timeout Default) and for the keyed-slot separation-of-duty
          // check — exactly as verifyResolution uses expectedAuthorityPublicKey. It is a
          // DEDICATED option, distinct from the general `trustedKeys` allowlist (which
          // may legitimately hold approver keys). To verify an authority-signed receipt
          // you MUST supply it; without it such a receipt faults as `missing-authority-key`
          // — honest (can't verify), never silently valid, never a tamper alarm.
          if (approver && cs.policy !== "approver") {
            // A named approver's receipt is always an "approver" decision. A "default"
            // (or other) policy on it is the timeout-Default label smuggled onto a human
            // slot — verifyResolution rejects exactly this, so the audit must too.
            reason = "untrusted-key";
          } else if (approver?.mode === "keyed") {
            // A keyed slot must NOT be bound to the authority key (a keyed decision must be the
            // approver's OWN key), then be verified against that own bound key. The keyed-slot ≠
            // authority separation-of-duty check REQUIRES the authority key — like vouched/Default,
            // and exactly as verifyResolution requires expectedAuthorityPublicKey. Neither trustedKeys
            // (an approver allowlist that may itself CONTAIN the authority key — an auditor's slot
            // bound to and signed by that key would then pass) nor trustedAgentKeys (an agent pin)
            // can substitute; with either alone the audit would report ok on a keyed-slot==authority
            // SoD violation that verifyResolution always rejects. So without authorityKey, fault
            // `missing-authority-key`; trustedKeys/trustedAgentKeys are ADDITIONAL filters on top.
            if (authorityKeys === undefined) reason = "missing-authority-key";
            else if (approver.public_key && authorityKeys.includes(credentialKeyMaterial(approver.public_key))) reason = "untrusted-key";
            else if (!verifyCountersignature(cs, { trustedKeys: approver.public_key, webauthn: opts.webauthn })) reason = "untrusted-key";
          } else if (isTimeoutDefault) {
            // The timeout Default, checked like verifyResolution's default branch: decision
            // matches the quorum-derived default, stamped at/after the deadline (not
            // backdated), and authority-signed (by any listed authority key).
            const expectedDefault = quorumOf(intent) > 1 ? "reject" : intent.default;
            if (cs.decision !== expectedDefault) reason = "untrusted-key";
            else if (!(Date.parse(cs.timestamp) >= deadline(intent))) reason = "untrusted-key";
            else if (authorityKeys === undefined) reason = "missing-authority-key";
            else if (!verifyCountersignature(cs, { trustedKeys: authorityKeys, webauthn: opts.webauthn })) reason = "untrusted-key";
          } else if (approver) {
            // A vouched approver's receipt is authority-signed — verify it against the
            // authority key(s) (verifyResolution binds it to exactly the authority key).
            if (authorityKeys === undefined) reason = "missing-authority-key";
            else if (!verifyCountersignature(cs, { trustedKeys: authorityKeys, webauthn: opts.webauthn })) reason = "untrusted-key";
          } else {
            reason = "untrusted-key"; // actor is not an approver of this Intent
          }
          // `trustedKeys` is an ADDITIONAL allowlist for KEYED (approver-signed) receipts ONLY: one
          // that passed its per-key check (its signature already verified above) must ALSO be a key the
          // auditor trusts. Compare by credentialKeyMaterial — consistent with the keyed-slot==authority
          // check — so a passkey descriptor `webauthn-ed25519:K` and its raw form `K` are ONE identity;
          // a literal-descriptor match would false-fault an auditor who listed the other equivalent form.
          // It must NOT gate authority-signed vouched approvals or the timeout Default (those are anchored
          // by the dedicated authorityKey; trustedKeys legitimately holds only approver keys).
          if (reason === undefined && approver?.mode === "keyed" && trustedMaterials !== undefined && !trustedMaterials.has(credentialKeyMaterial(cs.public_key)))
            reason = "untrusted-key";
        } else if (trustedMaterials !== undefined && !trustedMaterials.has(credentialKeyMaterial(cs.public_key))) {
          // No Intents supplied → the global trusted-set MEMBERSHIP check, by credentialKeyMaterial —
          // the SAME identity semantics as the keyed gate above (raw K ≡ webauthn-ed25519:K), so the
          // audit verdict cannot flip based on whether `intents` was supplied or which equivalent
          // form the auditor listed. The signature itself was already verified in check (1) above.
          reason = "untrusted-key";
        }
      }
      if (reason) faults.push({ index, intent_id: cs.intent_id, actor: cs.actor, reason });
    });
    const report: ReceiptLogReport = { total: lines.length, valid: lines.length - faults.length, faults, chain, ok: faults.length === 0 && chain.intact };
    // A torn tail is not one of the stored lines, so it does not reduce `valid`; it does fail `ok`.
    if (torn) {
      report.tornTails = torn;
      if (torn.length) report.ok = false;
    }
    return report;
  }

  /** Read + parse every line into `{ obj, hash }`; throws loud on a corrupt line. Never writes. */
  private async parseLines(): Promise<ParsedLine[]> {
    return (await this.parseFile()).lines;
  }

  /**
   * Read and parse the file. READ ONLY. Strict, as in 0.2.0, unless `repairTornTail`
   * is on: then a torn last segment (no newline, does not parse) is returned
   * separately in `torn`, for `verifyAll` to report, instead of throwing.
   */
  private async parseFile(): Promise<{ lines: ParsedLine[]; torn?: TornTail }> {
    let buf: Buffer;
    try {
      buf = await readFile(this.filePath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { lines: [] };
      throw err;
    }
    const out: ParsedLine[] = [];
    const split = this.repairs ? splitTornTail(buf) : { lines: buf.toString("utf8").split("\n"), torn: undefined };
    const lines = split.lines;
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
    return { lines: out, torn: split.torn };
  }

  /**
   * Serialize writes through a promise chain so concurrent `append`/`record`
   * calls never interleave, and each entry links onto the one before it.
   */
  private write(receipts: Countersignature[]): Promise<void> {
    return this.enqueue(() => this.appendChained(receipts));
  }

  /** Run `task` after every earlier queued task (repair and writes never overlap). */
  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.tail.then(task, task);
    // Keep the chain from staying rejected; each caller still sees its own error.
    this.tail = run.catch(() => {});
    return run;
  }

  private async appendChained(receipts: Countersignature[]): Promise<void> {
    // Only the writer repairs, and only here, inside its own write queue: if the file does
    // not end on a whole line (a crash in mid-append, before or since this instance opened),
    // move the torn end aside and recover the head again before linking onto it.
    if (this.repairs && !(await endsClean(this.filePath))) {
      await repairTornTail(this.filePath, this.quarantinePath, this.fsync);
      this.headState = undefined;
    }
    const head = await this.ensureHead();
    if (!this.repairs) {
      // By default too, a last entry that only lost its newline gets it back before the
      // append, so the new entry is not glued onto it (0.2.0 did that, and the log then read
      // as corrupt). Only after the head was read (so an append that fails on damage
      // elsewhere writes nothing, as in 0.2.0), and only when the last segment is this log's
      // own head entry: a chain entry with the head's seq and hash, linked to the line
      // before it. Nothing is cut or moved; any other last segment is left exactly as it is,
      // and the append behaves as in 0.2.0.
      await completeLastLine(this.filePath, this.fsync, (last, before) => isHeadEntry(last, before, head));
    }
    let { count, lastHash } = head;
    let out = "";
    for (const receipt of receipts) {
      const entry: ChainEntry = { seq: count, prev: lastHash, receipt };
      const line = canonicalize(entry);
      out += line + "\n";
      lastHash = sha256b64url(line);
      count += 1;
    }
    try {
      // Written and flushed (fdatasync) before record() resolves: an approval the
      // runtime acts on is already on disk.
      await durableAppend(this.filePath, out, this.fsync);
    } catch (err) {
      // The write may have left a partial line. With the repair opted in, forget the head;
      // the next append's check moves any torn bytes aside first and links onto what is left.
      if (this.repairs) this.headState = undefined;
      throw err;
    }
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

/**
 * The default {@link IntentStore}: one canonical Intent per line in an
 * append-only JSONL file, flushed (`fdatasync`) before `put` resolves. A torn
 * last line is skipped by reads (which never change the file) and moved into
 * `<file>.quarantine.jsonl` by the next `put`, before it appends: only the
 * writer repairs. Single writer, like the log beside it. Intents are
 * stored as given and checked only when used: `verifyAll` verifies each one's
 * agent signature, so an edited line faults its receipts rather than vouching
 * for them.
 */
export class FileIntentStore implements IntentStore {
  private tail: Promise<unknown> = Promise.resolve();
  private cache?: Map<string, { intent: Intent; canonical: string }>;
  private readonly fsync: boolean;
  readonly quarantinePath: string;

  constructor(
    public readonly filePath: string,
    opts: { fsync?: boolean } = {},
  ) {
    this.fsync = opts.fsync ?? true;
    this.quarantinePath = `${filePath}.quarantine.jsonl`;
  }

  put(intent: Intent): Promise<void> {
    return this.enqueue(async () => {
      if (!intent || typeof intent !== "object" || typeof intent.intent_id !== "string")
        throw new CountersignError("intent store: not an Intent (no intent_id)");
      const cache = await this.load();
      const canonical = canonicalize(intent);
      const have = cache.get(intent.intent_id);
      if (have) {
        if (have.canonical === canonical) return;
        throw new CountersignError(`intent store: ${intent.intent_id} is already stored with different content — an intent_id is never rebound`);
      }
      // The writer's repair, on the write path only: never append onto a torn end. The cache
      // already left the torn bytes out, so it stays right.
      if (!(await endsClean(this.filePath))) await repairTornTail(this.filePath, this.quarantinePath, this.fsync);
      await durableAppend(this.filePath, canonical + "\n", this.fsync);
      cache.set(intent.intent_id, { intent: JSON.parse(canonical) as Intent, canonical });
    });
  }

  async get(intentId: string): Promise<Intent | undefined> {
    return (await this.enqueue(() => this.load())).get(intentId)?.intent;
  }

  async all(): Promise<Intent[]> {
    return [...(await this.enqueue(() => this.load())).values()].map((v) => v.intent);
  }

  /** Load (once). READ ONLY: a torn last line is left out, not repaired. The first stored copy of an id wins. */
  private async load(): Promise<Map<string, { intent: Intent; canonical: string }>> {
    if (this.cache) return this.cache;
    let text = "";
    try {
      text = await readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    const cache = new Map<string, { intent: Intent; canonical: string }>();
    const lines = wholeLines(text);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      let obj: unknown;
      try {
        obj = JSON.parse(line);
      } catch {
        throw new CountersignError(`intent store ${this.filePath} is corrupt at line ${i + 1}`);
      }
      const id = (obj as Intent | null)?.intent_id;
      if (typeof id === "string" && !cache.has(id)) cache.set(id, { intent: obj as Intent, canonical: canonicalize(obj) });
    }
    this.cache = cache;
    return cache;
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.tail.then(task, task);
    this.tail = run.catch(() => {});
    return run;
  }
}
