// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

/**
 * Decisions that survive a restart.
 *
 * `wrapAction` waits on an in-memory promise, and every adapter keeps its
 * pending Intents in memory. That is fine while the process lives; a restart
 * loses them. This module adds the missing durable half, without changing the
 * wire format or any default:
 *
 *  - {@link PendingStore}: what is pending, its deadline, whether it was
 *    delivered, and what is final. {@link FilePendingStore} is the file-backed
 *    default (an append-only JSONL event file, flushed before each call
 *    resolves, guarded by a lock file so only one process writes it).
 *  - {@link DurableDecisions}: issue an Intent now and resolve it later, in this
 *    process or after a restart. `restore()` re-arms every unfinished Intent with
 *    its remaining time, lapses the ones whose deadline passed while the process
 *    was down by minting the signed Default, finishes decisions that were taken
 *    but not yet logged, and never decides an Intent twice.
 */

import { hostname } from "node:os";
import { link, mkdir, open as openFile, readFile, rename, stat, unlink, utimes, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { authorityKeyFromEnv, DeliveryPartialError, type Adapter } from "./adapter.js";
import { canonicalize } from "./core/canonical.js";
import { normalizeActor } from "./core/countersignature.js";
import { awaitWithDefault, deadline, defaultResolution, verifyResolution } from "./core/defaults.js";
import { CountersignError } from "./core/errors.js";
import { assertIntentInvariants, quorumOf, verifyIntent } from "./core/intent.js";
import { publicKeyFromSecret } from "./core/keys.js";
import type { Countersignature, Intent, Resolution } from "./core/types.js";
import type { WebAuthnPolicy } from "./core/webauthn.js";
import { durableAppend, repairTornTail, syncDir } from "./durable-file.js";
import type { ReceiptSink } from "./receipt-log.js";

/** Where one Intent stands. */
export type PendingStatus = "pending" | "final" | "abandoned";

/** One Intent's durable state. */
export interface PendingRecord {
  intent: Intent;
  /** epoch ms at which its Default fires (see `deadline()`) */
  deadline: number;
  /** true once `deliver()` reached its approvers (all of them, or some: see `unreached`) */
  delivered: boolean;
  /**
   * Approvers the last delivery did not reach (a {@link DeliveryPartialError}):
   * the Intent is pending and the approvers reached can decide it, but these
   * were never asked. Absent when the delivery reached everyone.
   */
  unreached?: string[];
  status: PendingStatus;
  /** the final Resolution, when `status` is "final" */
  resolution?: Resolution;
  /** true once the final Resolution was handed to the receipt sink */
  logged: boolean;
  /** why it was abandoned, when `status` is "abandoned" */
  reason?: string;
}

/**
 * Durable state for Intents awaiting a decision. Every method must be durable
 * before it resolves. The one rule that makes decisions happen once: `finalize`
 * is FIRST-WINS. If the Intent is already final it stores nothing and returns
 * the stored Resolution, which callers must use in place of their own.
 *
 * A store has ONE writer. Two processes deciding from the same store could each
 * see "pending" and each decide; {@link FilePendingStore} enforces this with a
 * lock file. A store over a database can enforce it with a transaction instead.
 */
export interface PendingStore {
  /** Record a newly issued Intent as pending. Idempotent for the same Intent; rejects a different Intent under a stored id. */
  issue(intent: Intent): Promise<PendingRecord>;
  /**
   * Note that the Intent reached its approvers. `unreached` lists the approvers a
   * partial delivery missed (stored on the record); omitted or empty, the
   * delivery reached everyone and any earlier list is cleared.
   */
  markDelivered(intentId: string, unreached?: readonly string[]): Promise<void>;
  /** Make a Resolution final (first wins) and return the Resolution that is final. Issues the Intent if it was not. */
  finalize(intent: Intent, resolution: Resolution): Promise<Resolution>;
  /** Note that the final Resolution was written to the receipt sink. */
  markLogged(intentId: string): Promise<void>;
  /** Give up on a pending Intent that was never decided (for example, delivery failed). Not a decision: no receipt exists. */
  abandon(intentId: string, reason: string): Promise<void>;
  get(intentId: string): Promise<PendingRecord | undefined>;
  /** Every record, in the order first issued. */
  list(): Promise<PendingRecord[]>;
}

type StoreEvent =
  | { ev: "issued"; intent: Intent; deadline: number }
  | { ev: "delivered"; intent_id: string; unreached?: string[] }
  | { ev: "final"; intent_id: string; resolution: Resolution; intent?: Intent }
  | { ev: "logged"; intent_id: string }
  | { ev: "abandoned"; intent_id: string; reason: string };

function copy(rec: PendingRecord): PendingRecord {
  return rec.unreached ? { ...rec, unreached: [...rec.unreached] } : { ...rec };
}

/** True when `pid` is a live process on this host (EPERM means alive but not ours). */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Lock tokens held by live FilePendingStore handles in THIS process. Kept on
 * globalThis so two copies of this module (an ESM and a CJS build loaded side by
 * side) still agree on which locks this process holds.
 */
const HELD: Set<string> = ((globalThis as Record<symbol, unknown>)[Symbol.for("countersign.pending-store.held-locks")] ??= new Set<string>()) as Set<string>;

/**
 * When this process started (epoch ms, rounded down, so never later than the
 * true start). Recorded in the lock, and compared with a same-pid lock's last
 * heartbeat: an earlier run of this pid cannot have heartbeated after we started.
 */
const PROCESS_STARTED = Math.floor(Date.now() - process.uptime() * 1000);

/** The default lock lease: a lock whose heartbeat is older than this, held by another live pid, is stale. */
const DEFAULT_LOCK_LEASE_MS = 10_000;

/**
 * The steps of taking over a stale lock, reported to {@link FilePendingStoreOptions.lockSteps}.
 * "backoff": this opener's new lock was moved aside by another taker; it waits briefly and looks again.
 */
export type LockStep = "judged-stale" | "renamed" | "created" | "backoff";

/** How many rounds `open` tries to take a lock before giving up, and the base backoff between rounds (ms). */
const LOCK_ROUNDS = 8;
const LOCK_BACKOFF_MS = 25;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Options for {@link FilePendingStore.open}. */
export interface FilePendingStoreOptions {
  /** flush each event (`fdatasync`) before its call resolves. Default true. */
  fsync?: boolean;
  /**
   * How long a lock stays held without a heartbeat, in ms. The holder refreshes
   * the lock file every third of this; use the same value for every process on
   * a store. A lock held by another live process on this host whose heartbeat
   * is older than the lease is stale and taken over. A lock naming THIS
   * process's pid (a crash-restart in a container, or a live twin container
   * sharing this hostname and pid) is stale only once it is proven gone: its
   * last heartbeat is older than this process (an earlier run cannot have
   * heartbeated since we started) and older than two heartbeat intervals (a
   * live twin would have refreshed it), or older than the lease. A crash-restart
   * is taken at once when the crash came more than two heartbeat intervals
   * before; otherwise `open` waits out the rest of those two intervals and looks
   * again. A live twin is refused. Default 10 000.
   */
  lockLeaseMs?: number;
  /**
   * Testing seam: awaited at each step of taking over a stale lock, so a test can
   * interleave two openers deterministically. Not for production use.
   */
  lockSteps?: (step: LockStep) => Promise<void> | void;
}

interface LockBody {
  pid?: unknown;
  hostname?: unknown;
  token?: unknown;
  started?: unknown;
}

/** Read a lock file's text, last heartbeat (mtime) and age; undefined when there is none. */
async function readLock(lockPath: string): Promise<{ text: string; mtimeMs: number; ageMs: number } | undefined> {
  try {
    const [text, st] = await Promise.all([readFile(lockPath, "utf8"), stat(lockPath)]);
    return { text, mtimeMs: st.mtimeMs, ageMs: Date.now() - st.mtimeMs };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
}

/**
 * Is this lock held by a live writer? Held when its token belongs to a handle in
 * this process, when it is from another host (never taken over), or when it names
 * another live pid on this host whose heartbeat is within the lease. Stale when it
 * names a dead pid, or a live pid whose heartbeat is older than the lease (the pid
 * was reused, or its owner is wedged). An unreadable lock is stale once it is
 * older than the lease (a lock is created whole, so it is damaged).
 *
 * A lock naming THIS process's pid (with a token no handle here holds) is either
 * an earlier run of this pid (a container restarted after a crash) or a live twin:
 * another container sharing this hostname and pid, as with host networking and a
 * shared volume. `alive()` cannot tell them apart, so it is stale only with proof
 * the holder is gone: its last heartbeat is older than this process's start (an
 * earlier run cannot have heartbeated since) AND older than two heartbeat
 * intervals (a live twin would have refreshed it by now), or it is older than the
 * lease. A heartbeat from before our start that is still recent gives `waitMs`:
 * look again once two intervals have passed.
 */
function judgeLock(lock: { text: string; mtimeMs: number; ageMs: number }, leaseMs: number): { stale: boolean; body: LockBody; waitMs?: number } {
  const { text, mtimeMs, ageMs } = lock;
  let body: LockBody;
  try {
    body = JSON.parse(text) as LockBody;
    if (typeof body !== "object" || body === null) throw new Error("not an object");
  } catch {
    return { stale: ageMs > leaseMs, body: {} };
  }
  if (typeof body.token === "string" && HELD.has(body.token)) return { stale: false, body };
  if (body.hostname !== hostname()) return { stale: false, body };
  if (typeof body.pid !== "number") return { stale: ageMs > leaseMs, body };
  if (body.pid === process.pid) {
    if (ageMs > leaseMs) return { stale: true, body };
    if (mtimeMs >= PROCESS_STARTED) return { stale: false, body }; // heartbeated since we started: a live twin
    const twoBeats = 2 * heartbeatEvery(leaseMs);
    if (ageMs > twoBeats) return { stale: true, body };
    return { stale: false, body, waitMs: Math.ceil(twoBeats - ageMs) + 1 };
  }
  if (!alive(body.pid)) return { stale: true, body };
  return { stale: ageMs > leaseMs, body };
}

/** How often a holder refreshes its lock: every third of the lease. */
function heartbeatEvery(leaseMs: number): number {
  return Math.max(1, Math.floor(leaseMs / 3));
}

/**
 * Create `lockPath` holding `text`, only if it does not exist, and whole: the text
 * is written to a private file first and then hard-linked into place, so no
 * reader ever sees a half-written lock. Returns false if the lock exists.
 */
async function createLock(lockPath: string, text: string, token: string, fsync: boolean): Promise<boolean> {
  await mkdir(dirname(lockPath), { recursive: true });
  const tmp = `${lockPath}.${token}.tmp`;
  const fh = await openFile(tmp, "w");
  try {
    await fh.writeFile(text, "utf8");
    if (fsync) await fh.datasync();
  } finally {
    await fh.close();
  }
  try {
    await link(tmp, lockPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EEXIST") return false;
    // A filesystem without hard links: fall back to an exclusive create.
    if (code !== "EPERM" && code !== "ENOTSUP" && code !== "ENOSYS" && code !== "EOPNOTSUPP") throw err;
    try {
      await writeFile(lockPath, text, { flag: "wx" });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw e;
    }
  } finally {
    await unlink(tmp).catch(() => {});
  }
  if (fsync) await syncDir(dirname(lockPath));
  return true;
}

/**
 * The file-backed {@link PendingStore}. State is an append-only JSONL file of
 * events (issued, delivered, final, logged, abandoned), replayed on open. Each
 * event is flushed (`fdatasync`) before the call resolves, and a torn last line
 * left by a crash is moved to `<file>.quarantine.jsonl` on open, like the
 * receipt log. A corrupt line in the middle stops `open` with an error.
 *
 * SINGLE WRITER: exactly one process may write a store file, and you must
 * arrange that (one process per store; never two live processes on one file).
 * The lock below catches mistakes; it is not a distributed lock. `open` creates
 * `<file>.lock` (whole, by a hard link) holding this process's pid, host, start
 * time and a random token, and keeps it fresh with a heartbeat. A second `open`
 * (from any process, or a second handle in this one) fails while the lock is
 * held. On this host, a lock is stale, and taken over, when its pid is gone,
 * when its heartbeat is older than `lockLeaseMs`, or, for a lock naming this
 * process's own pid, when its heartbeat predates this process and is older than
 * two heartbeat intervals (an earlier run, as after a container restart; a live
 * twin container sharing this hostname and pid is refused, see `lockLeaseMs`).
 * Taking over is atomic: the stale lock is renamed aside and checked to be the
 * one judged stale before a new one is created, so of two processes starting
 * together exactly one gets it, and an opener that loses a round retries a few
 * times before giving up. A lock from another host is never taken over: remove
 * it by hand once you know that host is down. Every write checks, before and
 * after its append, that the lock is still this handle's and that the file holds
 * only what this handle read and wrote; otherwise the write rejects and the handle
 * stops writing (see `apply` for exactly what that guarantees). Call `close()` to
 * release it.
 *
 * The file only grows. Each Intent adds a handful of short lines, which is
 * small at approval rates; to start fresh, close the store and move the file
 * away once nothing in it is pending.
 */
export class FilePendingStore implements PendingStore {
  private records = new Map<string, PendingRecord>();
  private tail: Promise<unknown> = Promise.resolve();
  private closed = false;
  /** set when the heartbeat or a write finds the lock is no longer this handle's, or the file was written by another */
  private lost = false;
  /** the file's length as this handle last read or wrote it: anything else means another writer appended */
  private size = 0;
  private heartbeat?: ReturnType<typeof setInterval>;
  readonly lockPath: string;
  readonly quarantinePath: string;

  private constructor(
    public readonly filePath: string,
    private readonly fsync: boolean,
    private readonly lockToken: string,
  ) {
    this.lockPath = `${filePath}.lock`;
    this.quarantinePath = `${filePath}.quarantine.jsonl`;
  }

  /** Open (or create) a store, taking its lock. Rejects if another live writer holds it. */
  static async open(filePath: string, opts: FilePendingStoreOptions = {}): Promise<FilePendingStore> {
    const fsync = opts.fsync ?? true;
    const leaseMs = opts.lockLeaseMs ?? DEFAULT_LOCK_LEASE_MS;
    if (!(Number.isFinite(leaseMs) && leaseMs > 0)) throw new CountersignError("pending store: lockLeaseMs must be a positive number of milliseconds");
    const token = randomUUID();
    await FilePendingStore.lock(`${filePath}.lock`, token, fsync, filePath, leaseMs, opts.lockSteps);
    const store = new FilePendingStore(filePath, fsync, token);
    store.startHeartbeat(leaseMs);
    try {
      await store.load();
    } catch (err) {
      await store.close();
      throw err;
    }
    return store;
  }

  private static async lock(
    lockPath: string,
    token: string,
    fsync: boolean,
    filePath: string,
    leaseMs: number,
    step: (s: LockStep) => Promise<void> | void = () => {},
  ): Promise<void> {
    const body = JSON.stringify({ pid: process.pid, hostname: hostname(), token, started: PROCESS_STARTED, at: new Date().toISOString() });
    const heldError = (held: LockBody, ageMs?: number) =>
      new CountersignError(
        `pending store ${filePath} is held by pid ${String(held.pid)} on ${String(held.hostname)} (${lockPath}) — one writer per store; ` +
          `stop that process, or remove the lock by hand if it is gone` +
          (held.pid === process.pid && held.hostname === hostname()
            ? ` (it names this process's own pid but was heartbeated after this process started: another live process, such as a container sharing this hostname and pid)`
            : "") +
          (ageMs === undefined ? "" : ` (its heartbeat is ${Math.round(ageMs / 1000)}s old; it goes stale after ${Math.round(leaseMs / 1000)}s)`),
      );
    for (let round = 0; round < LOCK_ROUNDS; round++) {
      if (await createLock(lockPath, body, token, fsync)) {
        await step("created");
        const now = await readLock(lockPath);
        if (now?.text === body) {
          HELD.add(token);
          return;
        }
        // Another taker moved our new lock aside (it judged the old one stale just before we
        // replaced it). It puts ours back once it sees what it moved; wait briefly and look again.
        await step("backoff");
        await sleep(LOCK_BACKOFF_MS * (round + 1));
        continue;
      }
      const seen = await readLock(lockPath);
      if (!seen) continue; // released (or moved aside by another taker) since: try again
      if (seen.text === body) {
        // Our own lock, put back by a taker that had moved it aside.
        HELD.add(token);
        return;
      }
      const { stale, body: held, waitMs } = judgeLock(seen, leaseMs);
      if (!stale && waitMs !== undefined) {
        // This pid's lock from before we started, still within two heartbeats: a crashed
        // earlier run, or a live twin about to heartbeat. Wait and judge it again.
        await sleep(waitMs);
        continue;
      }
      if (!stale) throw heldError(held, typeof held.pid === "number" && held.hostname === hostname() ? seen.ageMs : undefined);
      await step("judged-stale");
      // Take over atomically: move the lock aside under a name only we use, and check that
      // what we moved is the very lock judged stale. If another taker replaced it meanwhile,
      // we moved THEIR fresh lock: put it back and look again.
      const aside = `${lockPath}.stale-${randomUUID()}`;
      try {
        await rename(lockPath, aside);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw err;
      }
      await step("renamed");
      let moved: string | undefined;
      try {
        moved = await readFile(aside, "utf8");
      } catch {
        moved = undefined;
      }
      if (moved !== seen.text) await link(aside, lockPath).catch(() => {});
      await unlink(aside).catch(() => {});
    }
    // Out of rounds. Never leave behind a lock that names us but that no heartbeat keeps.
    const left = await readLock(lockPath).catch(() => undefined);
    if (left?.text === body) await unlink(lockPath).catch(() => {});
    if (left && left.text !== body) throw heldError(judgeLock(left, leaseMs).body, left.ageMs);
    throw new CountersignError(`pending store ${filePath}: could not take the lock ${lockPath} (it changed while being taken)`);
  }

  /** Keep the lock fresh; notice if it stops being ours. Unref'd: it never keeps the process alive. */
  private startHeartbeat(leaseMs: number): void {
    this.heartbeat = setInterval(() => {
      void this.checkLock(true).catch(() => {});
    }, heartbeatEvery(leaseMs));
    this.heartbeat.unref?.();
  }

  /** True while the lock file is this handle's; with `touch`, also refresh its heartbeat. */
  private async checkLock(touch = false): Promise<boolean> {
    if (this.lost || this.closed) return !this.lost;
    // A lock briefly missing is another taker putting it back (see lock()): look twice.
    let mine = false;
    for (let look = 0; look < 2; look++) {
      let text: string;
      try {
        text = await readFile(this.lockPath, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        if (look === 0) await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      try {
        mine = (JSON.parse(text) as LockBody).token === this.lockToken;
      } catch {
        mine = false;
      }
      break;
    }
    if (!mine) {
      this.lost = true;
      this.stopHeartbeat();
      HELD.delete(this.lockToken);
      return false;
    }
    if (touch) {
      const now = new Date();
      await utimes(this.lockPath, now, now).catch(() => {});
    }
    return true;
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = undefined;
  }

  /** Release the lock. Further calls on this handle reject. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.stopHeartbeat();
    await this.tail;
    try {
      const held = JSON.parse(await readFile(this.lockPath, "utf8"));
      if (held.token === this.lockToken) await unlink(this.lockPath);
    } catch {
      // already gone
    } finally {
      HELD.delete(this.lockToken);
    }
  }

  issue(intent: Intent): Promise<PendingRecord> {
    return this.enqueue(async () => {
      assertIntentInvariants(intent);
      const have = this.records.get(intent.intent_id);
      if (have) {
        if (canonicalize(have.intent) !== canonicalize(intent))
          throw new CountersignError(`pending store: ${intent.intent_id} is already stored with different content — an intent_id is never rebound`);
        return copy(have);
      }
      return copy(await this.apply({ ev: "issued", intent, deadline: deadline(intent) }));
    });
  }

  markDelivered(intentId: string, unreached: readonly string[] = []): Promise<void> {
    return this.enqueue(async () => {
      const rec = this.need(intentId);
      const missed = unreached.map(String);
      if (rec.delivered && JSON.stringify(missed) === JSON.stringify(rec.unreached ?? [])) return;
      await this.apply({ ev: "delivered", intent_id: intentId, ...(missed.length ? { unreached: missed } : {}) });
    });
  }

  finalize(intent: Intent, resolution: Resolution): Promise<Resolution> {
    return this.enqueue(async () => {
      const have = this.records.get(intent.intent_id);
      if (have?.status === "final") return have.resolution!;
      if (have?.status === "abandoned")
        throw new CountersignError(`pending store: ${intent.intent_id} was abandoned (${have.reason}) and cannot be decided`);
      if (!have) assertIntentInvariants(intent);
      await this.apply({ ev: "final", intent_id: intent.intent_id, resolution, ...(have ? {} : { intent }) });
      return resolution;
    });
  }

  markLogged(intentId: string): Promise<void> {
    return this.enqueue(async () => {
      const rec = this.need(intentId);
      if (rec.status !== "final") throw new CountersignError(`pending store: ${intentId} is not final; nothing to log`);
      if (!rec.logged) await this.apply({ ev: "logged", intent_id: intentId });
    });
  }

  abandon(intentId: string, reason: string): Promise<void> {
    return this.enqueue(async () => {
      const rec = this.need(intentId);
      if (rec.status === "pending") await this.apply({ ev: "abandoned", intent_id: intentId, reason: String(reason) });
    });
  }

  async get(intentId: string): Promise<PendingRecord | undefined> {
    return this.enqueue(async () => {
      const rec = this.records.get(intentId);
      return rec && copy(rec);
    });
  }

  async list(): Promise<PendingRecord[]> {
    return this.enqueue(async () => [...this.records.values()].map(copy));
  }

  private need(intentId: string): PendingRecord {
    const rec = this.records.get(intentId);
    if (!rec) throw new CountersignError(`pending store: unknown intent ${intentId}`);
    return rec;
  }

  /**
   * Write one event durably, then apply it in memory. Refused if the lock is no
   * longer ours, or if the file is not exactly what this handle last read or wrote.
   *
   * There is no portable OS lock here, so the check and the append cannot be one
   * step: a takeover can land between them. Both are therefore checked again AFTER
   * the append, and the call rejects (never applying the event, and this handle
   * stops writing) unless the lock was still ours and the file held only our bytes.
   * The guarantee: a write that RESOLVES was made under this handle's lock, onto a
   * file no one else had appended to, so its event comes before any event another
   * writer adds later, and a replay of the file agrees with what was returned
   * (finalize is first-wins in file order). A write that rejected this way may
   * still be in the file; the next `open` replays it. The other handle, on its next
   * write, finds bytes it did not write and fails closed too. What is NOT
   * guaranteed: two writers on one file (a misconfiguration, or a filesystem
   * without atomic appends) may both fail and need a reopen.
   */
  private async apply(e: StoreEvent): Promise<PendingRecord> {
    if (!(await this.checkLock())) throw this.lostError();
    await this.checkSize();
    const line = canonicalize(e) + "\n";
    await durableAppend(this.filePath, line, this.fsync);
    this.size += Buffer.byteLength(line, "utf8");
    if (!(await this.checkLock()))
      throw new CountersignError(
        `pending store ${this.filePath} lost its lock ${this.lockPath} to another process while writing; the event may be in the file but was not applied, ` +
          `and this handle no longer writes (reopen the store once the other writer is gone)`,
      );
    await this.checkSize();
    return this.fold(e);
  }

  private lostError(): CountersignError {
    return new CountersignError(`pending store ${this.filePath} lost its lock ${this.lockPath} to another process; this handle no longer writes`);
  }

  /** Fail closed if the file is not exactly the bytes this handle has read and written. */
  private async checkSize(): Promise<void> {
    let now = 0;
    try {
      now = (await stat(this.filePath)).size;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    if (now === this.size) return;
    this.lost = true;
    this.stopHeartbeat();
    throw new CountersignError(
      `pending store ${this.filePath} was written by another writer (${this.size} bytes expected, ${now} found) — one writer per store; ` +
        `this handle no longer writes (reopen the store once the other writer is gone)`,
    );
  }

  private fold(e: StoreEvent): PendingRecord {
    if (e.ev === "issued") {
      const rec: PendingRecord = { intent: e.intent, deadline: e.deadline, delivered: false, status: "pending", logged: false };
      if (!this.records.has(e.intent.intent_id)) this.records.set(e.intent.intent_id, rec);
      return this.records.get(e.intent.intent_id)!;
    }
    let rec = this.records.get(e.intent_id);
    if (!rec && e.ev === "final" && e.intent) {
      rec = { intent: e.intent, deadline: deadline(e.intent), delivered: false, status: "pending", logged: false };
      this.records.set(e.intent_id, rec);
    }
    if (!rec) throw new CountersignError(`pending store ${this.filePath}: event for unknown intent ${e.intent_id}`);
    if (e.ev === "delivered") {
      rec.delivered = true;
      if (Array.isArray(e.unreached) && e.unreached.length) rec.unreached = e.unreached.map(String);
      else delete rec.unreached;
    }
    else if (e.ev === "final" && rec.status !== "final") {
      rec.status = "final";
      rec.resolution = e.resolution;
    } else if (e.ev === "logged") rec.logged = true;
    else if (e.ev === "abandoned" && rec.status === "pending") {
      rec.status = "abandoned";
      rec.reason = e.reason;
    }
    return rec;
  }

  private async load(): Promise<void> {
    await repairTornTail(this.filePath, this.quarantinePath, this.fsync);
    let buf = Buffer.alloc(0);
    try {
      buf = await readFile(this.filePath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    this.size = buf.length;
    const lines = buf.toString("utf8").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      let e: StoreEvent;
      try {
        e = JSON.parse(line) as StoreEvent;
      } catch {
        throw new CountersignError(`pending store ${this.filePath} is corrupt at line ${i + 1}`);
      }
      this.fold(e);
    }
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new CountersignError(`pending store ${this.filePath} is closed`));
    if (this.lost) return Promise.reject(this.lostError());
    const run = this.tail.then(task, task);
    this.tail = run.catch(() => {});
    return run;
  }
}

export interface DurableDecisionsOptions {
  /** delivers Intents and collects answers (its own in-memory PendingDecisions is fine) */
  adapter: Adapter;
  /** the durable state; one writer (see {@link PendingStore}) */
  store: PendingStore;
  /**
   * Where final Resolutions are recorded before they are handed back. When it is a
   * `ReceiptLog` (anything with `history()`), it is also checked before deciding:
   * an Intent the log already holds a final receipt for is never decided again.
   */
  receiptLog?: ReceiptSink;
  /** authority secret for vouched receipts and the timeout Default. Defaults to COUNTERSIGN_AUTHORITY_KEY. */
  authorityKey?: string;
  /** WebAuthn policy for passkey approvers, as for wrapAction */
  webauthn?: WebAuthnPolicy;
}

/** What `restore()` found and did. */
export interface RestoreReport {
  /** still inside their window: waiting again, with their remaining time; each promise resolves once decided (and logged) */
  rearmed: Array<{ intent: Intent; resolution: Promise<Resolution> }>;
  /** their deadline passed while the process was down: the signed Default was minted, stored and logged */
  lapsed: Array<{ intent: Intent; resolution: Resolution }>;
  /** decided before the restart but not yet logged (or found final in the log): finished now, not decided again */
  completed: Array<{ intent: Intent; resolution: Resolution }>;
  /** delivered (again) during restore, per the `redeliver` option */
  redelivered: Intent[];
  /** abandoned earlier (or now, because re-delivery failed and no earlier delivery had reached anyone): never decided, no receipt */
  abandoned: Intent[];
  /**
   * re-delivery failed for an Intent an earlier delivery already reached: it is
   * kept pending and re-armed (it is also in `rearmed`), because the people
   * reached then still hold live buttons and their answer counts. The error says
   * why this attempt failed; the record's `unreached` is left as it was.
   */
  redeliveryFailed: Array<{ intent: Intent; error: Error }>;
  /**
   * records that could not be restored (for example a stored decision that no
   * longer verifies, or a receipt log that cannot be written): left as they are
   * in the store, with the error. The other records were still restored.
   */
  failed: Array<{ intent: Intent; error: Error }>;
}

export interface RestoreOptions {
  /**
   * Which re-armed Intents to deliver again. "undelivered" (default): only those
   * whose delivery never completed, for example a crash between storing and
   * sending. "all": every re-armed Intent, for channels whose old message no
   * longer has working buttons. "none": never.
   */
  redeliver?: "undelivered" | "all" | "none";
}

type HistorySource = { history(): Promise<Map<string, Countersignature[]>> };
function hasHistory(s: unknown): s is HistorySource {
  return typeof (s as HistorySource | undefined)?.history === "function";
}
type IntentKeeper = { rememberIntent(intent: Intent): Promise<void> };
function keepsIntents(s: unknown): s is IntentKeeper {
  return typeof (s as IntentKeeper | undefined)?.rememberIntent === "function";
}

/**
 * Issue an Intent now; resolve it later, in this process or after a restart.
 *
 *   const store = await FilePendingStore.open("./state/pending.jsonl");
 *   const log = new ReceiptLog("./state/receipts.jsonl", { intents: true });
 *   const decisions = new DurableDecisions({ adapter, store, receiptLog: log });
 *
 *   // at start-up, before anything else uses the adapter:
 *   const { rearmed, lapsed, completed } = await decisions.restore();
 *
 *   // to ask:
 *   await decisions.issue(intent);              // stored, then delivered
 *   const resolution = await decisions.decide(intent);
 *
 * Order of every decision: the answer (or the Default) is verified, made final
 * in the store (first wins), written to the receipt log, marked logged, and
 * only then returned. A crash at any point is picked up by `restore()`, and an
 * Intent is decided at most once. The caller acts on what `decide()` or
 * `restore()` returns, after it returns.
 *
 * One process per store (see {@link PendingStore}). The adapter must be one
 * process's adapter: a press that reaches another process is not seen here.
 */
export class DurableDecisions {
  private readonly authority: string;
  private readonly authorityPub: string;
  private readonly inflight = new Map<string, Promise<Resolution>>();
  /** adapter waits registered as soon as an Intent is delivered or re-armed, so an early answer is not missed */
  private readonly armed = new Map<string, Promise<Resolution>>();

  constructor(private readonly opts: DurableDecisionsOptions) {
    this.authority = opts.authorityKey ?? authorityKeyFromEnv();
    this.authorityPub = publicKeyFromSecret(this.authority);
  }

  /**
   * Store the Intent (and keep it beside the receipts, when the log does that),
   * then deliver it. If delivery fails and reached nobody, the Intent is marked
   * abandoned, so a restart does not re-arm a request nobody can see, and the
   * error is rethrown.
   *
   * If delivery reached some approvers and not others (the adapter threw a
   * {@link DeliveryPartialError}), the approvers reached already hold live
   * buttons, so the Intent stays pending: it is marked delivered, their answer
   * counts, and `decide()` waits for it (or the Default) as usual. The approvers
   * not reached are stored on the record and returned in its `unreached` field;
   * `issue()` resolves rather than throws, so check `unreached`. Nothing here
   * delivers to them alone: to ask them, issue a new Intent, or let the quorum
   * or the Default decide.
   */
  async issue(intent: Intent): Promise<PendingRecord> {
    const { store, adapter, receiptLog } = this.opts;
    const rec = await store.issue(intent);
    if (rec.status !== "pending" || rec.delivered) return rec;
    if (keepsIntents(receiptLog)) await receiptLog.rememberIntent(intent);
    let unreached: readonly string[] = [];
    try {
      await adapter.deliver(intent);
    } catch (err) {
      if (!(err instanceof DeliveryPartialError) || err.reached.length === 0) {
        await store.abandon(intent.intent_id, `delivery failed: ${err instanceof Error ? err.message : String(err)}`).catch(() => {});
        throw err;
      }
      unreached = err.unreached;
    }
    // Listen for the answer right away, as wrapAction does (deliver, then awaitResolution).
    this.arm(intent);
    await store.markDelivered(intent.intent_id, unreached);
    return (await store.get(intent.intent_id)) ?? rec;
  }

  /**
   * Wait for the Intent's decision (or its Default) and return it once it is final
   * and logged. If it is already final (in the store, or in the receipt log), that
   * decision is returned and nothing is asked again. Concurrent calls share one wait.
   */
  decide(intent: Intent): Promise<Resolution> {
    const id = intent.intent_id;
    const running = this.inflight.get(id);
    if (running) return running;
    const p = this.decideOnce(intent).finally(() => {
      if (this.inflight.get(id) === p) this.inflight.delete(id);
    });
    this.inflight.set(id, p);
    return p;
  }

  /**
   * Pick up after a restart. For every record in the store:
   *  - abandoned: reported, left alone;
   *  - final and logged: nothing to do;
   *  - final, not logged: logged now (unless the log already has it), reported as completed;
   *  - pending, but the receipt log holds a final receipt for it: made final from the log, reported as completed;
   *  - pending, deadline passed while down: the signed Default is minted, stored and logged (lapsed);
   *  - pending, still in its window: re-armed with its remaining time (and delivered again per `redeliver`).
   *    If that re-delivery fails outright, an Intent no delivery ever reached is abandoned;
   *    one an earlier delivery reached stays pending and re-armed, and the failure is
   *    reported in `redeliveryFailed`.
   */
  async restore(opts: RestoreOptions = {}): Promise<RestoreReport> {
    const redeliver = opts.redeliver ?? "undelivered";
    const report: RestoreReport = { rearmed: [], lapsed: [], completed: [], redelivered: [], abandoned: [], redeliveryFailed: [], failed: [] };
    for (const rec of await this.opts.store.list()) {
      // One record that cannot be restored is reported and skipped; it never stops the rest.
      try {
        await this.restoreOne(rec, redeliver, report);
      } catch (err) {
        report.failed.push({ intent: rec.intent, error: err instanceof Error ? err : new CountersignError(String(err)) });
      }
    }
    return report;
  }

  private async restoreOne(rec: PendingRecord, redeliver: NonNullable<RestoreOptions["redeliver"]>, report: RestoreReport): Promise<void> {
    const { store, adapter } = this.opts;
    const { intent } = rec;
    // The store is a file someone could edit. An Intent that is malformed or no longer
    // carries its agent's signature is never re-armed, re-delivered (a person would be
    // shown text the agent never signed) or decided: it goes to `failed`.
    assertIntentInvariants(intent);
    if (!verifyIntent(intent)) throw new CountersignError(`intent ${intent.intent_id} does not carry a valid agent signature (edited in the store?)`);
    if (rec.status === "abandoned") {
      report.abandoned.push(intent);
      return;
    }
    if (rec.status === "final") {
      if (!rec.logged) report.completed.push({ intent, resolution: await this.complete(intent, rec.resolution!) });
      return;
    }
    const fromLog = await this.finalFromLog(intent);
    if (fromLog) {
      report.completed.push({ intent, resolution: await this.complete(intent, await store.finalize(intent, fromLog)) });
      return;
    }
    // The Intent's own deadline, never the copy stored beside it (which an older or
    // edited file could get wrong): the Default fires exactly when the Intent says.
    if (Date.now() >= deadline(intent)) {
      const winner = await store.finalize(intent, defaultResolution(intent, this.authority));
      report.lapsed.push({ intent, resolution: await this.complete(intent, winner) });
      return;
    }
    if (redeliver === "all" || (redeliver === "undelivered" && !rec.delivered)) {
      let unreached: readonly string[] = [];
      let reachedNobody = false;
      try {
        await adapter.deliver(intent);
      } catch (err) {
        if (!(err instanceof DeliveryPartialError) || err.reached.length === 0) {
          if (!rec.delivered) {
            // Nobody has ever seen it: abandon it, so it is not re-armed unseen.
            await store.abandon(intent.intent_id, `re-delivery failed: ${err instanceof Error ? err.message : String(err)}`);
            report.abandoned.push(intent);
            return;
          }
          // An earlier delivery reached people who still hold live buttons: keep it
          // pending and re-armed, and report this attempt's failure.
          report.redeliveryFailed.push({ intent, error: err instanceof Error ? err : new CountersignError(String(err)) });
          reachedNobody = true;
        } else {
          // Reached some: as in issue(), it stays pending and those reached can decide it.
          unreached = err.unreached;
        }
      }
      if (!reachedNobody) {
        await store.markDelivered(intent.intent_id, unreached);
        report.redelivered.push(intent);
      }
    }
    // Registered with the adapter before restore() returns: an answer that arrives
    // the moment it does is counted.
    this.arm(intent);
    const resolution = this.decide(intent);
    void resolution.catch(() => {}); // the caller handles it; never an unhandled rejection
    report.rearmed.push({ intent, resolution });
  }

  private async decideOnce(intent: Intent): Promise<Resolution> {
    const { store, adapter } = this.opts;
    const rec = await store.get(intent.intent_id);
    if (rec?.status === "abandoned") throw new CountersignError(`intent ${intent.intent_id} was abandoned (${rec.reason}); it cannot be decided`);
    if (rec?.status === "final") return this.complete(intent, rec.resolution!);
    const fromLog = await this.finalFromLog(intent);
    if (fromLog) return this.complete(intent, await store.finalize(intent, fromLog));
    if (!rec) await store.issue(intent);
    const answer = this.armed.get(intent.intent_id) ?? adapter.awaitResolution(intent);
    this.armed.delete(intent.intent_id);
    const resolution = await awaitWithDefault(intent, answer, this.authority, this.opts.webauthn);
    return this.complete(intent, await store.finalize(intent, resolution));
  }

  private arm(intent: Intent): void {
    if (this.armed.has(intent.intent_id)) return;
    const p = this.opts.adapter.awaitResolution(intent);
    void p.catch(() => {}); // consumed later by decide(); never an unhandled rejection
    this.armed.set(intent.intent_id, p);
  }

  /** Verify the final Resolution, write it to the log unless it is there, and mark it logged. */
  private async complete(intent: Intent, resolution: Resolution): Promise<Resolution> {
    const { store, receiptLog } = this.opts;
    // The store is a file someone could edit: never hand back a Resolution that does not verify.
    verifyResolution(intent, resolution, this.authorityPub, this.opts.webauthn);
    const rec = await store.get(intent.intent_id);
    if (rec?.logged) return resolution;
    if (receiptLog && !(await this.logHas(resolution))) await receiptLog.record(resolution, intent);
    await store.markLogged(intent.intent_id);
    return resolution;
  }

  private async logHas(resolution: Resolution): Promise<boolean> {
    const log = this.opts.receiptLog;
    if (!hasHistory(log)) return false;
    const id = resolution.countersignatures[0]?.intent_id;
    const stored = new Set(((await log.history()).get(id) ?? []).map((c) => c.signature));
    return resolution.countersignatures.every((c) => stored.has(c.signature));
  }

  /** A final Resolution rebuilt from receipts already in the log, if they verify; else undefined. */
  private async finalFromLog(intent: Intent): Promise<Resolution | undefined> {
    const log = this.opts.receiptLog;
    if (!hasHistory(log)) return undefined;
    const receipts = (await log.history()).get(intent.intent_id) ?? [];
    const candidates: Resolution[] = [];
    for (const c of receipts) {
      if (c.policy === "default") candidates.push({ decision: c.decision, policy: "default", countersignatures: [c] });
      else if (c.decision === "reject") candidates.push({ decision: "reject", policy: "approver", countersignatures: [c] });
    }
    const approvals = new Map<string, Countersignature>();
    for (const c of receipts) if (c.policy === "approver" && c.decision === "approve") approvals.set(normalizeActor(c.actor), c);
    if (approvals.size >= quorumOf(intent)) candidates.push({ decision: "approve", policy: "approver", countersignatures: [...approvals.values()] });
    for (const r of candidates) {
      try {
        verifyResolution(intent, r, this.authorityPub, this.opts.webauthn);
        return r;
      } catch {
        // not a valid final decision; keep looking
      }
    }
    return undefined;
  }
}
