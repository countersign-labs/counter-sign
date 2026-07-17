// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.
//
// SigningLinkAdapter — the Adapter that DELIVERS a keyed (passkey) Intent through
// the normal wrapAction path. The chat/email adapters are vouched-only (they
// refuse keyed approvers), and a bare SigningServer is not an Adapter, so without
// this there is no built-in way to run a multi-approver v0.2 request end-to-end.
//
// It composes with a SigningServer you have already mounted on an HTTP listener:
// deliver() sends each keyed approver their per-approver signing deep-link (via a
// `notify` callback that knows how to reach them — email, chat, SMS), and
// awaitResolution() hands back the SigningServer's collection promise. The server
// verifies each self-signed passkey receipt against the approver's OWN bound key,
// so — like every keyed path — a compromised authority server cannot forge it.
//
// Stable: the delivery/collection contract is frozen — deliver() fails closed
// on total delivery failure (and on ANY failure under default:"approve"), a decision that
// lands mid-delivery is never lost, and awaitResolution() is idempotent while the Intent
// is live. The SECURITY guarantees are the same as every keyed path: the server holds no
// approver key, so a compromised authority cannot forge a passkey approval. Raw-ed25519
// approvers sign out of band with the `approve` CLI instead of a web link. The core
// protocol does not depend on this adapter.

import { CountersignError } from "../core/errors.js";
import { deadline } from "../core/defaults.js";
import type { Adapter } from "../adapter.js";
import type { WebAuthnPolicy } from "../core/webauthn.js";
import type { Intent, Resolution } from "../core/types.js";
import type { SigningServer } from "../signing.js";

/** One approver's signing link, handed to `notify` for delivery. */
export interface SigningLink {
  /** the keyed approver this link is for */
  actor: string;
  /** the single-use signing URL to send them */
  url: string;
  /** the Intent being approved (for message context) */
  intent: Intent;
}

export interface SigningLinkAdapterConfig {
  /** The SigningServer that hosts the passkey page and collects the receipts. */
  server: SigningServer;
  /**
   * Deliver one approver's signing link to wherever that approver lives — email,
   * chat DM, SMS. Called once per keyed approver at delivery time. If it throws,
   * deliver() rejects (fail closed) and wrapAction never runs the action.
   */
  notify: (link: SigningLink) => void | Promise<void>;
  /** Actor-prefix channel name; defaults to "signing". */
  channel?: string;
}

export class SigningLinkAdapter implements Adapter {
  readonly channel: string;
  /** The SigningServer's RP policy, exposed so wrapAction verifies with the SAME
   *  policy the server signs against (a divergence would reject a valid assertion). */
  readonly webauthn: WebAuthnPolicy;
  private readonly server: SigningServer;
  private readonly notify: (link: SigningLink) => void | Promise<void>;
  /**
   * The resolution promise captured at deliver(), per intent. An approver can decide
   * WHILE the notify loop is still running — that resolves the wait and evicts the
   * PendingDecisions entry, so a later `wait()` (idempotent only while the entry is
   * alive) would mint a fresh, never-resolving promise and lose the real decision.
   * Caching the promise here lets awaitResolution() return the SAME (possibly already
   * resolved) promise instead.
   */
  private readonly captured = new Map<string, Promise<Resolution>>();
  private closed = false;

  constructor(cfg: SigningLinkAdapterConfig) {
    this.server = cfg.server;
    this.notify = cfg.notify;
    this.channel = cfg.channel ?? "signing";
    this.webauthn = cfg.server.webauthn;
  }

  async deliver(intent: Intent): Promise<void> {
    // Refuse new work once closed: otherwise a deliver() racing shutdown would register
    // a fresh wait and send links, and a default:"approve" request could execute after
    // the process was told to stop.
    if (this.closed) throw new CountersignError("signing-link adapter is closed");
    // Finality (spec §4) is enforced in PendingDecisions: once an intent RESOLVES, a
    // re-wait returns the recorded decision, not a fresh reopenable entry — so a second
    // deliver() of a resolved intent cannot be reopened by an un-consumed approver's
    // link. That guarantee lives at the shared layer (protecting every caller), which
    // also means re-delivering a STILL-PENDING intent (e.g. retrying after a swallowed
    // partial notify failure) safely re-notifies over the SAME idempotent wait here.
    // This adapter serves KEYED (passkey) approvers who sign their OWN receipt via
    // the SigningServer — the inverse of the vouched-only chat/email adapters. A
    // vouched approver has no key to sign a link with; refuse rather than silently
    // drop them from the quorum. Compute every link first (signingUrl also rejects a
    // raw-keyed/bot approver, who signs via the approve CLI, not a web link) so a
    // bad approver fails BEFORE we register the wait or send any link.
    const links: SigningLink[] = intent.approvers.map((a) => {
      if (a.mode !== "keyed")
        throw new CountersignError(
          `signing-link adapter serves keyed approvers only; ${a.actor} is vouched — use a chat/email adapter for it`,
        );
      return { actor: a.actor, url: this.server.signingUrl(intent, a.actor), intent };
    });
    // Register the collection point BEFORE any link goes out (record() needs the
    // pending entry to exist) and CAPTURE the promise so a decision that lands during
    // delivery isn't lost when awaitResolution() runs after deliver() returns.
    const pending = this.server.awaitResolution(intent);
    this.captured.set(intent.intent_id, pending);
    // Track whether the wait actually SETTLED — a real decision or a cancel/abort. This
    // is distinct from the deadline reaper merely evicting the entry (which leaves the
    // promise pending); `isPending` conflates the two, so a slow delivery crossing the
    // deadline would look "resolved" and skip the fail-closed guard below (a fail-open
    // under default:"approve"). The flag also serves as the no-unhandled-rejection catch.
    let settled = false;
    // Mark when the wait settles (real decision or abort) — but do NOT drop the captured
    // entry here: a decision that settles DURING delivery must still be returnable by the
    // awaitResolution() that runs after deliver(). The deadline timer below reclaims it
    // (bounded lifetime) so idempotent awaitResolution doesn't leak. Also serves as the
    // no-unhandled-rejection handler.
    pending.then(() => { settled = true; }, () => { settled = true; });

    // BEST-EFFORT delivery, CONCURRENTLY — independent channels; one slow/hung channel
    // must not block the others or sum their latencies. Count outcomes as they arrive;
    // `Promise.resolve().then(...)` normalizes a SYNCHRONOUS throw from notify to a
    // rejection so it doesn't escape the map.
    let delivered = 0;
    let firstError: unknown;
    const batch = Promise.allSettled(
      links.map((l) =>
        Promise.resolve()
          .then(() => this.notify(l))
          .then(() => { delivered += 1; }, (e) => { firstError ??= e; }),
      ),
    );
    // Do NOT block indefinitely on a hung notifier: proceed as soon as delivery finishes,
    // a decision (or close()/abort) SETTLES the wait, or the deadline passes — whichever is
    // first. Otherwise a never-settling notify would keep deliver() — and, since wrapAction
    // awaits it before awaitWithDefault, the whole operation including its timeout — pending.
    const remaining = Math.max(0, deadline(intent) - Date.now());
    await Promise.race([
      batch,
      pending.then(() => {}, () => {}),
      // At the deadline the Intent is dead (the runtime mints its Default). Also drop the
      // captured entry then, so a delivered-but-timed-out Intent (whose wait never settles)
      // doesn't linger in the map.
      new Promise<void>((res) => { const t = setTimeout(() => { this.captured.delete(intent.intent_id); res(); }, remaining); t.unref?.(); }),
    ]);

    // Swallow a partial delivery only when it fails SAFE: a decision already settled, or
    // the Default is `reject` (timeout → reject). Fail CLOSED on a TOTAL failure (nobody
    // can decide), or ANY failure under a `default:"approve"` Intent — the approve-Default
    // must not fire while a named approver never got their veto link. `delivered` is a
    // snapshot: a still-pending (hung) or failed notify counts as not delivered, so
    // `anyFailed` captures both. `settled` (not isPending) means the reaper can't mask it.
    const anyFailed = delivered < links.length;
    if (!settled && (delivered === 0 || (anyFailed && intent.default === "approve"))) {
      this.captured.delete(intent.intent_id);
      const err = firstError instanceof Error ? firstError : new CountersignError(`delivery incomplete for intent ${intent.intent_id} — failing closed`);
      this.server.cancel(intent, err);
      throw err;
    }
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    // Return the promise deliver() captured — it survives a resolve+evict during the
    // notify loop, and a reject from a concurrent close(). Idempotent: repeated calls
    // (e.g. a supervisor re-subscribing) return the SAME promise while it's live, rather
    // than minting a fresh, never-resolving wait; the settle/deadline cleanup removes it.
    const p = this.captured.get(intent.intent_id);
    if (p) return p;
    if (this.closed) return Promise.reject(new CountersignError("signing-link adapter is closed"));
    // Past the deadline the captured wait has been reclaimed and the intent is no longer
    // pending. Falling through to server.awaitResolution here would mint a BRAND-NEW wait whose
    // reaper fires immediately (remaining <= 0), leaving a promise that never resolves — a hang for
    // a raw await, or the wrong Default when wrapped in awaitWithDefault. Refuse deterministically
    // instead: a decision, if any, was returnable from `captured` throughout the intent's live
    // window; the durable outcome lives in the receipt log, not this best-effort in-memory wait.
    if (Date.now() >= deadline(intent))
      return Promise.reject(
        new CountersignError(`intent ${intent.intent_id} is past its deadline — no longer pending (its resolution was reclaimed; consult the receipt log for the durable outcome)`),
      );
    return this.server.awaitResolution(intent);
  }

  /**
   * Release in-flight waits on shutdown (matches the messaging adapters' close()). Does
   * NOT clear `captured`: a decision that already landed but hasn't been consumed by
   * awaitResolution() must still be returnable. Each captured wait gets a catch so the
   * abort below doesn't surface as an unhandled rejection.
   */
  close(): void {
    this.closed = true;
    for (const p of this.captured.values()) p.catch(() => {});
    this.server.close();
  }
}
