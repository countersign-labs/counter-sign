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
// @experimental — the browser-passkey web-delivery CHANNEL is still stabilizing. The
// SECURITY guarantees are the same as every keyed path (the server holds no approver
// key), but this async delivery/collection glue is not yet frozen. For production keyed
// approvals today, prefer raw-ed25519 approvers signing with the `approve` CLI (stable),
// or vouched approvers via the chat/email adapters. The core protocol does not depend
// on this adapter.

import { CountersignError } from "../core/errors.js";
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
    // the loop isn't lost when awaitResolution() runs after deliver() returns.
    const pending = this.server.awaitResolution(intent);
    this.captured.set(intent.intent_id, pending);
    // Safety handler: if this wait is later rejected by a fail-closed cancel() or a
    // concurrent close()/abort, don't let it surface as an unhandled rejection. The real
    // consumer (awaitResolution → awaitWithDefault) still observes the same outcome.
    pending.catch(() => {});

    // BEST-EFFORT delivery. One approver's channel being down must NOT abort a quorum
    // the OTHER approvers can still satisfy (any M-of-N with M < N, and every 1-of-N),
    // and an approval already in flight must not be cancelled out from under itself.
    // Send every link, counting successes.
    let delivered = 0;
    let firstError: unknown;
    for (const link of links) {
      try {
        await this.notify(link);
        delivered += 1;
      } catch (err) {
        firstError ??= err;
      }
    }
    // Fail closed ONLY when NOTHING could be delivered: no approver has a link, so none
    // can ever decide, and a default:"approve" Intent must not time out to approve on a
    // total delivery failure. (delivered === 0 ⇒ no decision could have landed, so no
    // isPending race to worry about.) A PARTIAL delivery is fine: the reachable approvers
    // may meet quorum, and if they can't it times out to the Default — reject for any
    // quorum > 1 — which fails SAFE, never open.
    if (delivered === 0) {
      this.captured.delete(intent.intent_id);
      const err = firstError instanceof Error ? firstError : new CountersignError(`delivery failed for every approver of intent ${intent.intent_id}`);
      this.server.cancel(intent, err);
      throw err;
    }
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    // Return the promise deliver() captured — it survives a resolve+evict during the
    // notify loop, and a reject from a concurrent close(). Only if there is none do we
    // consider a fresh wait; after close() we refuse (a fresh wait would never resolve,
    // and letting it fall to the timeout Default would be a fail-open on shutdown).
    const p = this.captured.get(intent.intent_id);
    this.captured.delete(intent.intent_id);
    if (p) return p;
    if (this.closed) return Promise.reject(new CountersignError("signing-link adapter is closed"));
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
