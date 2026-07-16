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

  constructor(cfg: SigningLinkAdapterConfig) {
    this.server = cfg.server;
    this.notify = cfg.notify;
    this.channel = cfg.channel ?? "signing";
    this.webauthn = cfg.server.webauthn;
  }

  async deliver(intent: Intent): Promise<void> {
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
    // Register the collection point BEFORE any link goes out: record() needs the
    // pending entry to exist, so an approver who taps immediately must not race a
    // not-yet-registered Intent. wait() is idempotent, so awaitResolution() returns
    // this very promise. Hold it here only to swallow the rejection cancel() raises
    // on a delivery failure (nobody awaits it on that path → unhandled rejection).
    const pending = this.server.awaitResolution(intent);
    try {
      for (const link of links) await this.notify(link);
    } catch (err) {
      pending.catch(() => {});
      this.server.cancel(intent, err instanceof Error ? err : new Error(String(err)));
      throw err;
    }
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    // The idempotent wait() returns the same promise deliver() registered.
    return this.server.awaitResolution(intent);
  }
}
