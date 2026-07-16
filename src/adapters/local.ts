// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { userInfo } from "node:os";
import { assertVouchedApprovers, authorityKeyFromEnv, formatIntent, type Adapter } from "../adapter.js";
import { signDecision } from "../core/countersignature.js";
import { CountersignError } from "../core/errors.js";
import { quorumOf } from "../core/intent.js";
import type { Intent, Resolution } from "../core/types.js";

/**
 * No-network adapter: the "channel" is the terminal you are sitting at.
 * Useful for demos, tests, and CI — requires no tokens of any kind.
 *
 * SINGLE-APPROVER ONLY. One terminal cannot independently authenticate distinct
 * humans — a single operator could type any names — so this adapter refuses
 * `quorum > 1` rather than pretend to enforce a distinct-human control (the same
 * stance EmailAdapter takes for its single bearer link). Use a chat adapter,
 * where distinct people each respond, for real M-of-N.
 */
export class LocalAdapter implements Adapter {
  readonly channel = "local";

  constructor(private readonly authorityKey: string = authorityKeyFromEnv()) {}

  async deliver(intent: Intent): Promise<void> {
    assertVouchedApprovers(intent); // this adapter is vouched-only; keyed approvers use the SigningServer
    if (quorumOf(intent) > 1) {
      throw new CountersignError(
        `local adapter supports a single approver (quorum 1); intent ${intent.intent_id} requires ${quorumOf(intent)}. ` +
          `One terminal cannot authenticate distinct humans — use a chat adapter for M-of-N.`,
      );
    }
    stdout.write(`\n${formatIntent(intent)}\n\n`);
  }

  async awaitResolution(intent: Intent): Promise<Resolution> {
    const rl = createInterface({ input: stdin });
    const who = userInfo().username;
    const actor = `local:${who}`;
    try {
      stdout.write(`${who}: approve "${intent.action}"? [y/N] `);
      const next = await rl[Symbol.asyncIterator]().next();
      const answer = next.done ? "" : String(next.value).trim();
      const decision: "approve" | "reject" = /^y(es)?$/i.test(answer) ? "approve" : "reject";
      return { decision, policy: "approver", countersignatures: [signDecision(intent, decision, actor, this.authorityKey)] };
    } finally {
      rl.close();
    }
  }
}
