// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { userInfo } from "node:os";
import { authorityKeyFromEnv, formatIntent, type Adapter } from "../adapter.js";
import { signDecision } from "../core/countersignature.js";
import { quorumOf } from "../core/intent.js";
import type { Countersignature, Intent, Resolution } from "../core/types.js";

/**
 * No-network adapter: the "channel" is the terminal you are sitting at.
 * Useful for demos, tests, and CI — requires no tokens of any kind. Under
 * quorum it prompts for each distinct approver in turn; any reject vetoes.
 */
export class LocalAdapter implements Adapter {
  readonly channel = "local";

  constructor(private readonly authorityKey: string = authorityKeyFromEnv()) {}

  async deliver(intent: Intent): Promise<void> {
    stdout.write(`\n${formatIntent(intent)}\n\n`);
  }

  async awaitResolution(intent: Intent): Promise<Resolution> {
    const quorum = quorumOf(intent);
    const rl = createInterface({ input: stdin });
    // Read via the async line iterator, which buffers lines rather than
    // dropping ones that arrive between sequential rl.question() calls (a
    // readline race that breaks piped input for multi-prompt quorum flows).
    const lines = rl[Symbol.asyncIterator]();
    const ask = async (prompt: string): Promise<string> => {
      stdout.write(prompt);
      const next = await lines.next();
      return next.done ? "" : String(next.value).trim();
    };
    const approvals = new Map<string, Countersignature>();
    try {
      while (true) {
        const who = quorum > 1 ? (await ask(`Approver name (${approvals.size}/${quorum} approved so far): `)) || userInfo().username : userInfo().username;
        const answer = await ask(`${who}: approve "${intent.action}"? [y/N] `);
        const actor = `local:${who}`;
        if (!/^y(es)?$/i.test(answer)) {
          // A single reject (or EOF with no more input) vetoes the whole request.
          return {
            decision: "reject",
            policy: "approver",
            countersignatures: [signDecision(intent, "reject", actor, this.authorityKey)],
          };
        }
        approvals.set(actor, signDecision(intent, "approve", actor, this.authorityKey));
        if (approvals.size >= quorum) {
          return { decision: "approve", policy: "approver", countersignatures: [...approvals.values()] };
        }
      }
    } finally {
      rl.close();
    }
  }
}
