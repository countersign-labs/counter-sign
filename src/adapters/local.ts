// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { userInfo } from "node:os";
import { authorityKeyFromEnv, formatIntent, type Adapter } from "../adapter.js";
import { signDecision } from "../core/countersignature.js";
import type { Countersignature, Intent } from "../core/types.js";

/**
 * No-network adapter: the "channel" is the terminal you are sitting at.
 * Useful for demos, tests, and CI — requires no tokens of any kind.
 */
export class LocalAdapter implements Adapter {
  readonly channel = "local";

  constructor(private readonly authorityKey: string = authorityKeyFromEnv()) {}

  async deliver(intent: Intent): Promise<void> {
    stdout.write(`\n${formatIntent(intent)}\n\n`);
  }

  async awaitDecision(intent: Intent): Promise<Countersignature> {
    const rl = createInterface({ input: stdin, output: stdout });
    try {
      const answer = await rl.question(`Approve "${intent.action}"? [y/N] `);
      const decision = /^y(es)?$/i.test(answer.trim()) ? "approve" : "reject";
      return signDecision(intent, decision, `local:${userInfo().username}`, this.authorityKey);
    } finally {
      rl.close();
    }
  }
}
