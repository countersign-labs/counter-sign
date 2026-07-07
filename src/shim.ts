// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { authorityKeyFromEnv, type Adapter } from "./adapter.js";
import { awaitWithDefault } from "./core/defaults.js";
import { IntentRejectedError } from "./core/errors.js";
import { createIntent, type AgentIdentity } from "./core/intent.js";
import { generateKeypair } from "./core/keys.js";
import type { Countersignature, Intent, IntentFields } from "./core/types.js";

export interface WrapOptions {
  /** Signing identity of the requesting agent. Defaults to a per-process keypair. */
  agent?: AgentIdentity;
  /** Authority seed used when the timeout Default fires. Defaults to COUNTERSIGN_AUTHORITY_KEY. */
  authorityKey?: string;
  /** Observe the signed Intent before delivery. */
  onIntent?: (intent: Intent) => void;
  /** Observe the Countersignature (approve, reject, or default) once produced. */
  onDecision?: (cs: Countersignature) => void;
}

let processAgent: AgentIdentity | undefined;

function defaultAgent(): AgentIdentity {
  processAgent ??= {
    id: process.env.COUNTERSIGN_AGENT_ID ?? "agent:local",
    keypair: generateKeypair(),
  };
  return processAgent;
}

/**
 * Wrap any function so it only runs once a human countersigns the intent.
 *
 *   const deploy = wrapAction(deployProd,
 *     { action: "deploy.prod", summary: "Deploy v2.1.0 to production",
 *       risk_tier: "high", approvers: ["telegram:8675309"], timeout: 300, default: "reject" },
 *     new TelegramAdapter());
 *   await deploy("v2.1.0");
 *
 * On approve, the wrapped function runs and its result is returned. On
 * reject — explicit or by timeout Default — IntentRejectedError is thrown,
 * carrying the Countersignature as the audit receipt.
 */
export function wrapAction<A extends unknown[], R>(
  fn: (...args: A) => R | Promise<R>,
  fields: IntentFields,
  adapter: Adapter,
  opts: WrapOptions = {},
): (...args: A) => Promise<R> {
  return async (...args: A): Promise<R> => {
    const agent = opts.agent ?? defaultAgent();
    const intent = createIntent(fields, agent);
    opts.onIntent?.(intent);

    await adapter.deliver(intent);
    const authority = opts.authorityKey ?? authorityKeyFromEnv();
    const cs = await awaitWithDefault(intent, adapter.awaitDecision(intent), authority);
    opts.onDecision?.(cs);
    if (intent.callback) void postCallback(intent.callback, cs);

    if (cs.decision !== "approve") throw new IntentRejectedError(cs, intent);
    return await fn(...args);
  };
}

async function postCallback(url: string, cs: Countersignature): Promise<void> {
  try {
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cs),
    });
  } catch {
    // Callback delivery is best-effort; the receipt still exists locally.
  }
}
