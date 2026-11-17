// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

/**
 * Test-only bridge from the Python client's tests to the TypeScript reference.
 * Run with tsx from the repository root:
 *
 *   tsx clients/python/tests/support/ts_interop.ts <command> [args]   < request.json
 *
 * It reads one JSON request on stdin and prints one JSON result on stdout, so
 * the Python side can compare what the reference produces with what it
 * produces itself. Nothing here is part of the package.
 *
 *   create-intent        {fields, agent_id, agent_secret}         -> Intent
 *   create-intents       {cases: [{fields, agent_id, agent_secret}]}
 *                                                                   -> [{ok, intent} | {ok, error}]
 *   write-log <path>     {agent_id, agent_secret, authority_secret} -> {intents, head, history}
 *   verify-log <path>    {intents?, authority_key?, trusted_keys?, trusted_agent_keys?, expected_head?, repair_torn_tail?}
 *                                                                   -> {head, history, report}
 */

import { createIntent } from "../../../../src/core/intent.js";
import { signDecision } from "../../../../src/core/countersignature.js";
import { deadline } from "../../../../src/core/defaults.js";
import { publicKeyFromSecret } from "../../../../src/core/keys.js";
import type { Countersignature, Intent, IntentFields } from "../../../../src/core/types.js";
import { ReceiptLog } from "../../../../src/receipt-log.js";

async function readStdin(): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8").trim();
  return text ? JSON.parse(text) : {};
}

function agentOf(id: string, secret: string) {
  return { id, keypair: { publicKey: publicKeyFromSecret(secret), secretKey: secret } };
}

function historyObject(map: Map<string, Countersignature[]>): Record<string, Countersignature[]> {
  return Object.fromEntries(map);
}

async function main(): Promise<void> {
  const [command, path] = process.argv.slice(2);
  const req = await readStdin();

  if (command === "create-intent") {
    const intent = createIntent(req.fields as IntentFields, agentOf(req.agent_id, req.agent_secret));
    process.stdout.write(JSON.stringify(intent));
    return;
  }

  if (command === "create-intents") {
    // Many cases in one process: each is {fields, agent_id, agent_secret}; each
    // result says whether the reference accepted it, with the Intent or the error.
    const out = (req.cases as any[]).map((c) => {
      try {
        return { ok: true, intent: createIntent(c.fields as IntentFields, agentOf(c.agent_id, c.agent_secret)) };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? `${err.name}: ${err.message}` : String(err) };
      }
    });
    process.stdout.write(JSON.stringify(out));
    return;
  }

  if (command === "write-log") {
    if (!path) throw new Error("write-log needs a file path");
    const agent = agentOf(req.agent_id, req.agent_secret);
    const authority: string = req.authority_secret;
    const keyed: { actor: string; secret: string }[] = req.keyed ?? [];
    const log = new ReceiptLog(path);
    const intents: Intent[] = [];

    // 1. A vouched approval.
    const vouched = createIntent(
      { action: "billing.refund", summary: "Refund 42.00 to customer 8675309", risk_tier: "high", approvers: ["tg:alice"], timeout: 300, default: "reject" },
      agent,
    );
    intents.push(vouched);
    await log.record({ intent_id: vouched.intent_id, decision: "approve", policy: "approver", countersignatures: [signDecision(vouched, "approve", "tg:alice", authority)] } as any);

    // 2. A keyed two-of-two approval, each receipt signed by the approver's own key.
    if (keyed.length >= 2) {
      const quorum = createIntent(
        {
          action: "prod.deploy",
          summary: "Deploy 2.4.0 to production",
          risk_tier: "critical",
          approvers: keyed.map((k) => ({ actor: k.actor, mode: "keyed" as const, public_key: publicKeyFromSecret(k.secret) })),
          quorum: 2,
          timeout: 600,
          default: "reject",
        },
        agent,
      );
      intents.push(quorum);
      await log.record({
        intent_id: quorum.intent_id,
        decision: "approve",
        policy: "approver",
        countersignatures: keyed.slice(0, 2).map((k) => signDecision(quorum, "approve", k.actor, k.secret)),
      } as any);
    }

    // 3. A veto: one vouched reject.
    const vetoed = createIntent(
      { action: "mail.send", summary: "Send the weekly newsletter", risk_tier: "medium", approvers: ["slack:U0BOB"], timeout: 120, default: "reject" },
      agent,
    );
    intents.push(vetoed);
    await log.append(signDecision(vetoed, "reject", "slack:U0BOB", authority));

    // 4. A timeout Default, stamped at the deadline.
    const silent = createIntent(
      { action: "post.publish", summary: "Publish the LinkedIn post", risk_tier: "low", approvers: ["tg:carol"], timeout: 1, default: "reject" },
      agent,
    );
    intents.push(silent);
    await log.append(signDecision(silent, "reject", "default:timeout", authority, "default", new Date(deadline(silent)).toISOString()));

    process.stdout.write(JSON.stringify({ intents, head: await log.head(), history: historyObject(await log.history()) }));
    return;
  }

  if (command === "verify-log") {
    if (!path) throw new Error("verify-log needs a file path");
    const log = new ReceiptLog(path, req.repair_torn_tail ? { repairTornTail: true } : {});
    const opts: Record<string, unknown> = {};
    if (req.intents !== undefined) opts.intents = req.intents;
    if (req.authority_key !== undefined) opts.authorityKey = req.authority_key;
    if (req.trusted_keys !== undefined) opts.trustedKeys = req.trusted_keys;
    if (req.trusted_agent_keys !== undefined) opts.trustedAgentKeys = req.trusted_agent_keys;
    if (req.expected_head !== undefined) opts.expectedHead = req.expected_head;
    const report = await log.verifyAll(opts);
    // history() throws on a line that is not a receipt; report that as null.
    const history = await log.history().then(historyObject, () => null);
    process.stdout.write(JSON.stringify({ head: await log.head(), history, report }));
    return;
  }

  throw new Error(`unknown command ${JSON.stringify(command)}`);
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
