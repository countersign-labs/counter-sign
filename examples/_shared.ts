// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Shared demo harness: wraps a pretend high-risk action with counter-sign,
// prints the resulting Countersignature, and verifies its signature.

import type { Adapter } from "../src/adapter.js";
import { verifyCountersignature } from "../src/core/countersignature.js";
import { IntentRejectedError } from "../src/core/errors.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Countersignature, IntentFields } from "../src/core/types.js";
import { verifyIntent } from "../src/core/intent.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { wrapAction } from "../src/shim.js";

/** The pretend tool call being guarded in every demo. */
export async function issueRefund(amountUsd: number): Promise<{ receipt: string; amountUsd: number }> {
  return { receipt: `refund-${Math.random().toString(36).slice(2, 8)}`, amountUsd };
}

export function demoFields(overrides: Partial<IntentFields> = {}): IntentFields {
  return {
    action: "billing.refund",
    summary: "Refund $42.00 to customer #1337 for order A-2041",
    risk_tier: "high",
    approvers: ["demo:approver"],
    timeout: 300,
    default: "reject",
    ...overrides,
  };
}

export async function runDemo(adapter: Adapter, fields: IntentFields): Promise<void> {
  const agent = { id: process.env.COUNTERSIGN_AGENT_ID ?? "agent:demo", keypair: generateKeypair() };
  let countersignature: Countersignature | undefined;

  // Set COUNTERSIGN_RECEIPT_LOG to a file path to give this run a persistent,
  // re-verifiable approval history where it is installed.
  const receiptLog = process.env.COUNTERSIGN_RECEIPT_LOG ? new ReceiptLog(process.env.COUNTERSIGN_RECEIPT_LOG) : undefined;

  const refund = wrapAction(issueRefund, fields, adapter, {
    agent,
    receiptLog,
    onIntent: (intent) => {
      console.log(`\n→ Intent ${intent.intent_id} signed (verifies: ${verifyIntent(intent)}) and delivered via ${adapter.channel}.`);
      console.log(`  Waiting up to ${intent.timeout}s; on silence the default is "${intent.default}".`);
    },
    onDecision: (cs) => {
      countersignature = cs;
    },
  });

  try {
    const result = await refund(42);
    console.log(`\n✓ Action executed:`, result);
  } catch (err) {
    if (err instanceof IntentRejectedError) {
      console.log(`\n✗ Action blocked: ${err.message}`);
    } else {
      throw err;
    }
  } finally {
    await adapter.close?.();
  }

  if (!countersignature) {
    console.error("No countersignature was produced — something is wrong.");
    process.exitCode = 1;
    return;
  }

  console.log(`\nCountersignature (portable receipt):`);
  console.log(JSON.stringify(countersignature, null, 2));
  const valid = verifyCountersignature(countersignature);
  console.log(`\nSignature verifies: ${valid}`);
  if (!valid) process.exitCode = 1;

  if (receiptLog) {
    const report = await receiptLog.verifyAll();
    console.log(`\nReceipt log ${receiptLog.filePath}: ${report.total} receipt(s), all verify: ${report.ok}.`);
  }
}

/**
 * Ensure one authority key exists for this process so the adapter and the
 * shim sign/verify against the SAME key. wrapAction only accepts a
 * Countersignature signed by the authority it trusts, so the adapter that
 * produces decisions must share this key. Real deployments set
 * COUNTERSIGN_AUTHORITY_KEY (via `npm run keygen`); demos synthesize one.
 */
export function ensureAuthorityKey(): string {
  if (!process.env.COUNTERSIGN_AUTHORITY_KEY) {
    process.env.COUNTERSIGN_AUTHORITY_KEY = generateKeypair().secretKey;
  }
  return process.env.COUNTERSIGN_AUTHORITY_KEY;
}

export function requireEnvOrExplain(vars: string[], setupHint: string): void {
  const missing = vars.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    console.error(`Missing env vars: ${missing.join(", ")}\n${setupHint}`);
    console.error(`Copy .env.example to .env, fill these in, then run again (e.g. with: npx dotenvx run -- ... or export them).`);
    process.exit(1);
  }
}
