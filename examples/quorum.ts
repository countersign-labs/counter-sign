// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// No-network illustration of the M-of-N quorum MECHANISM (distinct-actor
// accumulation, veto, receipts) using PendingDecisions directly.
//
// IMPORTANT: this SIMULATES two independent approvers to show how quorum works —
// it does NOT authenticate humans. Real M-of-N needs a channel where distinct
// people each respond (the chat adapters). The local and email adapters are
// single-approver and refuse quorum > 1, precisely because one terminal / one
// bearer link cannot represent distinct humans.
//   npm run demo:quorum

import { PendingDecisions } from "../src/adapter.js";
import { verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Intent } from "../src/core/types.js";
import { ensureAuthorityKey } from "./_shared.js";

const authorityKey = ensureAuthorityKey();
const agent = { id: process.env.COUNTERSIGN_AGENT_ID ?? "agent:demo", keypair: generateKeypair() };

function newIntent(): Intent {
  return createIntent(
    {
      action: "prod.deploy",
      summary: "Deploy release 2.4.0 to production (two-person rule)",
      risk_tier: "critical",
      approvers: ["m:alice", "m:bob"],
      quorum: 2,
      timeout: 300,
      default: "reject",
    },
    agent,
  );
}

console.log("A 2-of-2 quorum — the action runs only after BOTH distinct approvers approve:");
{
  const pd = new PendingDecisions();
  const intent = newIntent();
  const resolution = awaitWithDefault(intent, pd.wait(intent), authorityKey);
  console.log("  m:alice approves ->", pd.settle(intent.intent_id, "approve", "m:alice", authorityKey)?.status, "(1/2)");
  console.log("  m:bob   approves ->", pd.settle(intent.intent_id, "approve", "m:bob", authorityKey)?.status, "(2/2)");
  const r = await resolution;
  console.log(`  => ${r.decision.toUpperCase()} (policy: ${r.policy}) from ${r.countersignatures.length} receipt(s):`);
  for (const cs of r.countersignatures) console.log(`     ${cs.actor}: ${cs.decision}  (verifies: ${verifyCountersignature(cs)})`);
}

console.log("\nAny single reject vetoes immediately (m:alice approves, m:bob rejects):");
{
  const pd = new PendingDecisions();
  const intent = newIntent();
  const resolution = awaitWithDefault(intent, pd.wait(intent), authorityKey);
  pd.settle(intent.intent_id, "approve", "m:alice", authorityKey);
  console.log("  m:bob rejects ->", pd.settle(intent.intent_id, "reject", "m:bob", authorityKey)?.decision);
  const r = await resolution;
  console.log(`  => ${r.decision.toUpperCase()} — one veto blocks the action, whatever approvals were collected.`);
}
