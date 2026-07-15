// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// No-network illustration of the M-of-N quorum MECHANISM under v0.2: quorum > 1
// requires KEYED approvers, so each approver signs their OWN receipt with their
// OWN key (a compromised authority key cannot forge the quorum). The server only
// COLLECTS the pre-signed receipts (PendingDecisions.record).
//
// In a real deployment each keyed approver signs via the SigningServer passkey
// page (deep-linked to them) or the `npm run approve` CLI; here we simulate two
// approvers with two keypairs to show the accumulation, the veto, and that the
// authority key alone cannot satisfy the quorum.
//   npm run demo:quorum

import { PendingDecisions } from "../src/adapter.js";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault, verifyResolution } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Intent, Resolution } from "../src/core/types.js";
import { ensureAuthorityKey } from "./_shared.js";

const authorityKey = ensureAuthorityKey();
const authorityPub = publicKeyFromSecret(authorityKey);
const agent = { id: process.env.COUNTERSIGN_AGENT_ID ?? "agent:demo", keypair: generateKeypair() };

// Each approver holds their OWN key; the server never sees the secret.
const alice = generateKeypair();
const bob = generateKeypair();

function newIntent(): Intent {
  return createIntent(
    {
      action: "prod.deploy",
      summary: "Deploy release 2.4.0 to production (two-person rule)",
      risk_tier: "critical",
      approvers: [
        { actor: "m:alice", mode: "keyed", public_key: alice.publicKey },
        { actor: "m:bob", mode: "keyed", public_key: bob.publicKey },
      ],
      quorum: 2,
      timeout: 300,
      default: "reject",
    },
    agent,
  );
}

console.log("A keyed 2-of-2 quorum — each approver signs with THEIR OWN key; the action runs only after both:");
{
  const pd = new PendingDecisions();
  const intent = newIntent();
  const resolution = awaitWithDefault(intent, pd.wait(intent), authorityKey);
  console.log("  m:alice signs approve ->", pd.record(signDecision(intent, "approve", "m:alice", alice.secretKey, "approver"))?.status, "(1/2)");
  console.log("  m:bob   signs approve ->", pd.record(signDecision(intent, "approve", "m:bob", bob.secretKey, "approver"))?.status, "(2/2)");
  const r = await resolution;
  console.log(`  => ${r.decision.toUpperCase()} (policy: ${r.policy}) from ${r.countersignatures.length} receipt(s):`);
  for (const cs of r.countersignatures) console.log(`     ${cs.actor}: ${cs.decision}  (verifies: ${verifyCountersignature(cs)})`);
}

console.log("\nA single reject vetoes immediately (m:alice approves, m:bob rejects):");
{
  const pd = new PendingDecisions();
  const intent = newIntent();
  const resolution = awaitWithDefault(intent, pd.wait(intent), authorityKey);
  pd.record(signDecision(intent, "approve", "m:alice", alice.secretKey, "approver"));
  console.log("  m:bob signs reject ->", pd.record(signDecision(intent, "reject", "m:bob", bob.secretKey, "approver"))?.decision);
  const r = await resolution;
  console.log(`  => ${r.decision.toUpperCase()} — one veto blocks the action, whatever approvals were collected.`);
}

console.log("\nSeparation of duty: holding ONLY the authority key, you CANNOT forge the quorum:");
{
  const intent = newIntent();
  const forged: Resolution = {
    decision: "approve",
    policy: "approver",
    countersignatures: [
      signDecision(intent, "approve", "m:alice", authorityKey, "approver"),
      signDecision(intent, "approve", "m:bob", authorityKey, "approver"),
    ],
  };
  try {
    verifyResolution(intent, forged, authorityPub);
    console.log("  => ACCEPTED — this should never happen!");
  } catch (e) {
    console.log(`  => REJECTED: ${(e as Error).message}`);
  }
}
