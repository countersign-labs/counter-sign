// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// No-network two-person (quorum 2) demo. The LocalAdapter prompts for each
// distinct approver in turn; the action runs only after BOTH approve, and any
// single reject vetoes. Prints every contributing receipt and verifies it.
//   npm run demo:quorum
// (pipe input, e.g.:  printf 'alice\ny\nbob\ny\n' | npm run demo:quorum )

import { LocalAdapter } from "../src/adapters/local.js";
import { verifyCountersignature } from "../src/core/countersignature.js";
import { IntentRejectedError } from "../src/core/errors.js";
import { generateKeypair } from "../src/core/keys.js";
import { wrapAction } from "../src/shim.js";
import { demoFields, ensureAuthorityKey, issueRefund } from "./_shared.js";

ensureAuthorityKey();
const agent = { id: process.env.COUNTERSIGN_AGENT_ID ?? "agent:demo", keypair: generateKeypair() };

const deploy = wrapAction(
  issueRefund,
  demoFields({
    action: "prod.deploy",
    summary: "Deploy release 2.4.0 to production (two-person rule)",
    risk_tier: "critical",
    approvers: ["local:alice", "local:bob"],
    quorum: 2,
  }),
  new LocalAdapter(),
  {
    agent,
    onResolution: (r) => {
      console.log(`\nResolution: ${r.decision.toUpperCase()} (policy: ${r.policy}) from ${r.countersignatures.length} receipt(s):`);
      for (const cs of r.countersignatures) {
        console.log(`  - ${cs.actor}: ${cs.decision}  (verifies: ${verifyCountersignature(cs)})`);
      }
    },
  },
);

try {
  const result = await deploy(42);
  console.log("\n✓ Action executed (both approved):", result);
} catch (err) {
  if (err instanceof IntentRejectedError) console.log(`\n✗ Action blocked: ${err.message}`);
  else throw err;
}
