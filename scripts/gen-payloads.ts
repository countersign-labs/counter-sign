// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Regenerates examples/payloads/*.json with really-signed envelopes so the
// schema tests always validate true-to-life data.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { signDecision } from "../src/core/countersignature.js";
import { deadline, defaultResolution } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";

const dir = join(import.meta.dirname, "..", "examples", "payloads");
mkdirSync(dir, { recursive: true });

const agent = { id: "agent:example", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;

// A single-approver, vouched Intent — the frictionless button flow.
const intent = createIntent(
  {
    action: "billing.refund",
    summary: "Refund $42.00 to customer #1337 for order A-2041",
    risk_tier: "high",
    approvers: ["telegram:8675309", "email:ops@example.com"],
    timeout: 300,
    default: "reject",
    callback: "https://agent.example.com/countersign/callback",
  },
  agent,
);

// A two-person (four-eyes) Intent. quorum > 1 requires KEYED approvers, so each
// manager signs with their own key — a compromised server cannot forge the quorum.
const alice = generateKeypair();
const bob = generateKeypair();
const quorumIntent = createIntent(
  {
    action: "prod.deploy",
    summary: "Deploy release 2.4.0 to production (two-person rule)",
    risk_tier: "critical",
    approvers: [
      { actor: "slack:U024BE7LH", mode: "keyed", public_key: alice.publicKey },
      { actor: "slack:U07QX9ZLE", mode: "keyed", public_key: bob.publicKey },
    ],
    quorum: 2,
    timeout: 600,
    default: "reject",
    callback: null,
  },
  agent,
);

// Vouched receipts (authority-signed) over the single-approver Intent.
const approved = signDecision(intent, "approve", "telegram:8675309", authority);
const rejected = signDecision(intent, "reject", "email:ops@example.com", authority);
// A KEYED receipt — approver Alice signs her own approval with HER key (not the
// authority key), so it verifies independently and the server cannot forge it.
const keyed = signDecision(quorumIntent, "approve", "slack:U024BE7LH", alice.secretKey, "approver");
// The vector represents a timeout that has already fired. Advance the guard's
// wall clock to the exact deadline so defaultResolution mints a conforming,
// on-time receipt without making payload generation wait five minutes.
const timedOut = (() => {
  const actualNow = Date.now;
  try {
    Date.now = () => deadline(intent);
    return defaultResolution(intent, authority).countersignatures[0];
  } finally {
    Date.now = actualNow;
  }
})();

const write = (name: string, value: unknown) => {
  writeFileSync(join(dir, name), JSON.stringify(value, null, 2) + "\n");
  console.log(`wrote examples/payloads/${name}`);
};

write("intent.example.json", intent);
write("intent.quorum.example.json", quorumIntent);
write("countersignature.approve.example.json", approved);
write("countersignature.reject.example.json", rejected);
write("countersignature.keyed.example.json", keyed);
write("countersignature.default-timeout.example.json", timedOut);
