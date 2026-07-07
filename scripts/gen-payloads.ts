// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Regenerates examples/payloads/*.json with really-signed envelopes so the
// schema tests always validate true-to-life data.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { signDecision } from "../src/core/countersignature.js";
import { defaultCountersignature } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";

const dir = join(import.meta.dirname, "..", "examples", "payloads");
mkdirSync(dir, { recursive: true });

const agent = { id: "agent:example", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;

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

const approved = signDecision(intent, "approve", "telegram:8675309", authority);
const rejected = signDecision(intent, "reject", "email:ops@example.com", authority);
const timedOut = defaultCountersignature(intent, authority);

const write = (name: string, value: unknown) => {
  writeFileSync(join(dir, name), JSON.stringify(value, null, 2) + "\n");
  console.log(`wrote examples/payloads/${name}`);
};

write("intent.example.json", intent);
write("countersignature.approve.example.json", approved);
write("countersignature.reject.example.json", rejected);
write("countersignature.default-timeout.example.json", timedOut);
