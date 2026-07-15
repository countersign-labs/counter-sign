// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/core/canonical.js";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { IntentFields } from "../src/core/types.js";

const fields: IntentFields = {
  action: "billing.refund",
  summary: "Refund $42",
  risk_tier: "high",
  approvers: ["email:ops@example.com"],
  timeout: 300,
  default: "reject",
};

describe("canonicalization", () => {
  it("sorts keys at every depth and strips whitespace", () => {
    expect(canonicalize({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: "x" } })).toBe(
      '{"a":{"c":"x","d":[2,{"y":2,"z":1}]},"b":1}',
    );
  });

  it("omits undefined members and rejects non-finite numbers", () => {
    expect(canonicalize({ a: undefined, b: null })).toBe('{"b":null}');
    expect(() => canonicalize({ a: Infinity })).toThrow(TypeError);
  });
});

describe("intent sign/verify round-trip", () => {
  it("verifies a freshly created intent", () => {
    const intent = createIntent(fields, { id: "agent:test", keypair: generateKeypair() });
    expect(verifyIntent(intent)).toBe(true);
  });

  it("fails verification when any field is tampered", () => {
    const intent = createIntent(fields, { id: "agent:test", keypair: generateKeypair() });
    expect(verifyIntent({ ...intent, summary: "Refund $42000" })).toBe(false);
    expect(verifyIntent({ ...intent, default: "approve" })).toBe(false);
    expect(verifyIntent({ ...intent, timeout: 30000 })).toBe(false);
  });

  it("fails verification with the wrong public key", () => {
    const intent = createIntent(fields, { id: "agent:test", keypair: generateKeypair() });
    const other = generateKeypair();
    expect(verifyIntent({ ...intent, agent: { ...intent.agent, public_key: other.publicKey } })).toBe(false);
  });
});

describe("countersignature sign/verify round-trip", () => {
  const agent = { id: "agent:test", keypair: generateKeypair() };
  const authority = generateKeypair();

  it("verifies and carries the authority public key", () => {
    const intent = createIntent(fields, agent);
    const cs = signDecision(intent, "approve", "email:ops@example.com", authority.secretKey);
    expect(cs.public_key).toBe(authority.publicKey);
    expect(cs.policy).toBe("approver");
    expect(verifyCountersignature(cs)).toBe(true);
  });

  it("fails verification when decision or actor is tampered", () => {
    const intent = createIntent(fields, agent);
    const cs = signDecision(intent, "reject", "email:ops@example.com", authority.secretKey);
    expect(verifyCountersignature({ ...cs, decision: "approve" })).toBe(false);
    expect(verifyCountersignature({ ...cs, actor: "email:attacker@example.com" })).toBe(false);
  });

  it("derives the same public key from the seed both ways", () => {
    const kp = generateKeypair();
    expect(publicKeyFromSecret(kp.secretKey)).toBe(kp.publicKey);
  });
});

describe("checked-in example payloads carry real signatures", () => {
  const load = (p: string) => JSON.parse(readFileSync(join(import.meta.dirname, "..", p), "utf8"));

  it("intent.example.json and the keyed quorum intent verify", () => {
    expect(verifyIntent(load("examples/payloads/intent.example.json"))).toBe(true);
    expect(verifyIntent(load("examples/payloads/intent.quorum.example.json"))).toBe(true);
  });

  it("all countersignature examples verify (incl. the keyed receipt, signed by the approver's own key)", () => {
    for (const name of ["approve", "reject", "keyed", "default-timeout"]) {
      expect(verifyCountersignature(load(`examples/payloads/countersignature.${name}.example.json`))).toBe(true);
    }
    // The keyed receipt's key is the approver's own — it matches an approver bound in the quorum Intent.
    const keyed = load("examples/payloads/countersignature.keyed.example.json");
    const quorum = load("examples/payloads/intent.quorum.example.json");
    const bound = quorum.approvers.find((a: { actor: string }) => a.actor === keyed.actor);
    expect(bound.public_key).toBe(keyed.public_key);
  });

  it("default-timeout example is an on-time Resolution for its Intent", () => {
    const intent = load("examples/payloads/intent.example.json");
    const receipt = load("examples/payloads/countersignature.default-timeout.example.json");
    expect(() =>
      verifyResolution(
        intent,
        { decision: receipt.decision, policy: "default", countersignatures: [receipt] },
        receipt.public_key,
      ),
    ).not.toThrow();
  });
});
