// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { IntentRejectedError } from "../src/core/errors.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Approver, Countersignature, Decision, Intent, Resolution } from "../src/core/types.js";
import { wrapAction } from "../src/shim.js";

const authority = generateKeypair();

/** Adapter that instantly answers with a fixed single-approver decision. */
function instantAdapter(decision: Decision): Adapter & { delivered: Intent[] } {
  const delivered: Intent[] = [];
  return {
    channel: "mock",
    delivered,
    async deliver(intent) {
      delivered.push(intent);
    },
    awaitResolution(intent): Promise<Resolution> {
      return Promise.resolve({
        decision,
        policy: "approver",
        countersignatures: [signDecision(intent, decision, "mock:tester", authority.secretKey)],
      });
    },
  };
}

const fields = {
  action: "billing.refund",
  summary: "Refund $42",
  risk_tier: "high" as const,
  approvers: ["mock:tester"],
  timeout: 300,
  default: "reject" as const,
};

describe("wrapAction happy path", () => {
  it("delivers the intent, then runs the function and returns its result", async () => {
    const adapter = instantAdapter("approve");
    const fn = vi.fn(async (amount: number) => ({ refunded: amount }));
    let receipt: Countersignature | undefined;

    const guarded = wrapAction(fn, fields, adapter, {
      authorityKey: authority.secretKey,
      onDecision: (cs) => (receipt = cs),
    });
    const result = await guarded(42);

    expect(result).toEqual({ refunded: 42 });
    expect(fn).toHaveBeenCalledWith(42);
    expect(adapter.delivered).toHaveLength(1);
    expect(adapter.delivered[0].action).toBe("billing.refund");
    expect(receipt?.decision).toBe("approve");
    expect(receipt?.intent_id).toBe(adapter.delivered[0].intent_id);
  });

  it("signs each call as a fresh intent", async () => {
    const adapter = instantAdapter("approve");
    const guarded = wrapAction(async () => "ok", fields, adapter, { authorityKey: authority.secretKey });
    await guarded();
    await guarded();
    expect(adapter.delivered[0].intent_id).not.toBe(adapter.delivered[1].intent_id);
  });
});

describe("wrapAction pre-delivery guards (fail fast, no post-approval split-brain)", () => {
  const keyedFields = (approver: Approver) => ({
    action: "prod.deploy", summary: "Deploy", risk_tier: "critical" as const,
    approvers: [approver], quorum: 1, timeout: 300, default: "reject" as const,
  });

  it("rejects a passkey approver with no webauthn policy BEFORE delivery", async () => {
    const adapter = instantAdapter("approve");
    const passkey: Approver = { actor: "m:ceo", mode: "keyed", public_key: `webauthn-ed25519:${generateKeypair().publicKey}` };
    const guarded = wrapAction(async () => "ran", keyedFields(passkey), adapter, { authorityKey: authority.secretKey });
    await expect(guarded()).rejects.toThrow(/passkey.*webauthn|webauthn.*policy/i);
    expect(adapter.delivered).toHaveLength(0); // guard fired before deliver()
  });

  it("rejects agent key == authority key BEFORE delivery", async () => {
    const adapter = instantAdapter("approve");
    const guarded = wrapAction(async () => "ran", fields, adapter, { agent: { id: "agent:evil", keypair: authority }, authorityKey: authority.secretKey });
    await expect(guarded()).rejects.toThrow(/agent key must be distinct/);
    expect(adapter.delivered).toHaveLength(0);
  });

  it("rejects a keyed approver bound to the authority key BEFORE delivery", async () => {
    const adapter = instantAdapter("approve");
    const bound: Approver = { actor: "m:ceo", mode: "keyed", public_key: publicKeyFromSecret(authority.secretKey) };
    const guarded = wrapAction(async () => "ran", keyedFields(bound), adapter, { authorityKey: authority.secretKey });
    await expect(guarded()).rejects.toThrow(/bound to the authority key/);
    expect(adapter.delivered).toHaveLength(0);
  });

  it("rejects an adapter whose authority key differs from opts.authorityKey BEFORE delivery", async () => {
    // The adapter signs vouched receipts with a DIFFERENT authority key than opts.authorityKey (e.g. the
    // runtime rotated its key but the adapter stayed pinned). Without reconciliation the human approves,
    // the adapter signs with its key, and verifyResolution then rejects that receipt against opts' key —
    // a post-approval split-brain. wrapAction must fail fast, like the webauthn-policy reconciliation.
    const other = generateKeypair();
    const delivered: Intent[] = [];
    const adapter: Adapter = {
      channel: "mock",
      authorityPublicKey: publicKeyFromSecret(other.secretKey),
      async deliver(intent) { delivered.push(intent); },
      awaitResolution: (intent) => Promise.resolve({ decision: "approve", policy: "approver", countersignatures: [signDecision(intent, "approve", "mock:tester", other.secretKey)] }),
    };
    const guarded = wrapAction(async () => "ran", fields, adapter, { authorityKey: authority.secretKey });
    await expect(guarded()).rejects.toThrow(/authority key/i);
    expect(delivered).toHaveLength(0); // guard fired before deliver()
  });

  it("delivers when the adapter's exposed authority key MATCHES opts.authorityKey (guard not over-broad)", async () => {
    const delivered: Intent[] = [];
    const adapter: Adapter = {
      channel: "mock",
      authorityPublicKey: publicKeyFromSecret(authority.secretKey), // same key wrapAction verifies with
      async deliver(intent) { delivered.push(intent); },
      awaitResolution: (intent) => Promise.resolve({ decision: "approve", policy: "approver", countersignatures: [signDecision(intent, "approve", "mock:tester", authority.secretKey)] }),
    };
    const guarded = wrapAction(async () => "ran", fields, adapter, { authorityKey: authority.secretKey });
    expect(await guarded()).toBe("ran");
    expect(delivered).toHaveLength(1);
  });

  it("still delivers a passkey approver WITH a webauthn policy (guard is not over-broad)", async () => {
    // A vouched instantAdapter can't actually serve a keyed approver, but the guard must
    // let it PAST — delivery is what fails here, not the pre-delivery guard.
    const adapter = instantAdapter("approve");
    const passkey: Approver = { actor: "m:ceo", mode: "keyed", public_key: `webauthn-ed25519:${generateKeypair().publicKey}` };
    const guarded = wrapAction(async () => "ran", keyedFields(passkey), adapter, { authorityKey: authority.secretKey, webauthn: { rpId: "example.com", allowedOrigins: ["https://example.com"] } });
    // The pre-delivery guard passes (webauthn supplied), so it reaches delivery — which
    // then fails at resolution (this vouched adapter can't serve a keyed approver).
    await expect(guarded()).rejects.toThrow();
    expect(adapter.delivered).toHaveLength(1); // delivery DID happen — the guard let it through
  });
});

describe("wrapAction reject path", () => {
  it("never runs the function and throws IntentRejectedError carrying the receipt", async () => {
    const adapter = instantAdapter("reject");
    const fn = vi.fn(async () => "must not happen");

    const guarded = wrapAction(fn, fields, adapter, { authorityKey: authority.secretKey });
    const err = await guarded().catch((e) => e);

    expect(err).toBeInstanceOf(IntentRejectedError);
    expect(err.countersignature.decision).toBe("reject");
    expect(err.countersignature.actor).toBe("mock:tester");
    expect(err.intent.action).toBe("billing.refund");
    expect(fn).not.toHaveBeenCalled();
  });

  it("a reject Default on timeout also blocks the function", async () => {
    vi.useFakeTimers();
    try {
      const silent: Adapter = {
        channel: "mock",
        async deliver() {},
        awaitResolution: () => new Promise<Resolution>(() => {}),
      };
      const fn = vi.fn(async () => "must not happen");
      const guarded = wrapAction(fn, { ...fields, timeout: 30 }, silent, { authorityKey: authority.secretKey });

      const pending = guarded().catch((e) => e);
      await vi.advanceTimersByTimeAsync(30_000);
      const err = await pending;

      expect(err).toBeInstanceOf(IntentRejectedError);
      expect(err.countersignature.policy).toBe("default");
      expect(fn).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
