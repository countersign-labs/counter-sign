// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { IntentRejectedError } from "../src/core/errors.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Countersignature, Decision, Intent } from "../src/core/types.js";
import { wrapAction } from "../src/shim.js";

const authority = generateKeypair();

/** Adapter that instantly answers with a fixed decision. */
function instantAdapter(decision: Decision): Adapter & { delivered: Intent[] } {
  const delivered: Intent[] = [];
  return {
    channel: "mock",
    delivered,
    async deliver(intent) {
      delivered.push(intent);
    },
    awaitDecision(intent) {
      return Promise.resolve(signDecision(intent, decision, "mock:tester", authority.secretKey));
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
        awaitDecision: () => new Promise<Countersignature>(() => {}),
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
