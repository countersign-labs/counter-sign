// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault, deadline, defaultCountersignature, isExpired } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import { signDecision } from "../src/core/countersignature.js";
import type { Countersignature, Decision } from "../src/core/types.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;

function intentWith(timeout: number, def: Decision) {
  return createIntent(
    {
      action: "demo.op",
      summary: "Do the thing",
      risk_tier: "low",
      approvers: ["local:you"],
      timeout,
      default: def,
    },
    agent,
  );
}

const never = new Promise<Countersignature>(() => {});

describe("deadline arithmetic", () => {
  it("deadline = created_at + timeout seconds", () => {
    const intent = intentWith(300, "reject");
    expect(deadline(intent)).toBe(Date.parse(intent.created_at) + 300_000);
    expect(isExpired(intent, deadline(intent) - 1)).toBe(false);
    expect(isExpired(intent, deadline(intent))).toBe(true);
  });
});

describe("timeout fires the declared Default", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("silence resolves to a signed reject when default=reject", async () => {
    const intent = intentWith(60, "reject");
    const pending = awaitWithDefault(intent, never, authority);
    await vi.advanceTimersByTimeAsync(60_000);
    const cs = await pending;
    expect(cs.decision).toBe("reject");
    expect(cs.actor).toBe("default:timeout");
    expect(cs.policy).toBe("default");
    expect(verifyCountersignature(cs)).toBe(true);
  });

  it("silence resolves to a signed approve when default=approve", async () => {
    const intent = intentWith(60, "approve");
    const pending = awaitWithDefault(intent, never, authority);
    await vi.advanceTimersByTimeAsync(60_000);
    const cs = await pending;
    expect(cs.decision).toBe("approve");
    expect(cs.policy).toBe("default");
  });

  it("an already-expired intent resolves to the Default immediately", async () => {
    const intent = intentWith(1, "reject");
    vi.setSystemTime(deadline(intent) + 1);
    const cs = await awaitWithDefault(intent, never, authority);
    expect(cs.actor).toBe("default:timeout");
  });

  it("a human decision before the deadline wins over the Default", async () => {
    const intent = intentWith(60, "reject");
    const human = Promise.resolve(signDecision(intent, "approve", "local:you", authority));
    const cs = await awaitWithDefault(intent, human, authority);
    expect(cs.decision).toBe("approve");
    expect(cs.policy).toBe("approver");
  });
});

describe("countersignature validation at the race boundary", () => {
  it("rejects a receipt for a different intent", async () => {
    const intent = intentWith(60, "reject");
    const other = intentWith(60, "reject");
    const wrong = Promise.resolve(signDecision(other, "approve", "local:you", authority));
    await expect(awaitWithDefault(intent, wrong, authority)).rejects.toThrow(InvalidCountersignatureError);
  });

  it("rejects a receipt whose signature does not verify", async () => {
    const intent = intentWith(60, "reject");
    const forged = { ...signDecision(intent, "reject", "local:you", authority), decision: "approve" as const };
    await expect(awaitWithDefault(intent, Promise.resolve(forged), authority)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("defaultCountersignature is portable and verifiable standalone", () => {
    const intent = intentWith(5, "approve");
    const cs = defaultCountersignature(intent, authority);
    expect(verifyCountersignature(cs)).toBe(true);
    expect(cs.intent_id).toBe(intent.intent_id);
  });
});
