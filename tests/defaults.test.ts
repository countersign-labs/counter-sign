// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault, deadline, defaultResolution, isExpired } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, type Keypair } from "../src/core/keys.js";
import type { Countersignature, Decision, Intent, Policy, Resolution } from "../src/core/types.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;

// Keyed approvers (quorum > 1 requires keyed) with stable per-actor keys.
const approverKeys = new Map<string, Keypair>();
function keyOf(actor: string): Keypair {
  let kp = approverKeys.get(actor);
  if (!kp) { kp = generateKeypair(); approverKeys.set(actor, kp); }
  return kp;
}
function keyedReceipt(i: Intent, decision: Decision, actor: string) {
  return signDecision(i, decision, actor, keyOf(actor).secretKey, "approver");
}

function intentWith(timeout: number, def: Decision, quorum = 1) {
  const approvers =
    quorum > 1
      ? [
          { actor: "local:you", mode: "keyed" as const, public_key: keyOf("local:you").publicKey },
          { actor: "local:them", mode: "keyed" as const, public_key: keyOf("local:them").publicKey },
        ]
      : ["local:you"];
  return createIntent(
    { action: "demo.op", summary: "Do the thing", risk_tier: "low", approvers, quorum, timeout, default: def },
    agent,
  );
}

/** Wrap one signed receipt as a human Resolution. */
function human(cs: Countersignature, policy: Policy = "approver"): Resolution {
  return { decision: cs.decision, policy, countersignatures: [cs] };
}

const never = new Promise<Resolution>(() => {});

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
    const r = await pending;
    expect(r.decision).toBe("reject");
    expect(r.policy).toBe("default");
    expect(r.countersignatures[0].actor).toBe("default:timeout");
    expect(verifyCountersignature(r.countersignatures[0])).toBe(true);
  });

  it("silence resolves to a signed approve when default=approve", async () => {
    const intent = intentWith(60, "approve");
    const pending = awaitWithDefault(intent, never, authority);
    await vi.advanceTimersByTimeAsync(60_000);
    const r = await pending;
    expect(r.decision).toBe("approve");
    expect(r.policy).toBe("default");
  });

  it("an already-expired intent resolves to the Default immediately", async () => {
    const intent = intentWith(1, "reject");
    vi.setSystemTime(deadline(intent) + 1);
    const r = await awaitWithDefault(intent, never, authority);
    expect(r.countersignatures[0].actor).toBe("default:timeout");
  });

  it("a human decision before the deadline wins over the Default", async () => {
    const intent = intentWith(60, "reject");
    const decision = Promise.resolve(human(signDecision(intent, "approve", "local:you", authority)));
    const r = await awaitWithDefault(intent, decision, authority);
    expect(r.decision).toBe("approve");
    expect(r.policy).toBe("approver");
  });

  it("a quorum that never completes in time yields the Default, not an approval", async () => {
    const intent = intentWith(60, "reject", 2);
    // Only one of the two required approvals ever arrives -> stays pending -> Default.
    const pending = awaitWithDefault(intent, never, authority);
    await vi.advanceTimersByTimeAsync(60_000);
    const r = await pending;
    expect(r.decision).toBe("reject");
    expect(r.policy).toBe("default");
  });
});

describe("resolution validation at the race boundary", () => {
  it("rejects a resolution whose receipt is for a different intent", async () => {
    const intent = intentWith(60, "reject");
    const other = intentWith(60, "reject");
    const wrong = Promise.resolve(human(signDecision(other, "approve", "local:you", authority)));
    await expect(awaitWithDefault(intent, wrong, authority)).rejects.toThrow(InvalidCountersignatureError);
  });

  it("rejects a resolution whose signature does not verify", async () => {
    const intent = intentWith(60, "reject");
    const forged = { ...signDecision(intent, "reject", "local:you", authority), decision: "approve" as const };
    await expect(awaitWithDefault(intent, Promise.resolve(human(forged)), authority)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("rejects an approve resolution not backed by quorum distinct approvers", async () => {
    const intent = intentWith(60, "reject", 2);
    // Adapter (buggy/hostile) asserts approve with only ONE approver.
    const underQuorum: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [keyedReceipt(intent, "approve", "local:you")],
    };
    await expect(awaitWithDefault(intent, Promise.resolve(underQuorum), authority)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("rejects an approve resolution whose two receipts share one actor", async () => {
    const intent = intentWith(60, "reject", 2);
    const sameActor: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        keyedReceipt(intent, "approve", "local:you"),
        keyedReceipt(intent, "approve", "local:you"),
      ],
    };
    await expect(awaitWithDefault(intent, Promise.resolve(sameActor), authority)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("defaultResolution is portable and every receipt verifies standalone", () => {
    const intent = intentWith(5, "approve");
    // A Default can only be minted once the deadline has passed (CS-22).
    vi.useFakeTimers();
    vi.setSystemTime(deadline(intent) + 1);
    const r = defaultResolution(intent, authority);
    vi.useRealTimers();
    expect(verifyCountersignature(r.countersignatures[0])).toBe(true);
    expect(r.countersignatures[0].intent_id).toBe(intent.intent_id);
  });
});
