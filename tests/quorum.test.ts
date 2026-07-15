// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// M-of-N approval quorum. Under v0.2, quorum > 1 requires KEYED approvers (each
// signs with their own key), so a compromised authority server cannot forge the
// quorum. Covers keyed accumulation via record(), veto, dedup, defaults, the
// construction guardrail, and the headline separation-of-duty property.

import { describe, expect, it, vi } from "vitest";
import { PendingDecisions, type Adapter, type SettleResult } from "../src/adapter.js";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault } from "../src/core/defaults.js";
import { CountersignError, IntentRejectedError } from "../src/core/errors.js";
import { createIntent, quorumOf } from "../src/core/intent.js";
import { generateKeypair, type Keypair } from "../src/core/keys.js";
import type { Approver, Intent, IntentFields, Resolution } from "../src/core/types.js";
import { EmailAdapter } from "../src/adapters/email.js";
import { wrapAction } from "../src/shim.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();

// Stable per-actor approver keypairs so a keyed approver's identity is consistent.
const approverKeys = new Map<string, Keypair>();
function keyOf(actor: string): Keypair {
  let kp = approverKeys.get(actor);
  if (!kp) { kp = generateKeypair(); approverKeys.set(actor, kp); }
  return kp;
}
function keyed(actor: string): Approver {
  return { actor, mode: "keyed", public_key: keyOf(actor).publicKey };
}
/** A receipt signed by the KEYED approver themselves (not the authority). */
function keyedReceipt(intent: Intent, decision: "approve" | "reject", actor: string) {
  return signDecision(intent, decision, actor, keyOf(actor).secretKey, "approver");
}

function intent(quorum: number, overrides: Partial<IntentFields> = {}): Intent {
  const approvers =
    overrides.approvers ?? (quorum > 1 ? [keyed("m:alice"), keyed("m:bob"), keyed("m:carol")] : ["m:alice", "m:bob", "m:carol"]);
  return createIntent(
    {
      action: "prod.deploy",
      summary: "Deploy 2.4.0",
      risk_tier: "critical",
      timeout: 300,
      default: "reject",
      ...overrides,
      approvers,
      quorum,
    },
    agent,
  );
}

describe("quorumOf", () => {
  it("treats an ABSENT quorum as 1 but FAILS CLOSED on a malformed one", () => {
    const i = intent(1);
    expect(quorumOf(i)).toBe(1);
    expect(quorumOf({ ...i, quorum: undefined as unknown as number })).toBe(1);
    expect(quorumOf({ ...i, quorum: 3 })).toBe(3);
    expect(() => quorumOf({ ...i, quorum: 0 })).toThrow();
    expect(() => quorumOf({ ...i, quorum: -1 })).toThrow();
    expect(() => quorumOf({ ...i, quorum: 2.5 })).toThrow();
    expect(() => quorumOf({ ...i, quorum: "3" as unknown as number })).toThrow();
  });

  it("createIntent rejects a quorum below 1 and includes it in the signed envelope", () => {
    expect(() => intent(0)).toThrow();
    expect(intent(2).quorum).toBe(2);
  });

  it("createIntent REQUIRES all approvers keyed when quorum > 1 (vouched quorum is server-forgeable)", () => {
    expect(() => intent(2, { approvers: ["m:alice", "m:bob"] })).toThrow(/keyed/);
    // One vouched slot in an otherwise-keyed quorum is still refused.
    expect(() => intent(2, { approvers: [keyed("m:alice"), "m:bob"] })).toThrow(/keyed/);
    // A fully-keyed quorum is accepted.
    expect(intent(2, { approvers: [keyed("m:alice"), keyed("m:bob")] }).quorum).toBe(2);
  });
});

describe("PendingDecisions.record accumulates a distinct-actor KEYED quorum", () => {
  it("resolves approve only after quorum distinct approvers submit their own receipts", async () => {
    const pd = new PendingDecisions();
    const i = intent(2);
    const p = pd.wait(i);

    const r1 = pd.record(keyedReceipt(i, "approve", "m:alice"))!;
    expect(r1.status).toBe("pending");
    expect(r1.collected).toBe(1);
    expect(r1.quorum).toBe(2);

    const r2 = pd.record(keyedReceipt(i, "approve", "m:bob"))!;
    expect(r2.status).toBe("resolved");
    expect(r2.decision).toBe("approve");

    const resolution = await p;
    expect(resolution.decision).toBe("approve");
    expect(resolution.policy).toBe("approver");
    expect(resolution.countersignatures).toHaveLength(2);
    expect(new Set(resolution.countersignatures.map((c) => c.actor)).size).toBe(2);
    // Each receipt verifies against its OWN approver key (not the authority key).
    expect(verifyCountersignature(resolution.countersignatures[0], { trustedKeys: keyOf("m:alice").publicKey })).toBe(true);
  });

  it("does NOT let one actor fill a two-person quorum by submitting twice", async () => {
    const pd = new PendingDecisions();
    const i = intent(2);
    const p = pd.wait(i);
    let resolved = false;
    void p.then(() => (resolved = true));

    expect(pd.record(keyedReceipt(i, "approve", "m:alice"))!.collected).toBe(1);
    const again = pd.record(keyedReceipt(i, "approve", "m:alice"))!;
    expect(again.status).toBe("pending");
    expect(again.collected).toBe(1);
    await new Promise((r) => setTimeout(r, 10));
    expect(resolved).toBe(false);
  });

  it("ignores a receipt not signed by the approver's own bound key", () => {
    const pd = new PendingDecisions();
    const i = intent(2);
    void pd.wait(i);
    // A receipt for m:alice but signed by the authority key (or any non-bound key)
    // is NOT a valid keyed decision — the server cannot vouch for a keyed approver.
    expect(pd.record(signDecision(i, "approve", "m:alice", authority.secretKey, "approver"))).toBeNull();
    // The genuine keyed receipt is accepted.
    expect(pd.record(keyedReceipt(i, "approve", "m:alice"))?.collected).toBe(1);
  });

  it("a keyed reject vetoes immediately even after approvals were collected", async () => {
    const pd = new PendingDecisions();
    const i = intent(3);
    const p = pd.wait(i);

    pd.record(keyedReceipt(i, "approve", "m:alice"));
    const veto = pd.record(keyedReceipt(i, "reject", "m:bob"))!;
    expect(veto.status).toBe("resolved");
    expect(veto.decision).toBe("reject");

    const resolution = await p;
    expect(resolution.decision).toBe("reject");
    expect(resolution.countersignatures).toHaveLength(1);
    expect(resolution.countersignatures[0].actor).toBe("m:bob");

    expect(pd.record(keyedReceipt(i, "approve", "m:carol"))).toBeNull(); // single-shot
  });
});

/** Adapter backed by PendingDecisions; the test drives keyed-receipt submissions. */
class MockQuorumAdapter implements Adapter {
  readonly channel = "mock";
  readonly pending = new PendingDecisions();
  async deliver(): Promise<void> {}
  awaitResolution(i: Intent): Promise<Resolution> {
    return this.pending.wait(i);
  }
  submit(intent: Intent, decision: "approve" | "reject", actor: string): SettleResult | null {
    return this.pending.record(keyedReceipt(intent, decision, actor));
  }
}

async function untilPending(adapter: MockQuorumAdapter, intentId: string): Promise<void> {
  for (let i = 0; i < 50 && !adapter.pending.has(intentId); i++) await new Promise((r) => setTimeout(r, 0));
}

describe("wrapAction end-to-end under a keyed quorum", () => {
  const fields: IntentFields = {
    action: "prod.deploy",
    summary: "Deploy 2.4.0",
    risk_tier: "critical",
    approvers: [keyed("mock:alice"), keyed("mock:bob")],
    quorum: 2,
    timeout: 300,
    default: "reject",
  };

  it("runs the action only after two distinct approvals", async () => {
    const adapter = new MockQuorumAdapter();
    const fn = vi.fn(async () => "deployed");
    let intent!: Intent;
    let resolution: Resolution | undefined;
    const guarded = wrapAction(fn, fields, adapter, {
      agent,
      authorityKey: authority.secretKey,
      onIntent: (i) => (intent = i),
      onResolution: (r) => (resolution = r),
    });

    const run = guarded();
    await untilPending(adapter, (intent as Intent | undefined)?.intent_id ?? "");

    adapter.submit(intent, "approve", "mock:alice");
    expect(fn).not.toHaveBeenCalled();
    adapter.submit(intent, "approve", "mock:bob");

    await expect(run).resolves.toBe("deployed");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(resolution?.decision).toBe("approve");
    expect(resolution?.countersignatures).toHaveLength(2);
  });

  it("blocks the action when a single approver vetoes", async () => {
    const adapter = new MockQuorumAdapter();
    const fn = vi.fn(async () => "deployed");
    let intent!: Intent;
    const guarded = wrapAction(fn, fields, adapter, {
      agent,
      authorityKey: authority.secretKey,
      onIntent: (i) => (intent = i),
    });

    const run = guarded().catch((e) => e);
    await untilPending(adapter, (intent as Intent | undefined)?.intent_id ?? "");
    adapter.submit(intent, "approve", "mock:alice");
    adapter.submit(intent, "reject", "mock:bob");

    const err = await run;
    expect(err).toBeInstanceOf(IntentRejectedError);
    expect(err.resolution.decision).toBe("reject");
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("quorum security (separation of duty)", () => {
  it("HEADLINE: holding only the authority key CANNOT satisfy a keyed 2-of-2", async () => {
    // The exact concern from external review: with one authority key, forge two
    // distinct-actor 'approve' receipts. Under keyed quorum this is rejected —
    // each keyed slot must be signed by that approver's OWN key.
    const i = intent(2); // keyed m:alice / m:bob / m:carol
    const forged: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        signDecision(i, "approve", "m:alice", authority.secretKey, "approver"),
        signDecision(i, "approve", "m:bob", authority.secretKey, "approver"),
      ],
    };
    await expect(awaitWithDefault(i, Promise.resolve(forged), authority.secretKey)).rejects.toThrow();
  });

  it("a legitimate keyed 2-of-2 (each approver's own key) is accepted", async () => {
    const i = intent(2);
    const legit: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [keyedReceipt(i, "approve", "m:alice"), keyedReceipt(i, "approve", "m:bob")],
    };
    await expect(awaitWithDefault(i, Promise.resolve(legit), authority.secretKey)).resolves.toMatchObject({
      decision: "approve",
    });
  });

  it("rejects an approve quorum if ANY receipt is signed by the wrong key", async () => {
    const attacker = generateKeypair();
    const i = intent(2);
    const mixed: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        keyedReceipt(i, "approve", "m:alice"),
        signDecision(i, "approve", "m:bob", attacker.secretKey, "approver"), // not m:bob's bound key
      ],
    };
    await expect(awaitWithDefault(i, Promise.resolve(mixed), authority.secretKey)).rejects.toThrow();
  });

  it("forbids the self-defeating quorum > 1 + default:approve at construction", () => {
    expect(() => intent(2, { default: "approve" })).toThrow(/default: approve/);
    expect(intent(1, { default: "approve" }).default).toBe("approve");
  });

  it("rejects a non-conforming quorum>1 + default:approve Intent at the enforcement boundary (fail closed)", async () => {
    const bad = { ...intent(2), default: "approve" as const };
    await expect(
      awaitWithDefault(bad, new Promise<Resolution>(() => {}), authority.secretKey),
    ).rejects.toThrow(/default: approve|quorum/);
  });

  it("still times out fail-closed (reject) for a CONFORMING keyed quorum>1 intent", async () => {
    vi.useFakeTimers();
    try {
      const i = intent(2); // keyed quorum 2, default reject
      const pending = awaitWithDefault(i, new Promise<Resolution>(() => {}), authority.secretKey);
      await vi.advanceTimersByTimeAsync(300_000);
      const r = await pending;
      expect(r.decision).toBe("reject");
      expect(r.policy).toBe("default");
    } finally {
      vi.useRealTimers();
    }
  });

  it("the email adapter refuses quorum > 1 at delivery (bearer links cannot represent distinct approvers)", async () => {
    const adapter = new EmailAdapter({
      transport: { sendMail: async () => {}, close: () => {} } as never,
      from: "a@x", to: "b@x", callbackBaseUrl: "http://x", authorityKey: authority.secretKey,
    });
    await expect(adapter.deliver(intent(2))).rejects.toThrow(CountersignError);
    await expect(adapter.deliver(intent(1))).resolves.toBeUndefined();
    adapter.close();
  });
});

describe("backward compatibility", () => {
  it("a bare-string approver is read as a vouched single approver", async () => {
    const pd = new PendingDecisions();
    const base = intent(1); // approvers are bare strings -> vouched
    const legacy = { ...base } as Record<string, unknown>;
    delete legacy.quorum; // simulate a pre-quorum Intent
    const p = pd.wait(legacy as unknown as Intent);
    const r = pd.settle(base.intent_id, "approve", "m:alice", authority.secretKey)!;
    expect(r.status).toBe("resolved");
    expect((await p).countersignatures).toHaveLength(1);
  });
});
