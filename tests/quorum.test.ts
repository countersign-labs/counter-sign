// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// M-of-N approval quorum: distinct-actor accumulation, veto, dedup, defaults,
// backward compatibility, and end-to-end through the shim.

import { describe, expect, it, vi } from "vitest";
import { PendingDecisions, type Adapter, type SettleResult } from "../src/adapter.js";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault } from "../src/core/defaults.js";
import { CountersignError, IntentRejectedError } from "../src/core/errors.js";
import { createIntent, quorumOf } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Intent, IntentFields, Resolution } from "../src/core/types.js";
import { EmailAdapter } from "../src/adapters/email.js";
import { TelegramAdapter } from "../src/adapters/telegram.js";
import { wrapAction } from "../src/shim.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();

function intent(quorum: number, overrides: Partial<IntentFields> = {}): Intent {
  return createIntent(
    {
      action: "prod.deploy",
      summary: "Deploy 2.4.0",
      risk_tier: "critical",
      approvers: ["m:alice", "m:bob", "m:carol"],
      quorum,
      timeout: 300,
      default: "reject",
      ...overrides,
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
    // A present-but-malformed quorum must NOT silently downgrade to 1 — that
    // would let a `quorum: "3"` / `2.5` / `0` Intent be authorized by one approver.
    expect(() => quorumOf({ ...i, quorum: 0 })).toThrow();
    expect(() => quorumOf({ ...i, quorum: -1 })).toThrow();
    expect(() => quorumOf({ ...i, quorum: 2.5 })).toThrow();
    expect(() => quorumOf({ ...i, quorum: "3" as unknown as number })).toThrow();
  });

  it("createIntent rejects a quorum below 1 and includes it in the signed envelope", () => {
    expect(() => intent(0)).toThrow();
    expect(intent(2).quorum).toBe(2);
  });
});

describe("PendingDecisions accumulates a distinct-actor quorum", () => {
  it("resolves approve only after quorum distinct actors approve", async () => {
    const pd = new PendingDecisions();
    const i = intent(2);
    const p = pd.wait(i);

    const r1 = pd.settle(i.intent_id, "approve", "m:alice", authority.secretKey)!;
    expect(r1.status).toBe("pending");
    expect(r1.collected).toBe(1);
    expect(r1.quorum).toBe(2);

    const r2 = pd.settle(i.intent_id, "approve", "m:bob", authority.secretKey)!;
    expect(r2.status).toBe("resolved");
    expect(r2.decision).toBe("approve");

    const resolution = await p;
    expect(resolution.decision).toBe("approve");
    expect(resolution.policy).toBe("approver");
    expect(resolution.countersignatures).toHaveLength(2);
    expect(new Set(resolution.countersignatures.map((c) => c.actor)).size).toBe(2);
    for (const cs of resolution.countersignatures) expect(verifyCountersignature(cs)).toBe(true);
  });

  it("does NOT let one actor fill a two-person quorum by pressing twice", async () => {
    const pd = new PendingDecisions();
    const i = intent(2);
    const p = pd.wait(i);
    let resolved = false;
    void p.then(() => (resolved = true));

    expect(pd.settle(i.intent_id, "approve", "m:alice", authority.secretKey)!.collected).toBe(1);
    const again = pd.settle(i.intent_id, "approve", "m:alice", authority.secretKey)!;
    expect(again.status).toBe("pending");
    expect(again.collected).toBe(1); // still one distinct approver
    await new Promise((r) => setTimeout(r, 10));
    expect(resolved).toBe(false);
  });

  it("a reject vetoes immediately even after approvals were collected", async () => {
    const pd = new PendingDecisions();
    const i = intent(3);
    const p = pd.wait(i);

    pd.settle(i.intent_id, "approve", "m:alice", authority.secretKey);
    const veto = pd.settle(i.intent_id, "reject", "m:bob", authority.secretKey)!;
    expect(veto.status).toBe("resolved");
    expect(veto.decision).toBe("reject");

    const resolution = await p;
    expect(resolution.decision).toBe("reject");
    expect(resolution.countersignatures).toHaveLength(1);
    expect(resolution.countersignatures[0].actor).toBe("m:bob");

    // Resolution is single-shot: later decisions are ignored.
    expect(pd.settle(i.intent_id, "approve", "m:carol", authority.secretKey)).toBeNull();
  });
});

/** Adapter backed by PendingDecisions; the test drives button presses. */
class MockQuorumAdapter implements Adapter {
  readonly channel = "mock";
  readonly pending = new PendingDecisions();
  constructor(private readonly authorityKey: string) {}
  async deliver(): Promise<void> {}
  awaitResolution(i: Intent): Promise<Resolution> {
    return this.pending.wait(i);
  }
  press(intentId: string, decision: "approve" | "reject", actor: string): SettleResult | null {
    return this.pending.settle(intentId, decision, actor, this.authorityKey);
  }
}

async function untilPending(adapter: MockQuorumAdapter, intentId: string): Promise<void> {
  for (let i = 0; i < 50 && !adapter.pending.has(intentId); i++) await new Promise((r) => setTimeout(r, 0));
}

describe("wrapAction end-to-end under quorum", () => {
  const fields: IntentFields = {
    action: "prod.deploy",
    summary: "Deploy 2.4.0",
    risk_tier: "critical",
    approvers: ["m:alice", "m:bob"],
    quorum: 2,
    timeout: 300,
    default: "reject",
  };

  it("runs the action only after two distinct approvals", async () => {
    const adapter = new MockQuorumAdapter(authority.secretKey);
    const fn = vi.fn(async () => "deployed");
    let intentId = "";
    let resolution: Resolution | undefined;
    const guarded = wrapAction(fn, fields, adapter, {
      agent,
      authorityKey: authority.secretKey,
      onIntent: (i) => (intentId = i.intent_id),
      onResolution: (r) => (resolution = r),
    });

    const run = guarded();
    await untilPending(adapter, intentId);

    adapter.press(intentId, "approve", "mock:alice");
    expect(fn).not.toHaveBeenCalled(); // one approval is not enough
    adapter.press(intentId, "approve", "mock:bob");

    await expect(run).resolves.toBe("deployed");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(resolution?.decision).toBe("approve");
    expect(resolution?.countersignatures).toHaveLength(2);
  });

  it("blocks the action when a single approver vetoes", async () => {
    const adapter = new MockQuorumAdapter(authority.secretKey);
    const fn = vi.fn(async () => "deployed");
    let intentId = "";
    const guarded = wrapAction(fn, fields, adapter, {
      agent,
      authorityKey: authority.secretKey,
      onIntent: (i) => (intentId = i.intent_id),
    });

    const run = guarded().catch((e) => e);
    await untilPending(adapter, intentId);
    adapter.press(intentId, "approve", "mock:alice");
    adapter.press(intentId, "reject", "mock:bob");

    const err = await run;
    expect(err).toBeInstanceOf(IntentRejectedError);
    expect(err.resolution.decision).toBe("reject");
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("quorum security", () => {
  it("awaitWithDefault rejects an approve quorum if ANY receipt is foreign-signed", async () => {
    const attacker = generateKeypair();
    const i = intent(2);
    // Two distinct approvers, but one receipt is signed by an untrusted key.
    const mixed: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        signDecision(i, "approve", "m:alice", authority.secretKey),
        signDecision(i, "approve", "m:bob", attacker.secretKey),
      ],
    };
    await expect(awaitWithDefault(i, Promise.resolve(mixed), authority.secretKey)).rejects.toThrow();
  });

  it("forbids the self-defeating quorum > 1 + default:approve at construction", () => {
    expect(() => intent(2, { default: "approve" })).toThrow(/default: approve/);
    // quorum 1 + default:approve is fine (single-approver low-risk).
    expect(intent(1, { default: "approve" }).default).toBe("approve");
  });

  it("rejects a non-conforming quorum>1 + default:approve Intent at the enforcement boundary (fail closed)", async () => {
    // Hand-craft a non-conforming Intent (createIntent would refuse it). The
    // enforcement path must not process it at all: assertIntentInvariants throws
    // up front, so a timeout can never authorize a quorum action via a bad
    // default. Fail-closed by refusal is stricter than the old coerce-to-reject.
    const bad = { ...intent(2), default: "approve" as const };
    await expect(
      awaitWithDefault(bad, new Promise<Resolution>(() => {}), authority.secretKey),
    ).rejects.toThrow(/default: approve|quorum/);
  });

  it("still times out fail-closed (reject) for a CONFORMING quorum>1 intent", async () => {
    vi.useFakeTimers();
    try {
      const i = intent(2); // quorum 2, default reject — conforming
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
    // quorum 1 is fine.
    await expect(adapter.deliver(intent(1))).resolves.toBeUndefined();
    adapter.close();
  });
});

describe("a real chat adapter accumulates a distinct-user quorum via its handler", () => {
  it("telegram: two distinct users approving a quorum-2 intent resolves to approve", async () => {
    const realFetch = globalThis.fetch;
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ ok: true, result: {} }), { status: 200 }));
    try {
      const adapter = new TelegramAdapter({ botToken: "t", chatId: "1", authorityKey: authority.secretKey, mode: "webhook" });
      const i = intent(2);
      const pending = adapter.awaitResolution(i);
      const update = (uid: number, decision: string) => ({
        update_id: uid,
        callback_query: {
          id: `c${uid}`,
          from: { id: uid, username: `u${uid}` },
          message: { message_id: 1, chat: { id: 1 }, text: "x", reply_markup: {} },
          data: `cs:${i.intent_id}:${decision}`,
        },
      });

      const r1 = await adapter.handleUpdate(update(10, "approve"));
      expect(r1?.status).toBe("pending"); // one approval is not enough
      const r2 = await adapter.handleUpdate(update(20, "approve"));
      expect(r2?.status).toBe("resolved");

      const resolution = await pending;
      expect(resolution.decision).toBe("approve");
      expect(resolution.countersignatures).toHaveLength(2);
      expect(new Set(resolution.countersignatures.map((c) => c.actor)).size).toBe(2);
      adapter.close();
    } finally {
      vi.stubGlobal("fetch", realFetch);
      vi.unstubAllGlobals();
    }
  });
});

describe("backward compatibility", () => {
  it("an intent with no quorum field behaves as single-approver", async () => {
    const pd = new PendingDecisions();
    const base = intent(1);
    const legacy = { ...base } as Record<string, unknown>;
    delete legacy.quorum; // simulate a pre-quorum Intent
    const p = pd.wait(legacy as unknown as Intent);
    const r = pd.settle(base.intent_id, "approve", "m:alice", authority.secretKey)!;
    expect(r.status).toBe("resolved");
    expect((await p).countersignatures).toHaveLength(1);
  });
});
