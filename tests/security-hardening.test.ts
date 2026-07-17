// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Regression tests for the pre-public adversarial stress test: each `it` below
// encodes a confirmed exploit and asserts it is now BLOCKED. See docs/security-review.md.

import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PendingDecisions, readBody, type Adapter } from "../src/adapter.js";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { canonicalize } from "../src/core/canonical.js";
import { signContext } from "../src/core/keys.js";
import { COUNTERSIGNATURE_CONTEXT } from "../src/core/types.js";
import { awaitWithDefault, deadline, defaultResolution, verifyResolution } from "../src/core/defaults.js";
import { wrapAction } from "../src/shim.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { fromB64url, generateKeypair, publicKeyFromSecret, type Keypair } from "../src/core/keys.js";
import type { Approver, Intent, Resolution } from "../src/core/types.js";
import { LocalAdapter } from "../src/adapters/local.js";
import { TelegramAdapter } from "../src/adapters/telegram.js";
import { WhatsAppAdapter } from "../src/adapters/whatsapp.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const authPub = publicKeyFromSecret(authority.secretKey);

// Stable per-actor keypairs for keyed approvers (quorum > 1 requires keyed).
const approverKeys = new Map<string, Keypair>();
function keyOf(actor: string): Keypair {
  let kp = approverKeys.get(actor);
  if (!kp) { kp = generateKeypair(); approverKeys.set(actor, kp); }
  return kp;
}
function keyed(actor: string): Approver {
  return { actor, mode: "keyed", public_key: keyOf(actor).publicKey };
}
/** A receipt signed by the keyed approver's OWN key. */
function keyedReceipt(i: Intent, decision: "approve" | "reject", actor: string) {
  return signDecision(i, decision, actor, keyOf(actor).secretKey, "approver");
}

function intent(quorum: number, over: Partial<Parameters<typeof createIntent>[0]> = {}): Intent {
  const approvers =
    over.approvers ?? (quorum > 1 ? [keyed("m:alice"), keyed("m:bob"), keyed("m:carol")] : ["m:alice", "m:bob", "m:carol"]);
  return createIntent(
    { action: "prod.deploy", summary: "Deploy 2.4.0", risk_tier: "critical", timeout: 300, default: "reject", ...over, approvers, quorum },
    agent,
  );
}

describe("BLOCKER: verifyResolution cannot be bypassed via resolution.policy", () => {
  it("rejects a policy:'default' approve for a quorum>1 intent (the headline exploit)", () => {
    const i = intent(3);
    // A single authority-signed receipt, labelled policy:default, must NOT authorize a 3-of-3.
    const forged: Resolution = {
      decision: "approve",
      policy: "default",
      countersignatures: [signDecision(i, "approve", "default:timeout", authority.secretKey, "default")],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("rejects an 'approve' resolution whose receipts actually say 'reject' (decision consistency)", () => {
    const i = intent(1);
    // The public timeout-reject receipt re-presented as an approve.
    const rejectReceipt = signDecision(i, "reject", "default:timeout", authority.secretKey, "default");
    const forged: Resolution = { decision: "approve", policy: "default", countersignatures: [rejectReceipt] };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("rejects an approve resolution with an unrecognized policy", () => {
    const i = intent(1);
    const forged = {
      decision: "approve",
      policy: "x" as unknown as "approver",
      countersignatures: [signDecision(i, "approve", "m:alice", authority.secretKey)],
    } as Resolution;
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("still ACCEPTS a legitimate quorum-1 default:approve and a real human quorum", () => {
    const da = intent(1, { default: "approve" });
    // A genuine timeout Default can only be minted once the deadline has passed (CS-22).
    vi.useFakeTimers();
    vi.setSystemTime(deadline(da) + 1);
    const legit = defaultResolution(da, authority.secretKey);
    vi.useRealTimers();
    expect(() => verifyResolution(da, legit, authPub)).not.toThrow();

    const q = intent(2); // keyed approvers — each signs with their own key
    const humans: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [keyedReceipt(q, "approve", "m:alice"), keyedReceipt(q, "approve", "m:bob")],
    };
    expect(() => verifyResolution(q, humans, authPub)).not.toThrow();
  });
});

describe("one human cannot fill a multi-person quorum via actor variants", () => {
  it("counts alice / Alice / 'alice ' as ONE distinct approver", () => {
    const i = intent(3);
    // All three receipts are signed by the SAME keyed approver's key (m:alice),
    // just with case/space-variant actor strings — they must collapse to 1 distinct.
    const k = keyOf("m:alice").secretKey;
    const forged: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        signDecision(i, "approve", "m:alice", k, "approver"),
        signDecision(i, "approve", "m:Alice", k, "approver"),
        signDecision(i, "approve", "m:alice ", k, "approver"),
      ],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(/distinct approver/);
  });
});

describe("malformed Intents fail closed at the enforcement boundary", () => {
  const never = new Promise<Resolution>(() => {});
  it("rejects a NaN created_at (would otherwise collapse the veto window)", async () => {
    const bad = { ...intent(1, { default: "approve" }), created_at: "not-a-date" };
    await expect(awaitWithDefault(bad, never, authority.secretKey)).rejects.toThrow();
  });
  it("rejects an out-of-range timeout", async () => {
    const bad = { ...intent(1, { default: "approve" }), timeout: 1e15 };
    await expect(awaitWithDefault(bad, never, authority.secretKey)).rejects.toThrow();
  });
  it("rejects a far-future created_at that would overflow the timer (Codex review P1)", async () => {
    // Parseable but absurd: deadline - now exceeds Node's setTimeout ceiling, which
    // would clamp to ~1ms and fire the Default immediately (auto-approve). Fail closed.
    const bad = { ...intent(1, { default: "approve" }), created_at: "+275760-09-13T00:00:00.000Z" };
    await expect(awaitWithDefault(bad, never, authority.secretKey)).rejects.toThrow();
  });
});

describe("DoS: readBody is size-capped", () => {
  it("throws before buffering a body larger than the cap", async () => {
    async function* chunks() {
      for (let i = 0; i < 10; i++) yield Buffer.from("x".repeat(50));
    }
    await expect(readBody(chunks() as unknown as IncomingMessage, 100)).rejects.toThrow(/exceeds/);
  });
});

describe("DoS: PendingDecisions reaps timed-out entries", () => {
  afterEach(() => vi.useRealTimers());
  it("evicts an entry at its deadline instead of leaking forever", async () => {
    vi.useFakeTimers();
    const pd = new PendingDecisions();
    const i = intent(1);
    const p = pd.wait(i);
    p.catch(() => {}); // reaper rejects; swallow
    expect(pd.size).toBe(1);
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    expect(pd.size).toBe(0);
  });
});

describe("webhooks fail CLOSED without their secret", () => {
  it("Telegram webhookHandler() refuses to run without a secret token", () => {
    const a = new TelegramAdapter({ botToken: "t", chatId: "1", authorityKey: authority.secretKey, mode: "webhook" });
    expect(() => a.webhookHandler()).toThrow();
    a.close();
  });

  it("Telegram webhook rejects a POST with no / wrong secret header (401), accepts the right one", async () => {
    const a = new TelegramAdapter({ botToken: "t", chatId: "1", authorityKey: authority.secretKey, mode: "webhook", webhookSecret: "s3cret" });
    const server = createServer(a.webhookHandler());
    await new Promise<void>((r) => server.listen(0, r));
    const port = (server.address() as AddressInfo).port;
    const url = `http://127.0.0.1:${port}/`;
    const body = JSON.stringify({ update_id: 1 });
    try {
      const noHdr = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
      expect(noHdr.status).toBe(401);
      const wrong = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": "nope" }, body });
      expect(wrong.status).toBe(401);
      const right = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": "s3cret" }, body });
      expect(right.status).toBe(200);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
      a.close();
    }
  });

  it("WhatsApp construction requires an app secret", () => {
    const prev = process.env.WHATSAPP_APP_SECRET;
    delete process.env.WHATSAPP_APP_SECRET;
    try {
      expect(
        () => new WhatsAppAdapter({ accessToken: "t", phoneNumberId: "p", to: "1", verifyToken: "v", authorityKey: authority.secretKey }),
      ).toThrow(/WHATSAPP_APP_SECRET/);
    } finally {
      if (prev !== undefined) process.env.WHATSAPP_APP_SECRET = prev;
    }
  });
});

describe("Telegram keys the approver on the stable numeric id, not the mutable username", () => {
  it("records actor telegram:<id> regardless of username", async () => {
    const realFetch = globalThis.fetch;
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ ok: true, result: {} }), { status: 200 }));
    try {
      const a = new TelegramAdapter({ botToken: "t", chatId: "1", authorityKey: authority.secretKey, mode: "webhook", webhookSecret: "s" });
      const i = intent(1, { approvers: ["telegram:8675309"] });
      const pending = a.awaitResolution(i);
      await a.handleUpdate({
        update_id: 1,
        callback_query: { id: "c", from: { id: 8675309, username: "whoever" }, message: { message_id: 1, chat: { id: 1 }, text: "x", reply_markup: {} }, data: `cs:${i.intent_id}:approve` },
      });
      const r = await pending;
      expect(r.countersignatures[0].actor).toBe("telegram:8675309");
      a.close();
    } finally {
      vi.stubGlobal("fetch", realFetch);
      vi.unstubAllGlobals();
    }
  });
});

// ---- Findings from the Codex adversarial review of the v0.1.3 fixes ----

describe("LocalAdapter refuses quorum it cannot authenticate (Codex re-review)", () => {
  it("rejects quorum > 1 at deliver (one terminal cannot represent distinct humans)", async () => {
    const a = new LocalAdapter(authority.secretKey);
    await expect(a.deliver(intent(2))).rejects.toThrow(/single approver|quorum 1|keyed approver/);
  });
});

describe("only named approvers can decide (Codex #1)", () => {
  it("ignores an unlisted actor's approve AND veto at settle", () => {
    const i = intent(1); // approvers: m:alice / m:bob / m:carol
    const pd = new PendingDecisions();
    void pd.wait(i);
    expect(pd.settle(i.intent_id, "approve", "m:mallory", authority.secretKey)).toBeNull();
    expect(pd.settle(i.intent_id, "reject", "m:mallory", authority.secretKey)).toBeNull();
    expect(pd.settle(i.intent_id, "approve", "m:alice", authority.secretKey)?.status).toBe("resolved");
  });

  it("verifyResolution rejects an approve receipt from a non-approver", () => {
    const i = intent(1);
    const forged: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [signDecision(i, "approve", "m:mallory", authority.secretKey)],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(/not in the Intent's approvers/);
  });
});

describe("the reserved default:timeout actor can never be an approver (Codex CS-24)", () => {
  it("createIntent refuses it, and settle ignores it even on a hand-crafted hostile wire Intent", () => {
    // The primary defense: createIntent (and assertIntentInvariants) reject a
    // reserved actor as an approver up front.
    expect(() => intent(1, { approvers: ["m:alice", "default:timeout"] })).toThrow(/reserved/);
    // Defense in depth: even a hand-crafted Intent that bypasses createIntent and
    // lists it — settle's approverSet excludes the reserved actor, so it never decides.
    const base = intent(1, { approvers: ["m:alice"] });
    const hostile = { ...base, approvers: [...base.approvers, { actor: "default:timeout", mode: "vouched" as const }] };
    const pd = new PendingDecisions();
    void pd.wait(hostile);
    expect(pd.settle(hostile.intent_id, "approve", "default:timeout", authority.secretKey)).toBeNull();
    expect(pd.settle(hostile.intent_id, "approve", "Default:Timeout ", authority.secretKey)).toBeNull();
    expect(pd.settle(hostile.intent_id, "approve", "m:alice", authority.secretKey)?.status).toBe("resolved");
  });
});

describe("a decision processed after the deadline is ignored (Codex re-review)", () => {
  afterEach(() => vi.useRealTimers());
  it("settle rejects a late approval even if the reaper timer is overdue (event-loop stall)", () => {
    vi.useFakeTimers();
    const pd = new PendingDecisions();
    const i = intent(1); // approver m:alice is valid; the deadline gate must still reject
    void pd.wait(i);
    // Simulate a stall: the clock jumps past the deadline but timers have NOT run
    // (setSystemTime does not fire setTimeout), so the reaper entry is still present.
    vi.setSystemTime(deadline(i) + 1);
    expect(pd.settle(i.intent_id, "approve", "m:alice", authority.secretKey)).toBeNull();
    expect(pd.size).toBe(0); // evicted — the Default now decides
  });

  it("awaitWithDefault discards a late resolution from ANY adapter, not just PendingDecisions", async () => {
    vi.useFakeTimers();
    const i = intent(1); // default: reject
    let resolveAdapter!: (r: Resolution) => void;
    const adapterPromise = new Promise<Resolution>((res) => (resolveAdapter = res)); // a custom adapter's promise
    const pending = awaitWithDefault(i, adapterPromise, authority.secretKey); // remaining > 0: schedules the timer
    // Simulate a stall: clock jumps past the deadline (timers overdue, not fired),
    // then a late but validly-signed approval resolves the adapter promise.
    vi.setSystemTime(deadline(i) + 1);
    resolveAdapter({
      decision: "approve",
      policy: "approver",
      countersignatures: [signDecision(i, "approve", "m:alice", authority.secretKey)],
    });
    const r = await pending;
    expect(r.decision).toBe("reject"); // the Default wins; the late approval is discarded
    expect(r.policy).toBe("default");
  });
});

describe("timeout still yields a signed Default with the reaper active (Codex #2)", () => {
  afterEach(() => vi.useRealTimers());
  it("awaitWithDefault + a real pending promise at an equal deadline resolves to the Default, not a rejection", async () => {
    vi.useFakeTimers();
    const pd = new PendingDecisions();
    const i = intent(1); // default: reject, timeout 300s
    const p = pd.wait(i); // schedules the reaper
    const settled = awaitWithDefault(i, p, authority.secretKey); // schedules the default timer at ~same deadline
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    const r = await settled; // must NOT throw
    expect(r.decision).toBe("reject");
    expect(r.policy).toBe("default");
    expect(r.countersignatures[0].actor).toBe("default:timeout");
    expect(pd.size).toBe(0); // entry reaped
  });
});

describe("reject resolutions are bound to the approver allowlist too (Codex CS-21)", () => {
  it("verifyResolution rejects a veto receipt from an actor not in the Intent's approvers", () => {
    const i = intent(1); // approvers: m:alice / m:bob / m:carol
    const forged: Resolution = {
      decision: "reject",
      policy: "approver",
      countersignatures: [signDecision(i, "reject", "m:mallory", authority.secretKey)],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(/not in the Intent's approvers/);
  });

  it("verifyResolution rejects a reject resolution with an unrecognized policy", () => {
    const i = intent(1);
    const forged = {
      decision: "reject",
      policy: "x" as unknown as "approver",
      countersignatures: [signDecision(i, "reject", "m:alice", authority.secretKey)],
    } as Resolution;
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("verifyResolution rejects a policy:'default' reject that is not the canonical timeout receipt", () => {
    const i = intent(1); // default: reject — but the receipt's actor is not default:timeout
    const forged: Resolution = {
      decision: "reject",
      policy: "default",
      countersignatures: [signDecision(i, "reject", "m:mallory", authority.secretKey, "default")],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("verifyResolution rejects a 'default' reject that contradicts the Intent's declared Default", () => {
    // quorum-1 with default:"approve": the timeout could only ever have approved, so a
    // default-labelled reject receipt is forged even if it is authority-signed.
    const i = intent(1, { default: "approve" });
    const forged: Resolution = {
      decision: "reject",
      policy: "default",
      countersignatures: [signDecision(i, "reject", "default:timeout", authority.secretKey, "default")],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("awaitWithDefault refuses an authority-signed veto from an unlisted actor (fail closed)", async () => {
    const i = intent(1);
    const forged: Resolution = {
      decision: "reject",
      policy: "approver",
      countersignatures: [signDecision(i, "reject", "m:mallory", authority.secretKey)],
    };
    await expect(awaitWithDefault(i, Promise.resolve(forged), authority.secretKey)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("still ACCEPTS a listed approver's veto and the canonical timeout rejects", () => {
    const i = intent(1); // default: reject
    const veto: Resolution = {
      decision: "reject",
      policy: "approver",
      countersignatures: [signDecision(i, "reject", "m:bob", authority.secretKey)],
    };
    expect(() => verifyResolution(i, veto, authPub)).not.toThrow();

    // Genuine timeout Defaults, minted at the deadline through the production path (CS-22).
    const q = intent(3); // a multi-person quorum's timeout Default is always reject (fail closed)
    vi.useFakeTimers();
    vi.setSystemTime(deadline(i) + 1);
    const timeoutReject = defaultResolution(i, authority.secretKey);
    vi.setSystemTime(deadline(q) + 1);
    const failClosed = defaultResolution(q, authority.secretKey);
    vi.useRealTimers();
    expect(() => verifyResolution(i, timeoutReject, authPub)).not.toThrow();
    expect(() => verifyResolution(q, failClosed, authPub)).not.toThrow();
  });
});

describe("the Default cannot fire early (Codex CS-22)", () => {
  afterEach(() => vi.useRealTimers());

  /** Mint a default:timeout receipt whose signed timestamp is forged to sit past
   *  the deadline — what a hostile adapter holding the authority key would do to
   *  survive offline verification. Requires fake timers. */
  function forgeFutureDefault(i: Intent, decision: "approve" | "reject") {
    const now = Date.now();
    vi.setSystemTime(deadline(i) + 5);
    const cs = signDecision(i, decision, "default:timeout", authority.secretKey, "default");
    vi.setSystemTime(now);
    return cs;
  }

  it("verifyResolution rejects a default reject timestamped before the deadline (false timeout audit)", () => {
    const i = intent(1); // default: reject, timeout 300 — the deadline is 300s away
    const early: Resolution = {
      decision: "reject",
      policy: "default",
      countersignatures: [signDecision(i, "reject", "default:timeout", authority.secretKey, "default")],
    };
    expect(() => verifyResolution(i, early, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("verifyResolution rejects a default approve timestamped before the deadline (the auto-approve forgery)", () => {
    const i = intent(1, { default: "approve" });
    const early: Resolution = {
      decision: "approve",
      policy: "default",
      countersignatures: [signDecision(i, "approve", "default:timeout", authority.secretKey, "default")],
    };
    expect(() => verifyResolution(i, early, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("verifyResolution requires every approver receipt's signed policy to be approver", () => {
    const i = intent(2); // keyed approvers — each receipt signed by its own key
    const relabelled: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        keyedReceipt(i, "approve", "m:alice"),
        signDecision(i, "approve", "m:bob", keyOf("m:bob").secretKey, "default"), // m:bob's key, wrong policy
      ],
    };
    expect(() => verifyResolution(i, relabelled, authPub)).toThrow(/signed policy.*not "approver"/);
  });

  it("verifyResolution never treats a default:timeout RECEIPT as an approver (and createIntent refuses to list it)", () => {
    expect(() => intent(1, { approvers: ["  DEFAULT:TIMEOUT  "] })).toThrow(/reserved/);
    const i = intent(1, { approvers: ["m:alice"] });
    const forged: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [signDecision(i, "approve", "default:timeout", authority.secretKey, "approver")],
    };
    expect(() => verifyResolution(i, forged, authPub)).toThrow(/reserved actor default:timeout/);
  });

  it("a relabelled signed Default cannot win awaitWithDefault before the deadline", async () => {
    vi.useFakeTimers();
    const i = intent(1, { approvers: ["m:alice"], default: "approve" });
    const relabelled: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [forgeFutureDefault(i, "approve")],
    };
    expect(() => verifyResolution(i, relabelled, authPub)).toThrow(InvalidCountersignatureError);

    let settled = false;
    const pending = awaitWithDefault(i, Promise.resolve(relabelled), authority.secretKey)
      .then(
        (value) => ({ status: "fulfilled" as const, value }),
        (reason: unknown) => ({ status: "rejected" as const, reason }),
      )
      .then((outcome) => {
        settled = true;
        return outcome;
      });

    await vi.advanceTimersByTimeAsync(299_000);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1_000);
    const outcome = await pending;
    expect(outcome.status).toBe("fulfilled");
    if (outcome.status !== "fulfilled") throw outcome.reason;
    expect(outcome.value.policy).toBe("default");
    expect(outcome.value.countersignatures[0].actor).toBe("default:timeout");
    expect(Date.parse(outcome.value.countersignatures[0].timestamp)).toBeGreaterThanOrEqual(deadline(i));
  });

  it("defaultResolution refuses to mint before the deadline", () => {
    const i = intent(1);
    expect(() => defaultResolution(i, authority.secretKey)).toThrow(/deadline/);
  });

  it("awaitWithDefault ignores a forged future-stamped default:approve until the deadline", async () => {
    vi.useFakeTimers();
    const i = intent(1, { default: "approve" }); // the review window an early Default would collapse
    const forged: Resolution = {
      decision: "approve",
      policy: "default",
      countersignatures: [forgeFutureDefault(i, "approve")],
    };
    let settled = false;
    const pending = awaitWithDefault(i, Promise.resolve(forged), authority.secretKey).then((r) => {
      settled = true;
      return r;
    });
    await vi.advanceTimersByTimeAsync(299_000);
    expect(settled).toBe(false); // the review window is still open — no early authorization
    await vi.advanceTimersByTimeAsync(1_000);
    const r = await pending;
    expect(r.decision).toBe("approve"); // the DECLARED Default, fired AT the deadline
    expect(Date.parse(r.countersignatures[0].timestamp)).toBeGreaterThanOrEqual(deadline(i));
  });

  it("awaitWithDefault discards an early default-reject instead of accepting the false record", async () => {
    vi.useFakeTimers();
    const i = intent(1); // default: reject
    const early: Resolution = {
      decision: "reject",
      policy: "default",
      countersignatures: [signDecision(i, "reject", "default:timeout", authority.secretKey, "default")],
    };
    let settled = false;
    const pending = awaitWithDefault(i, Promise.resolve(early), authority.secretKey).then((r) => {
      settled = true;
      return r;
    });
    await vi.advanceTimersByTimeAsync(299_000);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1_000);
    const r = await pending;
    expect(r.policy).toBe("default");
    // The audit record is the GENUINE deadline receipt, not the early forgery.
    expect(Date.parse(r.countersignatures[0].timestamp)).toBeGreaterThanOrEqual(deadline(i));
  });

  it("wrapAction does not execute the action before the review window closes", async () => {
    vi.useFakeTimers();
    let ran = false;
    const hostile: Adapter = {
      channel: "hostile",
      deliver: async () => {},
      // Resolves INSTANTLY with a forged future-stamped default:approve.
      awaitResolution: (i) =>
        Promise.resolve({
          decision: "approve",
          policy: "default",
          countersignatures: [forgeFutureDefault(i, "approve")],
        }),
    };
    const act = wrapAction(
      () => {
        ran = true;
        return "done";
      },
      { action: "prod.deploy", summary: "Deploy 2.4.0", risk_tier: "critical", approvers: ["m:alice"], quorum: 1, timeout: 300, default: "approve" },
      hostile,
      { agent, authorityKey: authority.secretKey },
    );
    const p = act();
    await vi.advanceTimersByTimeAsync(299_000);
    expect(ran).toBe(false); // the forged instant-approve must NOT have run the action
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(p).resolves.toBe("done"); // the declared default:approve fires at the deadline
    expect(ran).toBe(true);
  });
});

describe("adapter faults and contradictory Defaults fail closed, never approve (Codex CS-28)", () => {
  afterEach(() => vi.useRealTimers());

  it("a pre-deadline adapter REJECTION fails closed — never falls through to a default:approve", async () => {
    vi.useFakeTimers();
    const i = intent(1, { approvers: ["m:alice"], default: "approve" }); // silence would approve
    let outcome = "pending";
    void awaitWithDefault(i, Promise.reject(new Error("approval route failed")), authority.secretKey).then(
      (r) => (outcome = `resolved:${r.decision}`),
      () => (outcome = "rejected"),
    );
    await Promise.resolve();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(300_000 + 10); // let any Default timer fire
    expect(outcome).toBe("rejected"); // a broken approval channel must NOT auto-approve
  });

  it("still resolves to the Default when the adapter simply stays silent (rejection != silence)", async () => {
    vi.useFakeTimers();
    const i = intent(1, { approvers: ["m:alice"], default: "reject" });
    const pending = awaitWithDefault(i, new Promise<Resolution>(() => {}), authority.secretKey);
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    const r = await pending;
    expect(r.policy).toBe("default"); // genuine silence still yields the Default
  });

  it("a far-future-deadline Intent with a REJECTING adapter fails closed with NO unhandled rejection", async () => {
    // The CS-28a rejection handler can throw; if the far-future guard throws after the
    // guarded promise is wired up, that guarded rejection is orphaned → unhandled → crash.
    const rejections: unknown[] = [];
    const onRej = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRej);
    try {
      const bad = { ...intent(1, { default: "approve" }), created_at: "+275760-09-13T00:00:00.000Z" };
      await expect(awaitWithDefault(bad, Promise.reject(new Error("route failed")), authority.secretKey)).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 30)); // let any unhandled rejection surface
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onRej);
    }
  });

  it("a malformed-agent Intent with a REJECTING adapter fails closed with NO unhandled rejection", async () => {
    // assertIntentInvariants now throws on a non-canonical agent key; if it throws
    // before awaitWithDefault installs its adapter-promise safety catch, the rejecting
    // adapter is orphaned → unhandled rejection → crash. The catch must come FIRST.
    const rejections: unknown[] = [];
    const onRej = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRej);
    try {
      const good = intent(1, { default: "reject" });
      const bytes = fromB64url(good.agent.public_key);
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      let alias = "";
      for (const c of alphabet) { const cand = good.agent.public_key.slice(0, -1) + c; if (cand !== good.agent.public_key && fromB64url(cand).length === 32 && fromB64url(cand).equals(bytes)) { alias = cand; break; } }
      expect(alias).not.toBe("");
      const bad = { ...good, agent: { ...good.agent, public_key: alias } };
      await expect(awaitWithDefault(bad, Promise.reject(new Error("route failed")), authority.secretKey)).rejects.toThrow(/canonical/);
      await new Promise((r) => setTimeout(r, 30)); // let any orphaned rejection surface
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onRej);
    }
  });

  it("does not swallow a contradictory early Default into an approval", async () => {
    vi.useFakeTimers();
    const i = intent(1, { approvers: ["m:alice"], default: "approve" }); // expected Default = approve
    // An authority-signed default:timeout receipt that says REJECT contradicts this intent's
    // Default. It must not be classified as an early-Default-to-discard and replaced with an
    // approve at the deadline — it must reach verifyResolution and fail closed.
    const contradictory: Resolution = {
      decision: "reject",
      policy: "default",
      countersignatures: [signDecision(i, "reject", "default:timeout", authority.secretKey, "default")],
    };
    let outcome = "pending";
    void awaitWithDefault(i, Promise.resolve(contradictory), authority.secretKey).then(
      (r) => (outcome = `resolved:${r.decision}`),
      () => (outcome = "rejected"),
    );
    await Promise.resolve();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    expect(outcome).not.toBe("resolved:approve");
  });
});

describe("the early-Default discard authenticates the receipt first (Codex CS-26)", () => {
  afterEach(() => vi.useRealTimers());

  it("does not let an UNVERIFIED policy:'default' receipt suppress a veto into a timeout-approve", async () => {
    // A default:"approve" intent (quorum 1). A custom adapter resolves EARLY with a
    // genuine human veto, contaminated by an appended receipt whose policy says
    // "default" but is FOREIGN (signed over a different intent). The old discard keyed
    // off the unverified policy field, dropped the whole veto, and the timer minted an
    // approve. It must instead reach verifyResolution and fail closed.
    const i = intent(1, { approvers: ["m:alice"], default: "approve", timeout: 1 });
    const foreign = intent(1, { approvers: ["m:alice"], default: "approve" });
    const contaminated: Resolution = {
      decision: "reject",
      policy: "approver",
      countersignatures: [
        signDecision(i, "reject", "m:alice", authority.secretKey, "approver"), // genuine veto
        signDecision(foreign, "reject", "default:timeout", authority.secretKey, "default"), // foreign, unverified-"default"
      ],
    };
    await expect(awaitWithDefault(i, Promise.resolve(contaminated), authority.secretKey)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("does not let a BADLY-SIGNED policy:'default' receipt suppress a veto either", async () => {
    const i = intent(1, { approvers: ["m:alice"], default: "approve", timeout: 1 });
    const tampered = { ...signDecision(i, "reject", "default:timeout", authority.secretKey, "default"), signature: "AAAA" };
    const contaminated: Resolution = {
      decision: "reject",
      policy: "approver",
      countersignatures: [signDecision(i, "reject", "m:alice", authority.secretKey, "approver"), tampered],
    };
    await expect(awaitWithDefault(i, Promise.resolve(contaminated), authority.secretKey)).rejects.toThrow(
      InvalidCountersignatureError,
    );
  });

  it("STILL discards a genuine authenticated early Default so the timer mints the real one (CS-22 preserved)", async () => {
    vi.useFakeTimers();
    const i = intent(1); // default: reject
    const early: Resolution = {
      decision: "reject",
      policy: "default",
      countersignatures: [signDecision(i, "reject", "default:timeout", authority.secretKey, "default")],
    };
    const pending = awaitWithDefault(i, Promise.resolve(early), authority.secretKey);
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    const r = await pending;
    expect(r.policy).toBe("default");
    expect(Date.parse(r.countersignatures[0].timestamp)).toBeGreaterThanOrEqual(deadline(i)); // genuine, on-time
  });
});

describe("the honest Default path survives a backward wall-clock step (Codex CS-23)", () => {
  afterEach(() => vi.useRealTimers());

  it("resolves to the Default (never throws/hangs) when the wall clock is behind the monotonic timer at fire time", async () => {
    vi.useFakeTimers();
    const i = intent(1); // default: reject, timeout 300 — the honest timeout path, nobody responds
    const pending = awaitWithDefault(i, new Promise<Resolution>(() => {}), authority.secretKey);
    // The libuv timer fires on the MONOTONIC clock; simulate the WALL clock having
    // stepped backward (NTP step-back / VM resume) to before the deadline at fire time.
    const spy = vi.spyOn(Date, "now").mockReturnValue(deadline(i) - 500);
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    const r = await pending; // MUST resolve — the runtime timer is the authoritative deadline signal
    spy.mockRestore();
    expect(r.policy).toBe("default");
    expect(r.decision).toBe("reject");
    expect(r.countersignatures[0].actor).toBe("default:timeout");
    // The genuine Default is stamped at/after the deadline, so verifyResolution's
    // timestamp gate (CS-22) accepts it even though the wall clock read earlier.
    expect(Date.parse(r.countersignatures[0].timestamp)).toBeGreaterThanOrEqual(deadline(i));
  });

  it("a genuine timeout Default is stamped no earlier than the deadline", async () => {
    vi.useFakeTimers();
    const i = intent(1, { default: "approve" });
    const pending = awaitWithDefault(i, new Promise<Resolution>(() => {}), authority.secretKey);
    await vi.advanceTimersByTimeAsync(300_000 + 10);
    const r = await pending;
    expect(Date.parse(r.countersignatures[0].timestamp)).toBeGreaterThanOrEqual(deadline(i));
  });
});

describe("Telegram webhook survives an oversized body (Codex #3)", () => {
  it("catches readBody's cap throw (500, no unhandled rejection) instead of leaking it", async () => {
    const rejections: unknown[] = [];
    const onRej = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRej);
    const a = new TelegramAdapter({ botToken: "t", chatId: "1", authorityKey: authority.secretKey, mode: "webhook", webhookSecret: "s3cret" });
    const handler = a.webhookHandler();
    let status = 0;
    let ended = false;
    const res = {
      headersSent: false,
      writeHead(code: number) {
        this.headersSent = true;
        status = code;
        return this;
      },
      end() {
        ended = true;
        return this;
      },
    };
    // A mock request that yields a body past the 1 MiB cap in one chunk.
    const req = {
      method: "POST",
      headers: { "x-telegram-bot-api-secret-token": "s3cret" },
      async *[Symbol.asyncIterator]() {
        yield Buffer.alloc(2_000_000);
      },
    };
    try {
      handler(req as never, res as never);
      await new Promise((r) => setTimeout(r, 30)); // let the async handler + its .catch run
      expect(rejections).toEqual([]); // #3: the outer catch swallowed readBody's throw
      expect(status).toBe(500); // and responded, rather than leaving the request hanging
      expect(ended).toBe(true);
    } finally {
      process.off("unhandledRejection", onRej);
      a.close();
    }
  });

  it("cannot forge a receipt with an accessor-backed public_key that diverges across reads", () => {
    // A crafted receipt whose `public_key` is a GETTER: it returns the trusted authority
    // key on the read the trust check uses, but the ATTACKER key on the read used to
    // canonicalize + verify the signature — a TOCTOU forgery if the verifier reads the
    // field more than once. The receipt is genuinely signed by the attacker over a body
    // that canonicalizes with the attacker key, so a naive verifier that trust-checks the
    // trusted value but signature-checks against the attacker value would accept it.
    const attacker = generateKeypair();
    const trusted = generateKeypair();
    const base = {
      countersign: "0.2" as const,
      intent_id: "11111111-1111-4111-8111-111111111111",
      decision: "approve" as const,
      actor: "m:ceo",
      policy: "approver" as const,
      timestamp: "2026-01-01T00:00:00.000Z",
      public_key: attacker.publicKey, // the body is signed with this key present
    };
    const signature = signContext(attacker.secretKey, COUNTERSIGNATURE_CONTEXT, canonicalize(base));

    let reads = 0;
    const receipt = { ...base, signature };
    Object.defineProperty(receipt, "public_key", {
      enumerable: true,
      configurable: true,
      // The classic exploit ordering: return `trusted` ONLY on the trust-check read
      // (3rd read in the multi-read verifier this fix removed), `attacker` on the
      // spread/canonicalize and signature-verify reads. A verifier that read the field
      // once per site would trust-check `trusted` yet signature-check the attacker's
      // real signature → accept. The single-snapshot fix reads it once (the spread),
      // so trust and signature see the SAME key and it fails closed.
      get() {
        reads += 1;
        return reads === 3 ? trusted.publicKey : attacker.publicKey;
      },
    });

    // Must be rejected: either the trust check sees the attacker key (not trusted), or the
    // signature check sees the trusted key (signature was made by the attacker) — never both
    // aligned, because a single snapshot is used throughout.
    expect(verifyCountersignature(receipt as never, { trustedKeys: [trusted.publicKey] })).toBe(false);
  });
});
