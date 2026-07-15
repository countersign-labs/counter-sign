// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Regression tests for the pre-public adversarial stress test: each `it` below
// encodes a confirmed exploit and asserts it is now BLOCKED. See docs/security-review.md.

import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PendingDecisions, readBody } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { awaitWithDefault, deadline, verifyResolution } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Intent, Resolution } from "../src/core/types.js";
import { TelegramAdapter } from "../src/adapters/telegram.js";
import { WhatsAppAdapter } from "../src/adapters/whatsapp.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const authPub = publicKeyFromSecret(authority.secretKey);

function intent(quorum: number, over: Partial<Parameters<typeof createIntent>[0]> = {}): Intent {
  return createIntent(
    { action: "prod.deploy", summary: "Deploy 2.4.0", risk_tier: "critical", approvers: ["m:alice", "m:bob", "m:carol"], quorum, timeout: 300, default: "reject", ...over },
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
    const legit: Resolution = {
      decision: "approve",
      policy: "default",
      countersignatures: [signDecision(da, "approve", "default:timeout", authority.secretKey, "default")],
    };
    expect(() => verifyResolution(da, legit, authPub)).not.toThrow();

    const q = intent(2);
    const humans: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [signDecision(q, "approve", "m:alice", authority.secretKey), signDecision(q, "approve", "m:bob", authority.secretKey)],
    };
    expect(() => verifyResolution(q, humans, authPub)).not.toThrow();
  });
});

describe("one human cannot fill a multi-person quorum via actor variants", () => {
  it("counts alice / Alice / 'alice ' as ONE distinct approver", () => {
    const i = intent(3);
    const forged: Resolution = {
      decision: "approve",
      policy: "approver",
      countersignatures: [
        signDecision(i, "approve", "m:alice", authority.secretKey),
        signDecision(i, "approve", "m:Alice", authority.secretKey),
        signDecision(i, "approve", "m:alice ", authority.secretKey),
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
});
