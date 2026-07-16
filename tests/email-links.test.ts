// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// The load-bearing rules of the signed link-callback pattern (spec §2):
// links are signed, single-use, expire with the Intent's timeout, and a GET
// can never decide anything.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { EmailAdapter, createLinkToken, verifyLinkToken } from "../src/adapters/email.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import { deadline } from "../src/core/defaults.js";
import type { Intent, Resolution } from "../src/core/types.js";

const authority = generateKeypair();
const agent = { id: "agent:test", keypair: generateKeypair() };

function makeIntent(timeout = 300): Intent {
  return createIntent(
    {
      action: "demo.op",
      summary: "Do the thing",
      risk_tier: "high",
      approvers: ["email:ops@countersign.local"],
      timeout,
      default: "reject",
    },
    agent,
  );
}

interface Harness {
  adapter: EmailAdapter;
  base: string;
  server: Server;
  sent: { text?: string }[];
}

async function makeHarness(): Promise<Harness> {
  const sent: { text?: string }[] = [];
  const adapter = new EmailAdapter({
    transport: { sendMail: async (o: any) => void sent.push(o), close: () => {} } as any,
    from: "approvals@countersign.local",
    to: "ops@countersign.local",
    callbackBaseUrl: "http://placeholder",
    authorityKey: authority.secretKey,
  });
  const server = createServer(adapter.handleRequest());
  const base = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
  });
  return { adapter, base, server, sent };
}

let harness: Harness;
afterEach(() => {
  harness?.server.close();
  harness?.adapter.close();
});

const getPage = (h: Harness, token: string) => fetch(`${h.base}/decide?token=${encodeURIComponent(token)}`);
const postDecision = (h: Harness, token: string) =>
  fetch(`${h.base}/decide`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `token=${encodeURIComponent(token)}`,
  });

describe("link tokens", () => {
  it("round-trip: token verifies and carries intent, decision, and the Intent's exact deadline", () => {
    const intent = makeIntent(120);
    const token = createLinkToken(intent, "approve", authority.secretKey);
    const payload = verifyLinkToken(token, authority.publicKey);
    expect(payload).toEqual({ intent_id: intent.intent_id, decision: "approve", exp: deadline(intent) });
  });

  it("a tampered token fails verification", () => {
    const intent = makeIntent();
    const token = createLinkToken(intent, "reject", authority.secretKey);
    const [body, sig] = token.split(".");
    const forgedBody = Buffer.from(
      Buffer.from(body, "base64url").toString("utf8").replace('"reject"', '"approve"'),
    ).toString("base64url");
    expect(verifyLinkToken(`${forgedBody}.${sig}`, authority.publicKey)).toBeNull();
    expect(verifyLinkToken(token, generateKeypair().publicKey)).toBeNull();
  });
});

describe("GET cannot decide (mail-scanner prefetch safety)", () => {
  it("any number of GETs leaves the intent pending; only the POST decides", async () => {
    harness = await makeHarness();
    const intent = makeIntent();
    await harness.adapter.deliver(intent);
    const decision = harness.adapter.awaitResolution(intent);
    let settled: Resolution | undefined;
    void decision.then((r) => (settled = r));

    const token = createLinkToken(intent, "approve", authority.secretKey);
    for (let i = 0; i < 3; i++) {
      const res = await getPage(harness, token);
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("Nothing happens until you press the button");
    }
    await new Promise((r) => setTimeout(r, 20));
    expect(settled).toBeUndefined();

    const post = await postDecision(harness, token);
    expect(post.status).toBe(200);
    const r = await decision;
    expect(r.decision).toBe("approve");
    expect(r.countersignatures[0].actor).toBe("email:ops@countersign.local");
  });
});

describe("single-use", () => {
  it("the second POST is refused and produces no second countersignature", async () => {
    harness = await makeHarness();
    const intent = makeIntent();
    await harness.adapter.deliver(intent);
    const decision = harness.adapter.awaitResolution(intent);

    const approveToken = createLinkToken(intent, "approve", authority.secretKey);
    expect((await postDecision(harness, approveToken)).status).toBe(200);
    await decision;

    const again = await postDecision(harness, approveToken);
    expect(again.status).toBe(410);
    expect(await again.text()).toContain("single-use");
  });

  it("once decided, the OTHER link for the same intent is dead too", async () => {
    harness = await makeHarness();
    const intent = makeIntent();
    await harness.adapter.deliver(intent);
    const decision = harness.adapter.awaitResolution(intent);

    await postDecision(harness, createLinkToken(intent, "reject", authority.secretKey));
    const r = await decision;
    expect(r.decision).toBe("reject");

    const approveAttempt = await postDecision(harness, createLinkToken(intent, "approve", authority.secretKey));
    expect(approveAttempt.status).toBe(410);
  });
});

describe("path-prefixed mount (proxy preserves the prefix)", () => {
  it("serves and decides at */decide, and the confirm form self-posts (not origin-root /decide)", async () => {
    harness = await makeHarness();
    const intent = makeIntent();
    await harness.adapter.deliver(intent);
    const decision = harness.adapter.awaitResolution(intent);
    const token = createLinkToken(intent, "approve", authority.secretKey);
    // GET at a PREFIXED path must render (handler matches "*/decide", not exactly "/decide").
    const get = await fetch(`${harness.base}/approvals/decide?token=${encodeURIComponent(token)}`);
    expect(get.status).toBe(200);
    expect(await get.text()).not.toContain('action="/decide"'); // no origin-root action that 404s behind a prefix
    // POST at the same prefixed path decides.
    const post = await fetch(`${harness.base}/approvals/decide`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `token=${encodeURIComponent(token)}`,
    });
    expect(post.status).toBe(200);
    expect((await decision).decision).toBe("approve");
  });
});

describe("settle() returning null is surfaced honestly (no false 'Countersignature issued')", () => {
  it("tells the human the decision was NOT recorded when the recipient is not a named approver, and does not burn the links", async () => {
    harness = await makeHarness(); // cfg.to = ops@countersign.local
    // The Intent names a DIFFERENT approver than the configured recipient: deliver()
    // emails cfg.to anyway, that human confirms, and settle() returns null (unlisted
    // actor). The page must NOT claim a Countersignature was issued — that would tell
    // a human "approved" while the Intent silently falls to its timeout Default.
    const intent = createIntent(
      { action: "demo.op", summary: "Do the thing", risk_tier: "high", approvers: ["email:security@corp.local"], timeout: 300, default: "reject" },
      agent,
    );
    await harness.adapter.deliver(intent);
    void harness.adapter.awaitResolution(intent).catch(() => {}); // register; consumed by close()
    const token = createLinkToken(intent, "approve", authority.secretKey);
    const post = await postDecision(harness, token);
    const text = await post.text();
    expect(post.status).not.toBe(200);
    expect(text).not.toContain("has been issued");
    expect(text).toMatch(/not recorded|could not be recorded/i);
    // The links are NOT burned: the intent is still pending, so the confirm page still renders.
    const get = await getPage(harness, token);
    expect(get.status).toBe(200);
    expect(await get.text()).toContain("Nothing happens until you press the button");
  });
});

describe("decided-set hygiene (long-running callback server)", () => {
  it("prunes decided entries once their links have expired (no unbounded growth)", async () => {
    harness = await makeHarness();
    const a = makeIntent(1); // 1-second window: its links die upstream at the expiry check
    await harness.adapter.deliver(a);
    const dA = harness.adapter.awaitResolution(a);
    expect((await postDecision(harness, createLinkToken(a, "approve", authority.secretKey))).status).toBe(200);
    await dA;
    const decided = (harness.adapter as unknown as { decided: { has(k: string): boolean } }).decided;
    expect(decided.has(a.intent_id)).toBe(true);
    await new Promise((r) => setTimeout(r, 1100)); // past a's deadline — the entry is now useless
    const b = makeIntent(300);
    await harness.adapter.deliver(b);
    const dB = harness.adapter.awaitResolution(b);
    expect((await postDecision(harness, createLinkToken(b, "approve", authority.secretKey))).status).toBe(200);
    await dB;
    expect(decided.has(a.intent_id)).toBe(false); // pruned when the next decision landed
    expect(decided.has(b.intent_id)).toBe(true);
  }, 10000);
});

describe("expiry matches the Intent timeout", () => {
  it("a token whose deadline has passed cannot decide, by GET or POST", async () => {
    harness = await makeHarness();
    const intent = makeIntent(300);
    // Backdate the deadline by rewriting created_at BEFORE the token is minted:
    // the expiry inside the link always equals the Intent's deadline.
    const expired: Intent = { ...intent, created_at: new Date(Date.now() - 301_000).toISOString() };
    await harness.adapter.deliver(expired);
    const decision = harness.adapter.awaitResolution(expired);
    let settled = false;
    void decision.then(() => (settled = true), () => {});

    const token = createLinkToken(expired, "approve", authority.secretKey);
    const get = await getPage(harness, token);
    expect(get.status).toBe(410);
    const post = await postDecision(harness, token);
    expect(post.status).toBe(410);
    expect(await post.text()).toContain("expired");
    await new Promise((r) => setTimeout(r, 20));
    expect(settled).toBe(false);
  });

  it("the emailed links carry exactly the Intent's deadline as expiry", async () => {
    harness = await makeHarness();
    const intent = makeIntent(60);
    await harness.adapter.deliver(intent);
    const text = harness.sent[0]?.text ?? "";
    const approveUrl = text.match(/Approve: (\S+)/)?.[1];
    const token = new URL(approveUrl!).searchParams.get("token")!;
    const payload = verifyLinkToken(token, authority.publicKey);
    expect(payload?.exp).toBe(deadline(intent));
  });
});
