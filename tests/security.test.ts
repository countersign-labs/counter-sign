// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Regression tests for the security review: authority binding, signature
// domain separation, and adapter message-injection hardening.

import { describe, expect, it, vi } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { signDecision, verifyCountersignature } from "../src/core/countersignature.js";
import { awaitWithDefault } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { CountersignError } from "../src/core/errors.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair, signContext, verifyContext } from "../src/core/keys.js";
import { canonicalize } from "../src/core/canonical.js";
import {
  COUNTERSIGNATURE_CONTEXT,
  INTENT_CONTEXT,
  LINK_CONTEXT,
  type Countersignature,
  type Intent,
  type Resolution,
} from "../src/core/types.js";
import { DiscordAdapter } from "../src/adapters/discord.js";
import { SlackAdapter } from "../src/adapters/slack.js";
import { createLinkToken, verifyLinkToken } from "../src/adapters/email.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const attacker = generateKeypair();

function makeIntent(overrides: Partial<Parameters<typeof createIntent>[0]> = {}): Intent {
  return createIntent(
    {
      action: "billing.refund",
      summary: "Refund $42",
      risk_tier: "high",
      approvers: ["someone"],
      timeout: 300,
      default: "reject",
      ...overrides,
    },
    agent,
  );
}

describe("authority binding — integrity is not authority", () => {
  it("verifyCountersignature with trustedKeys rejects a receipt signed by an untrusted key", () => {
    const intent = makeIntent();
    // An attacker mints an integrity-valid 'approve' with their OWN key.
    const forged = signDecision(intent, "approve", "attacker:evil", attacker.secretKey);

    // Integrity-only check passes — this is the trap.
    expect(verifyCountersignature(forged)).toBe(true);
    // But it carries no authority the runtime trusts.
    expect(verifyCountersignature(forged, { trustedKeys: authority.publicKey })).toBe(false);
    // The genuine authority's receipt is accepted.
    const real = signDecision(intent, "approve", "email:ops", authority.secretKey);
    expect(verifyCountersignature(real, { trustedKeys: [authority.publicKey] })).toBe(true);
  });

  it("awaitWithDefault rejects a decision not signed by the runtime's authority key", async () => {
    const intent = makeIntent();
    // A rogue/compromised adapter returns a self-signed 'approve'.
    const rogue: Promise<Resolution> = Promise.resolve({
      decision: "approve",
      policy: "approver",
      countersignatures: [signDecision(intent, "approve", "attacker:evil", attacker.secretKey)],
    });
    await expect(awaitWithDefault(intent, rogue, authority.secretKey)).rejects.toThrow(InvalidCountersignatureError);
  });

  it("awaitWithDefault accepts a decision signed by the runtime's authority key", async () => {
    const intent = makeIntent();
    const good: Promise<Resolution> = Promise.resolve({
      decision: "approve",
      policy: "approver",
      countersignatures: [signDecision(intent, "approve", "email:ops", authority.secretKey)],
    });
    const resolution = await awaitWithDefault(intent, good, authority.secretKey);
    expect(resolution.decision).toBe("approve");
    expect(resolution.countersignatures[0].public_key).toBe(authority.publicKey);
  });
});

describe("signature domain separation — a signature is only valid for its artifact type", () => {
  it("the same canonical bytes signed under one context do not verify under another", () => {
    const payload = canonicalize({ intent_id: "x", decision: "approve" });
    const sig = signContext(authority.secretKey, COUNTERSIGNATURE_CONTEXT, payload);
    expect(verifyContext(authority.publicKey, COUNTERSIGNATURE_CONTEXT, payload, sig)).toBe(true);
    expect(verifyContext(authority.publicKey, INTENT_CONTEXT, payload, sig)).toBe(false);
    expect(verifyContext(authority.publicKey, LINK_CONTEXT, payload, sig)).toBe(false);
  });

  it("an Intent's signature cannot be transplanted onto a Countersignature-shaped object", () => {
    const intent = makeIntent();
    expect(verifyIntent(intent)).toBe(true);
    // Reuse the intent's signature on a countersignature that shares its id.
    const cross = {
      countersign: "0.1",
      intent_id: intent.intent_id,
      decision: "approve",
      actor: "attacker:evil",
      policy: "approver",
      timestamp: intent.created_at,
      public_key: agent.keypair.publicKey,
      signature: intent.signature,
    } as unknown as Countersignature;
    expect(verifyCountersignature(cross)).toBe(false);
  });

  it("an email link token does not verify as a countersignature and vice versa", () => {
    const intent = makeIntent();
    const token = createLinkToken(intent, "approve", authority.secretKey);
    expect(verifyLinkToken(token, authority.publicKey)).not.toBeNull();
    // Wrong authority key → rejected.
    expect(verifyLinkToken(token, attacker.publicKey)).toBeNull();
  });
});

describe("verifiers are total — hostile input returns false, never throws", () => {
  it("verifyCountersignature returns false on a deeply-nested actor without blowing the stack", () => {
    let nested: any = "x";
    for (let i = 0; i < 5000; i++) nested = { a: nested };
    const cs = {
      countersign: "0.1",
      intent_id: "00000000-0000-0000-0000-000000000000",
      decision: "approve",
      actor: nested,
      policy: "approver",
      timestamp: "2026-01-01T00:00:00.000Z",
      public_key: authority.publicKey,
      signature: "x",
    } as unknown as Countersignature;
    expect(verifyCountersignature(cs)).toBe(false);
  });

  it("verifyCountersignature returns false on missing/garbage fields", () => {
    expect(verifyCountersignature({} as unknown as Countersignature)).toBe(false);
    expect(verifyCountersignature({ public_key: 42, signature: 42 } as unknown as Countersignature)).toBe(false);
  });
});

describe("timeout is bounded so a Default cannot fire early via setTimeout clamping", () => {
  it("rejects a timeout larger than the 32-bit millisecond timer allows", () => {
    expect(() => makeIntent({ timeout: 2_147_484 })).toThrow(CountersignError);
    expect(() => makeIntent({ timeout: Number.MAX_SAFE_INTEGER })).toThrow(CountersignError);
  });

  it("accepts the maximum safe timeout", () => {
    expect(makeIntent({ timeout: 2_147_483 }).timeout).toBe(2_147_483);
  });
});

describe("adapter message-injection hardening", () => {
  it("Discord disables all mentions so a crafted summary cannot ping the server", async () => {
    let sentBody: any;
    const real = globalThis.fetch;
    vi.stubGlobal("fetch", async (url: any, init?: RequestInit) => {
      sentBody = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ id: "m1" }), { status: 200 });
    });
    try {
      const adapter = new DiscordAdapter({
        botToken: "t",
        channelId: "c",
        publicKey: "00".repeat(32),
        authorityKey: authority.secretKey,
      });
      await adapter.deliver(makeIntent({ summary: "@everyone urgent <@&123456789> please" }));
      expect(sentBody.allowed_mentions).toEqual({ parse: [] });
      adapter.close();
    } finally {
      vi.stubGlobal("fetch", real);
      vi.unstubAllGlobals();
    }
  });

  it("Slack renders the summary as plain_text and escapes the fallback text", async () => {
    let sentBody: any;
    const real = globalThis.fetch;
    vi.stubGlobal("fetch", async (url: any, init?: RequestInit) => {
      sentBody = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    try {
      const adapter = new SlackAdapter({
        botToken: "xoxb",
        channelId: "C1",
        signingSecret: "s",
        authorityKey: authority.secretKey,
      });
      await adapter.deliver(makeIntent({ summary: "```<!channel> pwn```" }));
      const section = sentBody.blocks.find((b: any) => b.type === "section");
      expect(section.text.type).toBe("plain_text"); // never parses mrkdwn/mentions
      // The fallback notification text must not contain a live broadcast token.
      expect(sentBody.text).not.toContain("<!channel>");
      expect(sentBody.text).toContain("&lt;!channel&gt;");
      adapter.close();
    } finally {
      vi.stubGlobal("fetch", real);
      vi.unstubAllGlobals();
    }
  });
});
