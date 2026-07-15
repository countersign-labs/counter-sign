// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Adapter-interface conformance: every adapter, run against a mock of its
// platform, must (1) deliver the intent outward and (2) hand back a
// Countersignature that is schema-valid, signature-valid, and identical in
// shape no matter which interaction pattern produced it.

import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { verifyCountersignature } from "../src/core/countersignature.js";
import { createIntent } from "../src/core/intent.js";
import { fromB64url, generateKeypair, signBytes, utf8 } from "../src/core/keys.js";
import type { Intent, Resolution } from "../src/core/types.js";
import { DiscordAdapter } from "../src/adapters/discord.js";
import { EmailAdapter } from "../src/adapters/email.js";
import { SlackAdapter } from "../src/adapters/slack.js";
import { TelegramAdapter } from "../src/adapters/telegram.js";
import { WhatsAppAdapter } from "../src/adapters/whatsapp.js";

const ajv = new Ajv2020.default({ strict: true });
addFormats.default(ajv);
const validateCs = ajv.compile(
  JSON.parse(readFileSync(join(import.meta.dirname, "..", "schemas", "countersignature.schema.json"), "utf8")),
);

const authority = generateKeypair();
const agent = { id: "agent:test", keypair: generateKeypair() };

function makeIntent(approvers: string[] = ["someone"]): Intent {
  return createIntent(
    {
      action: "demo.op",
      summary: "Do the thing",
      risk_tier: "medium",
      approvers,
      timeout: 300,
      default: "reject",
    },
    agent,
  );
}

/** Intercept non-localhost fetches (platform APIs); pass localhost through. */
function interceptFetch(respond: (url: string, init?: RequestInit) => unknown) {
  const real = globalThis.fetch;
  const calls: { url: string; body: any }[] = [];
  vi.stubGlobal("fetch", async (input: any, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("127.0.0.1") || url.includes("localhost")) return real(input, init);
    calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const payload = respond(url, init);
    return new Response(JSON.stringify(payload ?? {}), { status: 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

function listen(handler: (req: any, res: any) => void): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }),
    );
  });
}

interface Case {
  name: string;
  pattern: "button-webhook" | "signed link-callback";
  make(): Promise<{
    adapter: Adapter;
    /** Simulate the human approving through the platform's real callback path. */
    approve(intent: Intent): Promise<void>;
    expectedActorPrefix: string;
    /** the exact actor identity this case will produce — must be a named approver */
    approver: string;
    teardown(): Promise<void> | void;
  }>;
}

const cases: Case[] = [
  {
    name: "telegram",
    pattern: "button-webhook",
    make: async () => {
      interceptFetch(() => ({ ok: true, result: { message_id: 7, chat: { id: 1 } } }));
      const adapter = new TelegramAdapter({
        botToken: "tg-token",
        chatId: "1",
        authorityKey: authority.secretKey,
        mode: "webhook",
        webhookSecret: "tg-secret",
      });
      const { server, base } = await listen(adapter.webhookHandler());
      return {
        adapter,
        expectedActorPrefix: "telegram:",
        approver: "telegram:42",
        approve: async (intent) => {
          await fetch(`${base}/`, {
            method: "POST",
            headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": "tg-secret" },
            body: JSON.stringify({
              update_id: 1,
              callback_query: {
                id: "cbq1",
                from: { id: 42, username: "approver" },
                message: { message_id: 7, chat: { id: 1 }, text: "intent" },
                data: `cs:${intent.intent_id}:approve`,
              },
            }),
          });
        },
        teardown: () => new Promise<void>((r) => server.close(() => r())),
      };
    },
  },
  {
    name: "discord",
    pattern: "button-webhook",
    make: async () => {
      interceptFetch(() => ({ id: "msg1" }));
      const discordAppKey = generateKeypair();
      const adapter = new DiscordAdapter({
        botToken: "dc-token",
        channelId: "123",
        publicKey: fromB64url(discordAppKey.publicKey).toString("hex"),
        authorityKey: authority.secretKey,
      });
      const { server, base } = await listen(adapter.interactionHandler());
      return {
        adapter,
        expectedActorPrefix: "discord:",
        approver: "discord:u42",
        approve: async (intent) => {
          const body = JSON.stringify({
            type: 3,
            data: { custom_id: `cs:${intent.intent_id}:approve` },
            member: { user: { id: "u42" } },
            message: { content: "intent" },
          });
          const ts = String(Math.floor(Date.now() / 1000));
          const sig = fromB64url(signBytes(discordAppKey.secretKey, utf8(ts + body))).toString("hex");
          const res = await fetch(base, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-signature-ed25519": sig,
              "x-signature-timestamp": ts,
            },
            body,
          });
          expect(res.status).toBe(200);
        },
        teardown: () => new Promise<void>((r) => server.close(() => r())),
      };
    },
  },
  {
    name: "slack",
    pattern: "button-webhook",
    make: async () => {
      interceptFetch(() => ({ ok: true }));
      const signingSecret = "slack-signing-secret";
      const adapter = new SlackAdapter({
        botToken: "xoxb-test",
        channelId: "C123",
        signingSecret,
        authorityKey: authority.secretKey,
      });
      const { server, base } = await listen(adapter.interactivityHandler());
      return {
        adapter,
        expectedActorPrefix: "slack:",
        approver: "slack:U42",
        approve: async (intent) => {
          const payload = JSON.stringify({
            type: "block_actions",
            user: { id: "U42" },
            actions: [{ action_id: "countersign_approve", value: `cs:${intent.intent_id}:approve` }],
          });
          const body = `payload=${encodeURIComponent(payload)}`;
          const ts = String(Math.floor(Date.now() / 1000));
          const sig = `v0=${createHmac("sha256", signingSecret).update(`v0:${ts}:${body}`).digest("hex")}`;
          const res = await fetch(base, {
            method: "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              "x-slack-request-timestamp": ts,
              "x-slack-signature": sig,
            },
            body,
          });
          expect(res.status).toBe(200);
        },
        teardown: () => new Promise<void>((r) => server.close(() => r())),
      };
    },
  },
  {
    name: "whatsapp",
    pattern: "button-webhook",
    make: async () => {
      interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
      const appSecret = "meta-app-secret";
      const adapter = new WhatsAppAdapter({
        accessToken: "meta-token",
        phoneNumberId: "555",
        to: "6591234567",
        verifyToken: "verify-me",
        appSecret,
        authorityKey: authority.secretKey,
      });
      const { server, base } = await listen(adapter.webhookHandler());
      return {
        adapter,
        expectedActorPrefix: "whatsapp:",
        approver: "whatsapp:6591234567",
        approve: async (intent) => {
          const body = JSON.stringify({
            entry: [
              {
                changes: [
                  {
                    value: {
                      messages: [
                        { type: "button", from: "6591234567", button: { payload: `cs:${intent.intent_id}:approve`, text: "Approve" } },
                      ],
                    },
                  },
                ],
              },
            ],
          });
          const sig = `sha256=${createHmac("sha256", appSecret).update(body).digest("hex")}`;
          const res = await fetch(base, {
            method: "POST",
            headers: { "content-type": "application/json", "x-hub-signature-256": sig },
            body,
          });
          expect(res.status).toBe(200);
        },
        teardown: () => new Promise<void>((r) => server.close(() => r())),
      };
    },
  },
  {
    name: "email",
    pattern: "signed link-callback",
    make: async () => {
      const sent: { text?: string }[] = [];
      const transport = {
        sendMail: async (opts: any) => void sent.push(opts),
        close: () => {},
      } as any;
      const adapter = new EmailAdapter({
        transport,
        from: "approvals@countersign.local",
        to: "ops@countersign.local",
        callbackBaseUrl: "http://placeholder",
        authorityKey: authority.secretKey,
      });
      const { server, base } = await listen(adapter.handleRequest());
      return {
        adapter,
        expectedActorPrefix: "email:",
        approver: "email:ops@countersign.local",
        approve: async () => {
          const text = sent[0]?.text ?? "";
          const approveUrl = text.match(/Approve: (\S+)/)?.[1];
          expect(approveUrl).toBeTruthy();
          const token = new URL(approveUrl!).searchParams.get("token")!;
          // Real flow: GET the confirm page, then POST the form.
          const get = await fetch(`${base}/decide?token=${encodeURIComponent(token)}`);
          expect(get.status).toBe(200);
          const post = await fetch(`${base}/decide`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: `token=${encodeURIComponent(token)}`,
          });
          expect(post.status).toBe(200);
        },
        teardown: () => new Promise<void>((r) => server.close(() => r())),
      };
    },
  },
];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe.each(cases)("adapter conformance: $name ($pattern)", (c) => {
  it("delivers, then returns a schema-valid, signature-valid Resolution", async () => {
    const { adapter, approve, expectedActorPrefix, approver, teardown } = await c.make();
    try {
      const intent = makeIntent([approver]);
      await adapter.deliver(intent);

      const pending = adapter.awaitResolution(intent);
      await approve(intent);
      const resolution: Resolution = await pending;

      expect(resolution.decision).toBe("approve");
      expect(resolution.policy).toBe("approver");
      expect(resolution.countersignatures).toHaveLength(1); // quorum 1

      // Each receipt is identical in shape and equally verifiable regardless of
      // interaction pattern (spec §2).
      const cs = resolution.countersignatures[0];
      expect(validateCs(cs), JSON.stringify(validateCs.errors)).toBe(true);
      expect(verifyCountersignature(cs)).toBe(true);
      expect(cs.intent_id).toBe(intent.intent_id);
      expect(cs.decision).toBe("approve");
      expect(cs.actor.startsWith(expectedActorPrefix)).toBe(true);
      expect(cs.public_key).toBe(authority.publicKey);
    } finally {
      await teardown();
      await adapter.close?.();
    }
  });
});

describe("webhook authentication is enforced before any payload is trusted", () => {
  it("slack: rejects a bad signature and decides nothing", async () => {
    interceptFetch(() => ({ ok: true }));
    const adapter = new SlackAdapter({
      botToken: "xoxb",
      channelId: "C1",
      signingSecret: "right-secret",
      authorityKey: authority.secretKey,
    });
    const { server, base } = await listen(adapter.interactivityHandler());
    try {
      const intent = makeIntent();
      await adapter.deliver(intent);
      const decision = adapter.awaitResolution(intent);
      let settled = false;
      void decision.then(() => (settled = true), () => {});

      const body = `payload=${encodeURIComponent(JSON.stringify({ type: "block_actions", user: { id: "U1" }, actions: [{ value: `cs:${intent.intent_id}:approve` }] }))}`;
      const ts = String(Math.floor(Date.now() / 1000));
      const res = await fetch(base, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "x-slack-request-timestamp": ts,
          "x-slack-signature": `v0=${"0".repeat(64)}`,
        },
        body,
      });
      expect(res.status).toBe(401);
      await new Promise((r) => setTimeout(r, 20));
      expect(settled).toBe(false);
    } finally {
      server.close();
      adapter.close();
    }
  });

  it("discord: rejects an unsigned interaction", async () => {
    const appKey = generateKeypair();
    const adapter = new DiscordAdapter({
      botToken: "t",
      channelId: "c",
      publicKey: fromB64url(appKey.publicKey).toString("hex"),
      authorityKey: authority.secretKey,
    });
    const { server, base } = await listen(adapter.interactionHandler());
    try {
      const res = await fetch(base, { method: "POST", body: JSON.stringify({ type: 1 }) });
      expect(res.status).toBe(401);
    } finally {
      server.close();
      adapter.close();
    }
  });

  it("discord: a non-approver's click neither resolves the request nor strips the buttons (CS-27)", async () => {
    interceptFetch(() => ({ id: "msg1" }));
    const appKey = generateKeypair();
    const adapter = new DiscordAdapter({
      botToken: "t",
      channelId: "c",
      publicKey: fromB64url(appKey.publicKey).toString("hex"),
      authorityKey: authority.secretKey,
    });
    const { server, base } = await listen(adapter.interactionHandler());
    const click = async (userId: string, decision: string, intent: Intent) => {
      const body = JSON.stringify({
        type: 3,
        data: { custom_id: `cs:${intent.intent_id}:${decision}` },
        member: { user: { id: userId } },
        message: { content: "intent", components: [{ type: 1, components: [{ type: 2 }] }] },
      });
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = fromB64url(signBytes(appKey.secretKey, utf8(ts + body))).toString("hex");
      const res = await fetch(base, {
        method: "POST",
        headers: { "content-type": "application/json", "x-signature-ed25519": sig, "x-signature-timestamp": ts },
        body,
      });
      return res.json();
    };
    try {
      const intent = makeIntent(["discord:approver"]);
      await adapter.deliver(intent);
      const pending = adapter.awaitResolution(intent);
      let resolved = false;
      void pending.then(() => (resolved = true), () => {});

      // A channel member who is NOT an approver clicks Approve.
      const intruder = await click("intruder", "approve", intent);
      // Must not falsely claim resolution and must not strip the approver's buttons.
      expect(JSON.stringify(intruder)).not.toMatch(/Resolved/i);
      expect(intruder.data?.components ?? null).not.toEqual([]);
      await new Promise((r) => setTimeout(r, 15));
      expect(resolved).toBe(false); // request is still open

      // The real approver can still decide — the request was not griefed.
      await click("approver", "approve", intent);
      const r = await pending;
      expect(r.decision).toBe("approve");
    } finally {
      server.close();
      adapter.close();
    }
  });

  it("discord: an interaction this instance does not track does not strip the buttons (CS-28)", async () => {
    // A click can arrive before awaitResolution registers the entry (deliver runs first in
    // wrapAction) or on another process-local instance. `!has()` must NOT be treated as
    // "closed" and strip the approver's buttons — that would grief the request.
    interceptFetch(() => ({ id: "msg1" }));
    const appKey = generateKeypair();
    const adapter = new DiscordAdapter({
      botToken: "t",
      channelId: "c",
      publicKey: fromB64url(appKey.publicKey).toString("hex"),
      authorityKey: authority.secretKey,
    });
    const { server, base } = await listen(adapter.interactionHandler());
    try {
      const intent = makeIntent(["discord:approver"]); // never registered via awaitResolution
      const body = JSON.stringify({
        type: 3,
        data: { custom_id: `cs:${intent.intent_id}:approve` },
        member: { user: { id: "approver" } },
        message: { content: "intent", components: [{ type: 1, components: [{ type: 2 }] }] },
      });
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = fromB64url(signBytes(appKey.secretKey, utf8(ts + body))).toString("hex");
      const res = await fetch(base, {
        method: "POST",
        headers: { "content-type": "application/json", "x-signature-ed25519": sig, "x-signature-timestamp": ts },
        body,
      });
      const out = await res.json();
      expect(out.data?.components ?? null).not.toEqual([]); // buttons NOT stripped
      expect(JSON.stringify(out)).not.toMatch(/Resolved/i);
    } finally {
      server.close();
      adapter.close();
    }
  });

  it("whatsapp: answers the GET verification challenge only for the right token", async () => {
    const adapter = new WhatsAppAdapter({
      accessToken: "t",
      phoneNumberId: "p",
      to: "1",
      verifyToken: "expected-token",
      appSecret: "meta-app-secret",
      authorityKey: authority.secretKey,
    });
    const { server, base } = await listen(adapter.webhookHandler());
    try {
      const good = await fetch(`${base}/?hub.mode=subscribe&hub.verify_token=expected-token&hub.challenge=12345`);
      expect(await good.text()).toBe("12345");
      const bad = await fetch(`${base}/?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=12345`);
      expect(bad.status).toBe(403);
    } finally {
      server.close();
      adapter.close();
    }
  });
});
