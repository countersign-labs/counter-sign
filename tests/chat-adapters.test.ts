// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Chat adapters: who gets asked, who is believed, and never asking anyone to
// approve text they cannot see in full. Platform APIs are stubbed the same way
// as in adapters.test.ts; webhooks are driven through a real local server.

import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatIntent } from "../src/adapter.js";
import { createIntent } from "../src/core/intent.js";
import { CountersignError } from "../src/core/errors.js";
import { fromB64url, generateKeypair, signBytes, utf8 } from "../src/core/keys.js";
import type { Intent, IntentFields } from "../src/core/types.js";
import { DiscordAdapter } from "../src/adapters/discord.js";
import { SLACK_MAX_SECTION_TEXT_LENGTH, SlackAdapter, slackConfigFromEnv } from "../src/adapters/slack.js";
import {
  TELEGRAM_MAX_MESSAGE_LENGTH,
  TelegramAdapter,
  TelegramPollingConflictError,
  telegramConfigFromEnv,
} from "../src/adapters/telegram.js";
import {
  DEFAULT_WHATSAPP_TEMPLATE_BODY,
  DeliveryPartialError,
  WHATSAPP_MAX_TEMPLATE_BODY_LENGTH,
  WhatsAppAdapter,
  whatsappConfigFromEnv,
  whatsappTemplateParameters,
  renderWhatsAppTemplateBody,
} from "../src/adapters/whatsapp.js";

const root = join(import.meta.dirname, "..");
const authority = generateKeypair();
const agent = { id: "agent:test", keypair: generateKeypair() };

function makeIntent(overrides: Partial<IntentFields> = {}): Intent {
  return createIntent(
    {
      action: "demo.op",
      summary: "Do the thing",
      risk_tier: "medium",
      approvers: ["someone"],
      timeout: 300,
      default: "reject",
      ...overrides,
    },
    agent,
  );
}

type Call = { url: string; body: any };

/** Stub non-localhost fetches; `respond` may return a Response or a JSON payload. */
function interceptFetch(respond: (url: string, body: any) => unknown = () => ({ ok: true, result: {} })): Call[] {
  const real = globalThis.fetch;
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (input: any, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("127.0.0.1") || url.includes("localhost")) return real(input, init);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, body });
    const out = respond(url, body);
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out ?? {}), { status: 200, headers: { "content-type": "application/json" } });
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

const settleTick = () => new Promise((r) => setTimeout(r, 25));

/** Watch a promise without letting a rejection go unhandled. */
function watch<T>(p: Promise<T>) {
  const state: { done: boolean; value?: T; error?: unknown } = { done: false };
  p.then(
    (v) => Object.assign(state, { done: true, value: v }),
    (e) => Object.assign(state, { done: true, error: e }),
  );
  return state;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── WhatsApp ────────────────────────────────────────────────────────────────

const WA_SECRET = "meta-app-secret";
const WA_ENV = ["WHATSAPP_TO", "WHATSAPP_RECIPIENT_MODE", "WHATSAPP_REQUIRE_PHONE_NUMBER_ID", "WHATSAPP_TEMPLATE_BODY"];
const savedWaEnv = Object.fromEntries(WA_ENV.map((k) => [k, process.env[k]]));
beforeEach(() => {
  for (const k of WA_ENV) delete process.env[k]; // a stray env value must not pick the mode
});
afterEach(() => {
  for (const k of WA_ENV) {
    if (savedWaEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedWaEnv[k];
  }
});

function wa(extra: Record<string, unknown> = {}) {
  return new WhatsAppAdapter({
    accessToken: "meta-token",
    phoneNumberId: "555",
    verifyToken: "v",
    appSecret: WA_SECRET,
    authorityKey: authority.secretKey,
    ...extra,
  });
}

/** Per-approver delivery: an explicit opt-in. */
const waApprovers = (extra: Record<string, unknown> = {}) => wa({ recipientMode: "approvers", ...extra });

async function pressWhatsApp(base: string, intent: Intent, from: string, metadata?: Record<string, unknown>) {
  const body = JSON.stringify({
    entry: [
      {
        changes: [
          {
            value: {
              ...(metadata ? { metadata } : {}),
              messages: [
                {
                  type: "button",
                  from,
                  id: "wamid.reply",
                  context: { id: "wamid.original" },
                  button: { payload: `cs:${intent.intent_id}:approve`, text: "Approve" },
                },
              ],
            },
          },
        ],
      },
    ],
  });
  const sig = `sha256=${createHmac("sha256", WA_SECRET).update(body).digest("hex")}`;
  return fetch(base, { method: "POST", headers: { "content-type": "application/json", "x-hub-signature-256": sig }, body });
}

describe("whatsapp: 0.2.0 behaviour when no recipient mode is given (F3)", () => {
  it("with `to` set, delivers to `to` an Intent that also names another whatsapp approver (quorum 1), as 0.2.0 did", async () => {
    // The reviewer's probe P1: 0.2.0 sent one message and threw nothing.
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa({ to: "6591234567" });
    try {
      await a.deliver(makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:6598765432"], quorum: 1 }));
      expect(calls).toHaveLength(1);
      expect(calls[0].body.to).toBe("6591234567");
    } finally {
      a.close();
    }
  });

  it("with `to` set, runs no approver checks: other spellings and other channels are delivered as before", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa({ to: "6591234567" });
    try {
      await a.deliver(makeIntent({ approvers: ["whatsapp:+6591234567"] }));
      await a.deliver(makeIntent({ approvers: ["slack:U1"] }));
      await a.deliver(makeIntent({ approvers: ["whatsapp:6599999999"] }));
      expect(calls.map((c) => c.body.to)).toEqual(["6591234567", "6591234567", "6591234567"]);
    } finally {
      a.close();
    }
  });

  it("WHATSAPP_TO from the environment works the same way", async () => {
    process.env.WHATSAPP_TO = "6591234567";
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa();
    try {
      await a.deliver(makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:6598765432"] }));
      expect(calls.map((c) => c.body.to)).toEqual(["6591234567"]);
    } finally {
      a.close();
    }
  });

  it("with no `to` and no mode, construction throws the 0.2.0 error", () => {
    expect(() => wa()).toThrow("missing required environment variable WHATSAPP_TO");
  });

  it("the resolved config carries only the 0.2.0 keys when nothing new is set", () => {
    const cfg = whatsappConfigFromEnv({
      accessToken: "meta-token",
      phoneNumberId: "555",
      to: "6591234567",
      verifyToken: "v",
      appSecret: WA_SECRET,
      authorityKey: authority.secretKey,
    });
    expect(Object.keys(cfg)).toEqual([
      "accessToken",
      "phoneNumberId",
      "to",
      "templateName",
      "templateLang",
      "verifyToken",
      "appSecret",
      "authorityKey",
      "graphBase",
    ]);
  });
});

describe("whatsapp: per-approver delivery, opt-in with recipientMode 'approvers' (B1, F3)", () => {
  it("delivers to each whatsapp approver named in the Intent", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = waApprovers();
    try {
      await a.deliver(makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:447700900123"] }));
      expect(calls.map((c) => c.body.to)).toEqual(["6591234567", "447700900123"]);
    } finally {
      a.close();
    }
  });

  it("WHATSAPP_RECIPIENT_MODE=approvers turns it on from the environment", async () => {
    process.env.WHATSAPP_RECIPIENT_MODE = "approvers";
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa();
    try {
      await a.deliver(makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:447700900123"] }));
      expect(calls.map((c) => c.body.to)).toEqual(["6591234567", "447700900123"]);
    } finally {
      a.close();
    }
  });

  it("an unknown recipient mode is a construction error", () => {
    expect(() => wa({ recipientMode: "everyone" })).toThrow(/recipientMode/);
    process.env.WHATSAPP_RECIPIENT_MODE = "all";
    expect(() => wa()).toThrow(/WHATSAPP_RECIPIENT_MODE/);
  });

  it("refuses an Intent that names no whatsapp approver, sending nothing", async () => {
    const calls = interceptFetch();
    const a = waApprovers();
    try {
      await expect(a.deliver(makeIntent({ approvers: ["slack:U1"] }))).rejects.toThrow(/no whatsapp approver/i);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("refuses an approver written with '+' (the webhook reports bare digits, so the press could never count)", async () => {
    const calls = interceptFetch();
    const a = waApprovers();
    try {
      await expect(a.deliver(makeIntent({ approvers: ["whatsapp:+6591234567"] }))).rejects.toThrow(/E\.164 digits/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });
});

describe("whatsapp: a send that fails part-way (F8)", () => {
  it("throws DeliveryPartialError naming who already holds live buttons and who was not reached", async () => {
    let n = 0;
    const calls = interceptFetch(() =>
      ++n === 2
        ? new Response(JSON.stringify({ error: { message: "boom" } }), { status: 500 })
        : { messages: [{ id: `wamid.${n}` }] },
    );
    const a = waApprovers();
    try {
      const intent = makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:447700900123", "whatsapp:61400000000"] });
      const err = await a.deliver(intent).then(
        () => null,
        (e) => e,
      );
      expect(err).toBeInstanceOf(DeliveryPartialError);
      expect(err).toBeInstanceOf(CountersignError);
      expect(err.intentId).toBe(intent.intent_id);
      expect(err.reached).toEqual(["whatsapp:6591234567"]);
      expect(err.unreached).toEqual(["whatsapp:447700900123", "whatsapp:61400000000"]);
      expect(String(err.cause?.message)).toMatch(/whatsapp template send failed/);
      expect(err.message).toMatch(/whatsapp:6591234567/);
      expect(calls).toHaveLength(2); // stops at the failure
    } finally {
      a.close();
    }
  });

  it("when the first send fails nobody was reached: the plain send error, as before", async () => {
    interceptFetch(() => new Response("nope", { status: 500 }));
    const a = waApprovers();
    try {
      const err = await a.deliver(makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:447700900123"] })).then(
        () => null,
        (e) => e,
      );
      expect(err).toBeInstanceOf(CountersignError);
      expect(err).not.toBeInstanceOf(DeliveryPartialError);
      expect(err.message).toBe("whatsapp template send failed: nope");
    } finally {
      a.close();
    }
  });
});

describe("whatsapp: single-recipient mode, opt-in with recipientMode 'single' (B1, F3)", () => {
  it("refuses an Intent whose approver is someone else", async () => {
    const calls = interceptFetch();
    const a = wa({ to: "6591234567", recipientMode: "single" });
    try {
      await expect(a.deliver(makeIntent({ approvers: ["whatsapp:6599999999"] }))).rejects.toThrow(/configured recipient/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("refuses when another whatsapp approver would never be asked (the reviewer's example, now opted into)", async () => {
    const calls = interceptFetch();
    const a = wa({ to: "6591234567", recipientMode: "single" });
    try {
      await expect(
        a.deliver(makeIntent({ approvers: ["whatsapp:6591234567", "whatsapp:6598765432"], quorum: 1 })),
      ).rejects.toThrow(/whatsapp:6598765432/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("still delivers to the configured recipient when it is the approver", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa({ to: "6591234567", recipientMode: "single" });
    try {
      await a.deliver(makeIntent({ approvers: ["whatsapp:6591234567"] }));
      expect(calls).toHaveLength(1);
      expect(calls[0].body.to).toBe("6591234567");
    } finally {
      a.close();
    }
  });

  it("without a recipient is a construction error", () => {
    expect(() => wa({ recipientMode: "single" })).toThrow(/WHATSAPP_TO/);
  });
});

describe("whatsapp: who is believed (B1)", () => {
  it("by default, a press is believed whatever phone_number_id it carries, as in 0.2.0", async () => {
    interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa({ to: "6591234567" });
    const { server, base } = await listen(a.webhookHandler());
    try {
      const intent = makeIntent({ approvers: ["whatsapp:6591234567"] });
      const state = watch(a.awaitResolution(intent));
      await pressWhatsApp(base, intent, "6591234567", { phone_number_id: "999" });
      await settleTick();
      expect(state.done).toBe(true);
    } finally {
      server.close();
      a.close();
    }
  });

  it("with requirePhoneNumberId, ignores a press for another phone_number_id and accepts the configured one", async () => {
    interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = waApprovers({ requirePhoneNumberId: true });
    const { server, base } = await listen(a.webhookHandler());
    try {
      const intent = makeIntent({ approvers: ["whatsapp:6591234567"] });
      const state = watch(a.awaitResolution(intent));
      const wrong = await pressWhatsApp(base, intent, "6591234567", { phone_number_id: "999" });
      expect(wrong.status).toBe(200); // acknowledged so Meta does not retry, but not believed
      await settleTick();
      expect(state.done).toBe(false);
      await pressWhatsApp(base, intent, "6591234567", { phone_number_id: "555" });
      await settleTick();
      expect(state.done).toBe(true);
      expect((state.value as any).countersignatures[0].actor).toBe("whatsapp:6591234567");
    } finally {
      server.close();
      a.close();
    }
  });

  it("with requirePhoneNumberId (or WHATSAPP_REQUIRE_PHONE_NUMBER_ID=1), a press without metadata is not believed", async () => {
    interceptFetch();
    process.env.WHATSAPP_REQUIRE_PHONE_NUMBER_ID = "1";
    for (const a of [waApprovers({ requirePhoneNumberId: true }), waApprovers()]) {
      const { server, base } = await listen(a.webhookHandler());
      try {
        const intent = makeIntent({ approvers: ["whatsapp:6591234567"] });
        const state = watch(a.awaitResolution(intent));
        await pressWhatsApp(base, intent, "6591234567");
        await settleTick();
        expect(state.done).toBe(false);
      } finally {
        server.close();
        a.close();
      }
    }
  });

  it("docs, example and .env.example agree the app secret is required", () => {
    const example = readFileSync(join(root, "examples", "whatsapp.ts"), "utf8");
    const readme = readFileSync(join(root, "adapters", "README.md"), "utf8");
    const env = readFileSync(join(root, ".env.example"), "utf8");
    expect(example).toMatch(/requireEnvOrExplain\(\s*\[[^\]]*"WHATSAPP_APP_SECRET"/);
    expect(readme).not.toMatch(/Optionally set `WHATSAPP_APP_SECRET`/);
    expect(env).not.toMatch(/Optional: app secret/);
  });
});

describe("whatsapp: never approving cut-off or rejected text (B4)", () => {
  it("refuses, before sending, a summary with a newline or tab (Meta rejects those, so 0.2.0 failed too)", async () => {
    const calls = interceptFetch();
    const a = wa({ to: "6591234567" });
    try {
      for (const summary of ["line one\nline two", "a\tb", "a\r\nb"]) {
        await expect(a.deliver(makeIntent({ summary, approvers: ["whatsapp:6591234567"] }))).rejects.toThrow(
          /template variable/,
        );
      }
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("by default, sends a run of four spaces and a long body as 0.2.0 did", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa({ to: "6591234567" });
    try {
      await a.deliver(makeIntent({ summary: "a    b", approvers: ["whatsapp:6591234567"] }));
      await a.deliver(makeIntent({ summary: "y".repeat(1100), approvers: ["whatsapp:6591234567"] }));
      expect(calls).toHaveLength(2);
    } finally {
      a.close();
    }
  });

  it("with enforceLimits, refuses a run of four spaces", async () => {
    const calls = interceptFetch();
    const a = wa({ to: "6591234567", enforceLimits: true });
    try {
      await expect(a.deliver(makeIntent({ summary: "a    b", approvers: ["whatsapp:6591234567"] }))).rejects.toThrow(
        /template variable/,
      );
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("with enforceLimits, refuses a rendered body over 1024 characters; accepts exactly 1024", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = waApprovers({ enforceLimits: true });
    try {
      const probe = makeIntent({ summary: "x", approvers: ["whatsapp:6591234567"] });
      const overhead = renderWhatsAppTemplateBody(DEFAULT_WHATSAPP_TEMPLATE_BODY, whatsappTemplateParameters(probe)).length - 1;
      const fits = "y".repeat(WHATSAPP_MAX_TEMPLATE_BODY_LENGTH - overhead);
      await a.deliver(makeIntent({ summary: fits, approvers: ["whatsapp:6591234567"] }));
      expect(calls).toHaveLength(1);
      await expect(
        a.deliver(makeIntent({ summary: `${fits}z`, approvers: ["whatsapp:6591234567"] })),
      ).rejects.toThrow(/1025 .*1024/);
      expect(calls).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("the limit and the template body are overridable", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = waApprovers({ enforceLimits: true, maxTemplateBodyLength: 20, templateBody: "{{1}}|{{2}}|{{3}}" });
    try {
      await expect(a.deliver(makeIntent({ approvers: ["whatsapp:6591234567"] }))).rejects.toThrow(/limit is 20/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("a template body that drops the summary placeholder is refused at construction", () => {
    expect(() => waApprovers({ templateBody: "Please approve {{2}} ({{3}})" })).toThrow(/\{\{1\}\}/);
  });
});

describe("whatsapp: saying the decision was recorded (B5)", () => {
  it("with confirmDecisions, replies to the presser naming who decided and when, quoting the request", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = waApprovers({ confirmDecisions: true });
    const { server, base } = await listen(a.webhookHandler());
    try {
      const intent = makeIntent({ approvers: ["whatsapp:6591234567"] });
      const pending = a.awaitResolution(intent);
      await pressWhatsApp(base, intent, "6591234567", { phone_number_id: "555" });
      const r = await pending;
      await settleTick();
      const reply = calls.find((c) => c.body?.type === "text");
      expect(reply).toBeTruthy();
      expect(reply!.body.to).toBe("6591234567");
      expect(reply!.body.context).toEqual({ message_id: "wamid.original" });
      const text: string = reply!.body.text.body;
      expect(text).toMatch(/^Decision recorded: APPROVE by whatsapp:6591234567 at /);
      expect(text).toContain(r.countersignatures[0].timestamp);
      expect(text).not.toMatch(/posted|done|completed/i);
    } finally {
      server.close();
      a.close();
    }
  });

  it("without confirmDecisions, sends nothing back (existing behaviour)", async () => {
    const calls = interceptFetch(() => ({ messages: [{ id: "wamid.1" }] }));
    const a = wa({ to: "6591234567" });
    const { server, base } = await listen(a.webhookHandler());
    try {
      const intent = makeIntent({ approvers: ["whatsapp:6591234567"] });
      const pending = a.awaitResolution(intent);
      await pressWhatsApp(base, intent, "6591234567");
      await pending;
      await settleTick();
      expect(calls).toHaveLength(0);
    } finally {
      server.close();
      a.close();
    }
  });
});

// ─── Slack ───────────────────────────────────────────────────────────────────

const SLACK_SECRET = "slack-signing-secret";

function slack(extra: Record<string, unknown> = {}) {
  return new SlackAdapter({
    botToken: "xoxb-test",
    channelId: "C123",
    signingSecret: SLACK_SECRET,
    authorityKey: authority.secretKey,
    ...extra,
  });
}

async function pressSlack(base: string, intent: Intent, user: string, extra: Record<string, unknown> = {}) {
  const payload = JSON.stringify({
    type: "block_actions",
    user: { id: user },
    response_url: "https://hooks.slack.test/respond",
    actions: [{ action_id: "countersign_approve", value: `cs:${intent.intent_id}:approve` }],
    ...extra,
  });
  const body = `payload=${encodeURIComponent(payload)}`;
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = `v0=${createHmac("sha256", SLACK_SECRET).update(`v0:${ts}:${body}`).digest("hex")}`;
  return fetch(base, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": ts, "x-slack-signature": sig },
    body,
  });
}

describe("slack: who is believed (B2)", () => {
  it("with appId configured, refuses a payload from another app and accepts its own", async () => {
    interceptFetch(() => ({ ok: true }));
    const a = slack({ appId: "A111" });
    const { server, base } = await listen(a.interactivityHandler());
    try {
      const intent = makeIntent({ approvers: ["slack:U42"] });
      const state = watch(a.awaitResolution(intent));
      const other = await pressSlack(base, intent, "U42", { api_app_id: "A999" });
      expect(other.status).toBe(403);
      const missing = await pressSlack(base, intent, "U42");
      expect(missing.status).toBe(403);
      await settleTick();
      expect(state.done).toBe(false);
      const own = await pressSlack(base, intent, "U42", { api_app_id: "A111" });
      expect(own.status).toBe(200);
      await settleTick();
      expect(state.done).toBe(true);
    } finally {
      server.close();
      a.close();
    }
  });

  it("with teamId configured, refuses a payload from another workspace", async () => {
    interceptFetch(() => ({ ok: true }));
    const a = slack({ appId: "A111", teamId: "T111" });
    const { server, base } = await listen(a.interactivityHandler());
    try {
      const intent = makeIntent({ approvers: ["slack:U42"] });
      const state = watch(a.awaitResolution(intent));
      const other = await pressSlack(base, intent, "U42", { api_app_id: "A111", team: { id: "T999" } });
      expect(other.status).toBe(403);
      await settleTick();
      expect(state.done).toBe(false);
      const own = await pressSlack(base, intent, "U42", { api_app_id: "A111", team: { id: "T111" } });
      expect(own.status).toBe(200);
      await settleTick();
      expect(state.done).toBe(true);
    } finally {
      server.close();
      a.close();
    }
  });
});

describe("slack: never approving cut-off text (B4)", () => {
  it("refuses, before posting, a section text over 3000 characters (Slack rejects it, so 0.2.0 failed too); accepts exactly 3000", async () => {
    const calls = interceptFetch(() => ({ ok: true }));
    const a = slack();
    try {
      const overhead = formatIntent(makeIntent({ summary: "x" })).length - 1;
      const fits = "y".repeat(SLACK_MAX_SECTION_TEXT_LENGTH - overhead);
      await a.deliver(makeIntent({ summary: fits }));
      expect(calls).toHaveLength(1);
      await expect(a.deliver(makeIntent({ summary: `${fits}z` }))).rejects.toThrow(/3001 .*3000/);
      expect(calls).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("by default counts characters (code points), so text 0.2.0 may have delivered still goes out", async () => {
    // 3000 code points but more than 3000 UTF-16 code units: whether Slack takes
    // it depends on how Slack counts, so the default does not refuse it.
    const calls = interceptFetch(() => ({ ok: true }));
    const a = slack();
    try {
      const overhead = [...formatIntent(makeIntent({ summary: "x" }))].length - 1;
      const summary = "😀".repeat(SLACK_MAX_SECTION_TEXT_LENGTH - overhead);
      expect(formatIntent(makeIntent({ summary })).length).toBeGreaterThan(SLACK_MAX_SECTION_TEXT_LENGTH);
      await a.deliver(makeIntent({ summary }));
      expect(calls).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("with enforceLimits, counts UTF-16 code units and refuses that text", async () => {
    const calls = interceptFetch(() => ({ ok: true }));
    const a = slack({ enforceLimits: true });
    try {
      const overhead = [...formatIntent(makeIntent({ summary: "x" }))].length - 1;
      const summary = "😀".repeat(SLACK_MAX_SECTION_TEXT_LENGTH - overhead);
      await expect(a.deliver(makeIntent({ summary }))).rejects.toThrow(/limit is 3000/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("the limit is overridable", async () => {
    const calls = interceptFetch(() => ({ ok: true }));
    const a = slack({ maxSectionTextLength: 50 });
    try {
      await expect(a.deliver(makeIntent())).rejects.toThrow(/limit is 50/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("the resolved config carries only the 0.2.0 keys when nothing new is set", () => {
    const saved = { app: process.env.SLACK_APP_ID, team: process.env.SLACK_TEAM_ID };
    delete process.env.SLACK_APP_ID;
    delete process.env.SLACK_TEAM_ID;
    try {
      const cfg = slackConfigFromEnv({ botToken: "x", channelId: "C", signingSecret: "s", authorityKey: authority.secretKey });
      expect(Object.keys(cfg)).toEqual(["botToken", "channelId", "signingSecret", "authorityKey", "apiBase"]);
    } finally {
      if (saved.app !== undefined) process.env.SLACK_APP_ID = saved.app;
      if (saved.team !== undefined) process.env.SLACK_TEAM_ID = saved.team;
    }
  });
});

describe("slack: saying the decision was recorded (B5)", () => {
  it("replaces the message with the request still visible, plus who decided and when", async () => {
    const calls = interceptFetch(() => ({ ok: true }));
    const a = slack();
    const { server, base } = await listen(a.interactivityHandler());
    try {
      const intent = makeIntent({ summary: "Refund $42 to #1337", approvers: ["slack:U42"] });
      const pending = a.awaitResolution(intent);
      await pressSlack(base, intent, "U42");
      const r = await pending;
      await settleTick();
      const update = calls.find((c) => c.url === "https://hooks.slack.test/respond")!.body;
      expect(update.replace_original).toBe(true);
      expect(update.text).toMatch(/^Decision recorded: APPROVE by <@U42> at /);
      expect(update.text).toContain(r.countersignatures[0].timestamp);
      expect(update.text).not.toMatch(/posted|done|completed/i);
      const section = update.blocks.find((b: any) => b.type === "section");
      expect(section.text).toEqual({ type: "plain_text", emoji: false, text: formatIntent(intent) });
      expect(update.blocks.some((b: any) => b.type === "actions")).toBe(false); // buttons removed
    } finally {
      server.close();
      a.close();
    }
  });

  it("a request too long to repeat in a section is replaced by the decision line alone", async () => {
    const calls = interceptFetch(() => ({ ok: true }));
    const a = slack();
    const { server, base } = await listen(a.interactivityHandler());
    try {
      const intent = makeIntent({ summary: "😀".repeat(2000), approvers: ["slack:U42"] });
      const pending = a.awaitResolution(intent);
      await pressSlack(base, intent, "U42");
      await pending;
      await settleTick();
      const update = calls.find((c) => c.url === "https://hooks.slack.test/respond")!.body;
      expect(update.blocks.some((b: any) => b.type === "section")).toBe(false);
      expect(update.blocks[0].elements[0].text).toMatch(/^Decision recorded: \*APPROVE\* by <@U42> at /);
    } finally {
      server.close();
      a.close();
    }
  });
});

// ─── Telegram ────────────────────────────────────────────────────────────────

function tg(extra: Record<string, unknown> = {}) {
  return new TelegramAdapter({ botToken: "t", chatId: "1", authorityKey: authority.secretKey, ...extra });
}

describe("telegram: one poller per bot (B3)", () => {
  it("a 409 from getUpdates fails the waiting request with one clear error instead of retrying silently", async () => {
    const calls = interceptFetch(
      () =>
        new Response(
          JSON.stringify({
            ok: false,
            error_code: 409,
            description: "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running",
          }),
          { status: 409 },
        ),
    );
    const a = tg({ mode: "poll" });
    try {
      const intent = makeIntent({ approvers: ["telegram:42"] });
      const err = await a.awaitResolution(intent).then(
        () => null,
        (e) => e,
      );
      expect(err).toBeInstanceOf(TelegramPollingConflictError);
      expect(String(err.message)).toMatch(/another process is already polling this bot/);
      expect(calls.filter((c) => c.url.endsWith("/getUpdates"))).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("the example and guide name the approver by user id, not chat id", () => {
    const example = readFileSync(join(root, "examples", "telegram.ts"), "utf8");
    const readme = readFileSync(join(root, "adapters", "README.md"), "utf8");
    expect(example).toContain("TELEGRAM_APPROVER_ID");
    expect(readme).toMatch(/group/i);
    expect(readme).toContain("TELEGRAM_APPROVER_ID");
  });
});

describe("telegram: never approving cut-off text (B4)", () => {
  it("refuses, before sending, a message over 4096 characters (Telegram rejects it, so 0.2.0 failed too)", async () => {
    const calls = interceptFetch(() => ({ ok: true, result: { message_id: 1 } }));
    const a = tg({ mode: "webhook", webhookSecret: "s" });
    try {
      const overhead = formatIntent(makeIntent({ summary: "x" })).length - 1;
      const fits = "y".repeat(TELEGRAM_MAX_MESSAGE_LENGTH - overhead);
      await a.deliver(makeIntent({ summary: fits }));
      expect(calls).toHaveLength(1);
      await expect(a.deliver(makeIntent({ summary: `${fits}z` }))).rejects.toThrow(/4097 .*4096/);
      expect(calls).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("by default counts characters (code points), so text 0.2.0 may have delivered still goes out", async () => {
    const calls = interceptFetch(() => ({ ok: true, result: { message_id: 1 } }));
    const a = tg({ mode: "webhook", webhookSecret: "s" });
    try {
      const overhead = [...formatIntent(makeIntent({ summary: "x" }))].length - 1;
      const summary = "😀".repeat(TELEGRAM_MAX_MESSAGE_LENGTH - overhead);
      expect(formatIntent(makeIntent({ summary })).length).toBeGreaterThan(TELEGRAM_MAX_MESSAGE_LENGTH);
      await a.deliver(makeIntent({ summary }));
      expect(calls).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("with enforceLimits, counts UTF-16 code units: refuses 4097, accepts exactly 4096", async () => {
    const calls = interceptFetch(() => ({ ok: true, result: { message_id: 1 } }));
    const a = tg({ mode: "webhook", webhookSecret: "s", enforceLimits: true });
    try {
      const overhead = formatIntent(makeIntent({ summary: "x" })).length - 1;
      // Each emoji is 2 UTF-16 code units: the count must be in code units, not characters.
      const units = TELEGRAM_MAX_MESSAGE_LENGTH - overhead;
      const fits = "😀".repeat(Math.floor(units / 2)) + "y".repeat(units % 2);
      await a.deliver(makeIntent({ summary: fits }));
      expect(calls).toHaveLength(1);
      await expect(a.deliver(makeIntent({ summary: `${fits}z` }))).rejects.toThrow(/4097 .*4096/);
      expect(calls).toHaveLength(1);
    } finally {
      a.close();
    }
  });

  it("the limit is overridable", async () => {
    const calls = interceptFetch();
    const a = tg({ mode: "webhook", webhookSecret: "s", maxMessageLength: 40 });
    try {
      await expect(a.deliver(makeIntent())).rejects.toThrow(/limit is 40/);
      expect(calls).toHaveLength(0);
    } finally {
      a.close();
    }
  });

  it("the resolved config carries only the 0.2.0 keys when nothing new is set", () => {
    const cfg = telegramConfigFromEnv({ botToken: "t", chatId: "1", authorityKey: authority.secretKey });
    expect(Object.keys(cfg)).toEqual(["botToken", "chatId", "authorityKey", "mode", "webhookSecret", "apiBase"]);
  });
});

describe("telegram: saying the decision was recorded (B5)", () => {
  function press(intent: Intent, text: string) {
    return {
      update_id: 1,
      callback_query: {
        id: "cbq",
        from: { id: 42 },
        message: { message_id: 7, chat: { id: 1 }, text, reply_markup: { inline_keyboard: [] } },
        data: `cs:${intent.intent_id}:approve`,
      },
    };
  }

  it("edits the message to say the decision was recorded, by whom and when", async () => {
    const calls = interceptFetch(() => ({ ok: true, result: {} }));
    const a = tg({ mode: "webhook", webhookSecret: "s" });
    try {
      const intent = makeIntent({ approvers: ["telegram:42"] });
      const pending = a.awaitResolution(intent);
      await a.handleUpdate(press(intent, formatIntent(intent)));
      const r = await pending;
      const edit = calls.find((c) => c.url.endsWith("/editMessageText"))!.body;
      expect(edit.text.startsWith(formatIntent(intent))).toBe(true);
      expect(edit.text).toContain(`Decision recorded: APPROVE by telegram:42 at ${r.countersignatures[0].timestamp}`);
      expect(edit.text).not.toMatch(/posted|done|completed|Resolved/i);
      expect(edit.reply_markup).toBeUndefined(); // buttons removed
    } finally {
      a.close();
    }
  });

  it("when the edit would pass the limit, removes the buttons and replies with the note instead", async () => {
    const calls = interceptFetch(() => ({ ok: true, result: {} }));
    const a = tg({ mode: "webhook", webhookSecret: "s" });
    try {
      const intent = makeIntent({ approvers: ["telegram:42"] });
      const pending = a.awaitResolution(intent);
      await a.handleUpdate(press(intent, "x".repeat(TELEGRAM_MAX_MESSAGE_LENGTH - 5)));
      await pending;
      expect(calls.some((c) => c.url.endsWith("/editMessageText"))).toBe(false);
      const markup = calls.find((c) => c.url.endsWith("/editMessageReplyMarkup"))!.body;
      expect(markup).toMatchObject({ chat_id: 1, message_id: 7, reply_markup: { inline_keyboard: [] } });
      const reply = calls.find((c) => c.url.endsWith("/sendMessage"))!.body;
      expect(reply.reply_to_message_id).toBe(7);
      expect(reply.text).toMatch(/^Decision recorded: APPROVE by telegram:42 at /);
    } finally {
      a.close();
    }
  });
});

// ─── Discord ─────────────────────────────────────────────────────────────────

describe("discord: saying the decision was recorded (same wording as the other chat adapters)", () => {
  it("updates the message with who decided and when, and removes the buttons", async () => {
    interceptFetch(() => ({ id: "msg1" }));
    const appKey = generateKeypair();
    const a = new DiscordAdapter({
      botToken: "t",
      channelId: "c",
      publicKey: fromB64url(appKey.publicKey).toString("hex"),
      authorityKey: authority.secretKey,
    });
    const { server, base } = await listen(a.interactionHandler());
    try {
      const intent = makeIntent({ approvers: ["discord:u42"] });
      const pending = a.awaitResolution(intent);
      const body = JSON.stringify({
        type: 3,
        data: { custom_id: `cs:${intent.intent_id}:approve` },
        member: { user: { id: "u42" } },
        message: { content: "the request", components: [{ type: 1, components: [{ type: 2 }] }] },
      });
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = fromB64url(signBytes(appKey.secretKey, utf8(ts + body))).toString("hex");
      const res = await fetch(base, {
        method: "POST",
        headers: { "content-type": "application/json", "x-signature-ed25519": sig, "x-signature-timestamp": ts },
        body,
      });
      const out = await res.json();
      const r = await pending;
      expect(out.data.content).toBe(
        `the request\n\nDecision recorded: APPROVE by <@u42> at ${r.countersignatures[0].timestamp}`,
      );
      expect(out.data.components).toEqual([]);
    } finally {
      server.close();
      a.close();
    }
  });
});
