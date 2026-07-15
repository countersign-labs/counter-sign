// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  authorityKeyFromEnv,
  decisionPayload,
  formatIntent,
  parseDecisionPayload,
  readBody,
  requireEnv,
  PendingDecisions,
  type Adapter,
  type SettleResult,
} from "../adapter.js";
import { CountersignError } from "../core/errors.js";

/** Constant-time compare of the webhook secret token (length is not secret). */
function secretEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
import type { Intent, Resolution } from "../core/types.js";

export interface TelegramConfig {
  botToken: string;
  chatId: string;
  authorityKey: string;
  /** "poll" long-polls getUpdates (no public URL needed); "webhook" expects updates via webhookHandler(). */
  mode: "poll" | "webhook";
  /** Optional shared secret checked against X-Telegram-Bot-Api-Secret-Token. */
  webhookSecret?: string;
  apiBase: string;
}

export function telegramConfigFromEnv(overrides: Partial<TelegramConfig> = {}): TelegramConfig {
  return {
    botToken: overrides.botToken ?? requireEnv("TELEGRAM_BOT_TOKEN"),
    chatId: overrides.chatId ?? requireEnv("TELEGRAM_CHAT_ID"),
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    mode: overrides.mode ?? (process.env.TELEGRAM_MODE as "poll" | "webhook") ?? "poll",
    webhookSecret: overrides.webhookSecret ?? process.env.TELEGRAM_WEBHOOK_SECRET,
    apiBase: overrides.apiBase ?? process.env.TELEGRAM_API_BASE ?? "https://api.telegram.org",
  };
}

/**
 * Telegram Bot API adapter. Delivers the Intent as a message with inline
 * Approve/Reject buttons; the decision arrives as a callback_query, either
 * long-polled (default) or via webhook.
 */
export class TelegramAdapter implements Adapter {
  readonly channel = "telegram";
  private readonly pending = new PendingDecisions();
  private readonly cfg: TelegramConfig;
  private offset = 0;
  private polling = false;
  private closed = false;

  constructor(config: Partial<TelegramConfig> = {}) {
    this.cfg = telegramConfigFromEnv(config);
  }

  async deliver(intent: Intent): Promise<void> {
    await this.api("sendMessage", {
      chat_id: this.cfg.chatId,
      text: formatIntent(intent),
      reply_markup: {
        inline_keyboard: [
          [
            { text: "✅ Approve", callback_data: decisionPayload(intent, "approve") },
            { text: "❌ Reject", callback_data: decisionPayload(intent, "reject") },
          ],
        ],
      },
    });
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    const resolution = this.pending.wait(intent);
    if (this.cfg.mode === "poll") void this.pollLoop();
    return resolution;
  }

  /**
   * Process one Telegram update. Shared by the polling loop and the webhook
   * handler, so the resulting receipts are identical regardless of transport.
   * Under quorum, an approval that does not yet complete the quorum is
   * acknowledged and the buttons are kept so other approvers can still decide.
   */
  async handleUpdate(update: any): Promise<SettleResult | null> {
    const cb = update?.callback_query;
    if (!cb?.data) return null;
    const parsed = parseDecisionPayload(cb.data);
    if (!parsed || !this.pending.has(parsed.intentId)) {
      await this.api("answerCallbackQuery", { callback_query_id: cb.id, text: "Request no longer pending." }).catch(() => {});
      return null;
    }
    // Key on the STABLE numeric id, never the mutable @username — a user could
    // change their username between approvals to be counted as two distinct approvers.
    const actor = `telegram:${cb.from?.id ?? "unknown"}`;
    const result = this.pending.settle(parsed.intentId, parsed.decision, actor, this.cfg.authorityKey);
    if (!result) return null;
    const ack =
      result.status === "resolved"
        ? `Recorded: ${result.decision}`
        : `Recorded (${result.collected}/${result.quorum}); awaiting more approvers`;
    await this.api("answerCallbackQuery", { callback_query_id: cb.id, text: ack }).catch(() => {});
    if (cb.message) {
      const note =
        result.status === "resolved"
          ? `Resolved: ${result.decision!.toUpperCase()} (last: ${actor})`
          : `Approval ${result.collected}/${result.quorum} by ${actor} — awaiting more`;
      await this.api("editMessageText", {
        chat_id: cb.message.chat.id,
        message_id: cb.message.message_id,
        text: `${cb.message.text}\n\n${note}`,
        // Keep the buttons while pending so other approvers can still act.
        ...(result.status === "resolved" ? {} : { reply_markup: cb.message.reply_markup }),
      }).catch(() => {});
    }
    return result;
  }

  /** Node HTTP handler for TELEGRAM_MODE=webhook (set via setWebhook). */
  webhookHandler(): (req: IncomingMessage, res: ServerResponse) => void {
    const secret = this.cfg.webhookSecret;
    if (!secret)
      throw new CountersignError(
        "Telegram webhook requires a secret token: set TELEGRAM_WEBHOOK_SECRET (and pass it to setWebhook). " +
          "Refusing to expose an unauthenticated webhook — anyone who learns an intent_id could otherwise forge a decision.",
      );
    return (req, res) => {
      void (async () => {
        if (req.method !== "POST") {
          res.writeHead(405).end();
          return;
        }
        const provided = req.headers["x-telegram-bot-api-secret-token"];
        if (typeof provided !== "string" || !secretEquals(provided, secret)) {
          res.writeHead(401).end();
          return;
        }
        const body = await readBody(req);
        try {
          await this.handleUpdate(JSON.parse(body.toString("utf8")));
        } catch {
          // Malformed update; acknowledge anyway so Telegram does not retry forever.
        }
        res.writeHead(200, { "content-type": "text/plain" }).end("ok");
      })().catch(() => {
        // e.g. an oversized body (readBody throws past the cap): respond and never
        // leave the request hanging or surface an unhandled rejection.
        if (!res.headersSent) res.writeHead(500).end();
      });
    };
  }

  close(): void {
    this.closed = true;
    this.pending.abortAll(new CountersignError("telegram adapter closed"));
  }

  private async pollLoop(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      while (!this.closed && this.pending.size > 0) {
        try {
          const updates: any[] = await this.api("getUpdates", {
            offset: this.offset,
            timeout: 25,
            allowed_updates: ["callback_query"],
          });
          for (const update of updates) {
            this.offset = update.update_id + 1;
            await this.handleUpdate(update);
          }
        } catch {
          await new Promise((r) => setTimeout(r, 2000));
        }
      }
    } finally {
      this.polling = false;
    }
  }

  private async api(method: string, body: unknown): Promise<any> {
    const res = await fetch(`${this.cfg.apiBase}/bot${this.cfg.botToken}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const data: any = await res.json().catch(() => ({}));
    if (!res.ok || data.ok !== true) {
      throw new CountersignError(`telegram ${method} failed: ${data.description ?? res.status}`);
    }
    return data.result;
  }
}
