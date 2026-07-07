// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  authorityKeyFromEnv,
  decisionPayload,
  parseDecisionPayload,
  readBody,
  requireEnv,
  warnOnce,
  PendingDecisions,
  type Adapter,
} from "../adapter.js";
import { CountersignError } from "../core/errors.js";
import type { Countersignature, Intent } from "../core/types.js";

export interface WhatsAppConfig {
  accessToken: string;
  phoneNumberId: string;
  /** Approver's number, E.164 digits without "+". */
  to: string;
  /** Pre-approved template with a 3-variable body and two quick-reply buttons. */
  templateName: string;
  templateLang: string;
  /** Token echoed back during Meta's webhook GET verification. */
  verifyToken: string;
  /** Optional app secret; verifies X-Hub-Signature-256 on webhook POSTs. */
  appSecret?: string;
  authorityKey: string;
  graphBase: string;
}

export function whatsappConfigFromEnv(overrides: Partial<WhatsAppConfig> = {}): WhatsAppConfig {
  return {
    accessToken: overrides.accessToken ?? requireEnv("WHATSAPP_ACCESS_TOKEN"),
    phoneNumberId: overrides.phoneNumberId ?? requireEnv("WHATSAPP_PHONE_NUMBER_ID"),
    to: overrides.to ?? requireEnv("WHATSAPP_TO"),
    templateName: overrides.templateName ?? process.env.WHATSAPP_TEMPLATE_NAME ?? "countersign_approval",
    templateLang: overrides.templateLang ?? process.env.WHATSAPP_TEMPLATE_LANG ?? "en",
    verifyToken: overrides.verifyToken ?? requireEnv("WHATSAPP_VERIFY_TOKEN"),
    appSecret: overrides.appSecret ?? process.env.WHATSAPP_APP_SECRET,
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    graphBase: overrides.graphBase ?? process.env.WHATSAPP_GRAPH_BASE ?? "https://graph.facebook.com/v20.0",
  };
}

/**
 * WhatsApp adapter, built EXCLUSIVELY on the Meta WhatsApp Business Cloud
 * API (never unofficial web-client libraries). The Intent goes out as a
 * pre-approved template message carrying two quick-reply buttons; the
 * decision arrives as a "button" message on the app's webhook. See
 * adapters/README.md for the Meta app and free test-number setup.
 */
export class WhatsAppAdapter implements Adapter {
  readonly channel = "whatsapp";
  private readonly pending = new PendingDecisions();
  private readonly cfg: WhatsAppConfig;

  constructor(config: Partial<WhatsAppConfig> = {}) {
    this.cfg = whatsappConfigFromEnv(config);
  }

  async deliver(intent: Intent): Promise<void> {
    const res = await fetch(`${this.cfg.graphBase}/${this.cfg.phoneNumberId}/messages`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.cfg.accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to: this.cfg.to,
        type: "template",
        template: {
          name: this.cfg.templateName,
          language: { code: this.cfg.templateLang },
          components: [
            {
              type: "body",
              parameters: [
                { type: "text", text: intent.summary },
                { type: "text", text: intent.action },
                { type: "text", text: `${intent.risk_tier} risk, default ${intent.default} in ${intent.timeout}s` },
              ],
            },
            {
              type: "button",
              sub_type: "quick_reply",
              index: "0",
              parameters: [{ type: "payload", payload: decisionPayload(intent, "approve") }],
            },
            {
              type: "button",
              sub_type: "quick_reply",
              index: "1",
              parameters: [{ type: "payload", payload: decisionPayload(intent, "reject") }],
            },
          ],
        },
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => String(res.status));
      throw new CountersignError(`whatsapp template send failed: ${detail}`);
    }
  }

  awaitDecision(intent: Intent): Promise<Countersignature> {
    return this.pending.wait(intent);
  }

  /**
   * Node HTTP handler for the Meta webhook: answers the GET verification
   * challenge, checks X-Hub-Signature-256 when an app secret is configured,
   * and settles pending intents on quick-reply button messages.
   */
  webhookHandler(): (req: IncomingMessage, res: ServerResponse) => void {
    if (!this.cfg.appSecret) {
      warnOnce(
        "whatsapp:no-app-secret",
        "WhatsApp webhook is running WITHOUT payload signature verification. Set WHATSAPP_APP_SECRET " +
          "so X-Hub-Signature-256 is checked; otherwise anyone who learns an intent_id can forge a decision.",
      );
    }
    return (req, res) => {
      void (async () => {
        const url = new URL(req.url ?? "/", "http://localhost");
        if (req.method === "GET") {
          const ok =
            url.searchParams.get("hub.mode") === "subscribe" &&
            url.searchParams.get("hub.verify_token") === this.cfg.verifyToken;
          if (ok) res.writeHead(200, { "content-type": "text/plain" }).end(url.searchParams.get("hub.challenge") ?? "");
          else res.writeHead(403).end();
          return;
        }
        if (req.method !== "POST") {
          res.writeHead(405).end();
          return;
        }
        const body = await readBody(req);
        if (this.cfg.appSecret && !this.verifyHubSignature(body, req.headers["x-hub-signature-256"] as string | undefined)) {
          res.writeHead(401).end("invalid hub signature");
          return;
        }
        try {
          const event = JSON.parse(body.toString("utf8"));
          for (const entry of event.entry ?? []) {
            for (const change of entry.changes ?? []) {
              for (const message of change.value?.messages ?? []) {
                if (message.type !== "button") continue;
                const parsed = parseDecisionPayload(message.button?.payload ?? "");
                if (parsed && this.pending.has(parsed.intentId)) {
                  this.pending.settle(parsed.intentId, parsed.decision, `whatsapp:${message.from}`, this.cfg.authorityKey);
                }
              }
            }
          }
        } catch {
          // Malformed event; acknowledge so Meta does not retry forever.
        }
        res.writeHead(200).end();
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
    };
  }

  verifyHubSignature(rawBody: Buffer, header: string | undefined): boolean {
    if (!this.cfg.appSecret || !header?.startsWith("sha256=")) return false;
    const expected = createHmac("sha256", this.cfg.appSecret).update(rawBody).digest("hex");
    const a = Buffer.from(`sha256=${expected}`);
    const b = Buffer.from(header);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  close(): void {
    this.pending.abortAll(new CountersignError("whatsapp adapter closed"));
  }
}
