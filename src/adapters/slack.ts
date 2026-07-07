// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createHmac, timingSafeEqual } from "node:crypto";
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
} from "../adapter.js";
import { CountersignError } from "../core/errors.js";
import type { Intent, Resolution } from "../core/types.js";

export interface SlackConfig {
  botToken: string;
  channelId: string;
  /** App Signing Secret; every interactivity request is verified against it. */
  signingSecret: string;
  authorityKey: string;
  apiBase: string;
}

export function slackConfigFromEnv(overrides: Partial<SlackConfig> = {}): SlackConfig {
  return {
    botToken: overrides.botToken ?? requireEnv("SLACK_BOT_TOKEN"),
    channelId: overrides.channelId ?? requireEnv("SLACK_CHANNEL_ID"),
    signingSecret: overrides.signingSecret ?? requireEnv("SLACK_SIGNING_SECRET"),
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    apiBase: overrides.apiBase ?? process.env.SLACK_API_BASE ?? "https://slack.com/api",
  };
}

const SIGNATURE_TOLERANCE_SECONDS = 300;

/** Neutralize Slack control sequences (mentions, links) in fallback text. */
function slackEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Slack adapter. Delivers the Intent as a Block Kit message with
 * Approve/Reject buttons; the decision arrives on the app's Interactivity
 * Request URL. Request signatures (v0 HMAC-SHA256 over the timestamped
 * body) are verified before any payload is trusted.
 */
export class SlackAdapter implements Adapter {
  readonly channel = "slack";
  private readonly pending = new PendingDecisions();
  private readonly cfg: SlackConfig;

  constructor(config: Partial<SlackConfig> = {}) {
    this.cfg = slackConfigFromEnv(config);
  }

  async deliver(intent: Intent): Promise<void> {
    await this.api("chat.postMessage", {
      channel: this.cfg.channelId,
      // plain_text never parses mrkdwn or broadcast mentions (<!channel> etc),
      // and the fallback `text` is escaped, so an attacker-influenced summary
      // cannot break out of the block or ping the channel.
      text: slackEscape(formatIntent(intent)),
      blocks: [
        { type: "section", text: { type: "plain_text", emoji: false, text: formatIntent(intent) } },
        {
          type: "actions",
          block_id: `countersign:${intent.intent_id}`,
          elements: [
            {
              type: "button",
              style: "primary",
              text: { type: "plain_text", text: "Approve" },
              action_id: "countersign_approve",
              value: decisionPayload(intent, "approve"),
            },
            {
              type: "button",
              style: "danger",
              text: { type: "plain_text", text: "Reject" },
              action_id: "countersign_reject",
              value: decisionPayload(intent, "reject"),
            },
          ],
        },
      ],
    });
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    return this.pending.wait(intent);
  }

  /** Verify Slack's v0 request signature over a raw request body. */
  verifySignature(rawBody: Buffer, timestamp: string | undefined, signature: string | undefined, now = Date.now()): boolean {
    if (!timestamp || !signature) return false;
    const ts = Number(timestamp);
    if (!Number.isFinite(ts) || Math.abs(now / 1000 - ts) > SIGNATURE_TOLERANCE_SECONDS) return false;
    const expected = `v0=${createHmac("sha256", this.cfg.signingSecret)
      .update(`v0:${timestamp}:${rawBody.toString("utf8")}`)
      .digest("hex")}`;
    const a = Buffer.from(expected);
    const b = Buffer.from(signature);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  /** Node HTTP handler for the app's Interactivity Request URL. */
  interactivityHandler(): (req: IncomingMessage, res: ServerResponse) => void {
    return (req, res) => {
      void (async () => {
        if (req.method !== "POST") {
          res.writeHead(405).end();
          return;
        }
        const body = await readBody(req);
        const ok = this.verifySignature(
          body,
          req.headers["x-slack-request-timestamp"] as string | undefined,
          req.headers["x-slack-signature"] as string | undefined,
        );
        if (!ok) {
          res.writeHead(401).end("invalid slack signature");
          return;
        }

        const params = new URLSearchParams(body.toString("utf8"));
        const payload = JSON.parse(params.get("payload") ?? "{}");
        if (payload.type === "block_actions") {
          const action = payload.actions?.[0];
          const parsed = parseDecisionPayload(action?.value ?? "");
          if (parsed && this.pending.has(parsed.intentId)) {
            const actor = `slack:${payload.user?.id ?? "unknown"}`;
            const result = this.pending.settle(parsed.intentId, parsed.decision, actor, this.cfg.authorityKey);
            if (result && payload.response_url) {
              // Resolved → replace the message (removes buttons). Pending → an
              // ephemeral progress note, leaving the original message and its
              // buttons intact so other approvers can still complete the quorum.
              const update =
                result.status === "resolved"
                  ? {
                      replace_original: true,
                      text: `counter-sign: ${result.decision!.toUpperCase()} (last: <@${payload.user?.id}>) — intent ${parsed.intentId}`,
                    }
                  : {
                      response_type: "ephemeral",
                      text: `Recorded ${result.collected}/${result.quorum} — awaiting more approvers.`,
                    };
              void fetch(payload.response_url, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(update),
              }).catch(() => {});
            }
          }
        }
        res.writeHead(200).end();
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
    };
  }

  close(): void {
    this.pending.abortAll(new CountersignError("slack adapter closed"));
  }

  private async api(method: string, body: unknown): Promise<any> {
    const res = await fetch(`${this.cfg.apiBase}/${method}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.cfg.botToken}`,
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(body),
    });
    const data: any = await res.json().catch(() => ({}));
    if (!res.ok || data.ok !== true) {
      throw new CountersignError(`slack ${method} failed: ${data.error ?? res.status}`);
    }
    return data;
  }
}
