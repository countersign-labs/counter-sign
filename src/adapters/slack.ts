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
  assertVouchedApprovers,
} from "../adapter.js";
import { CountersignError } from "../core/errors.js";
import { publicKeyFromSecret } from "../core/keys.js";
import type { Intent, Resolution } from "../core/types.js";

export interface SlackConfig {
  botToken: string;
  channelId: string;
  /** App Signing Secret; every interactivity request is verified against it. */
  signingSecret: string;
  authorityKey: string;
  apiBase: string;
  /**
   * The app's App ID (Basic Information). When set, an interactivity payload
   * whose `api_app_id` is anything else is refused with 403, even though it is
   * correctly signed: a signing secret shared or reused across apps is not a
   * reason to believe another app's button press.
   */
  appId?: string;
  /** The workspace (team) ID. When set, a payload from any other workspace is refused with 403. */
  teamId?: string;
  /** Longest section text this adapter will post. Defaults to SLACK_MAX_SECTION_TEXT_LENGTH. */
  maxSectionTextLength?: number;
  /**
   * Count the section text in UTF-16 code units, never fewer than the characters
   * Slack counts, so nothing near the limit can be cut. Off by default: the text
   * is then counted in characters (code points), and only text Slack would
   * reject under either count is refused.
   */
  enforceLimits?: boolean;
}

/**
 * Slack's documented maximum for a section block's `text`, at the time of
 * writing (Block Kit reference). Over it, chat.postMessage fails with
 * invalid_blocks. Override with `maxSectionTextLength` if Slack changes it.
 */
export const SLACK_MAX_SECTION_TEXT_LENGTH = 3000;

export function slackConfigFromEnv(overrides: Partial<SlackConfig> = {}): SlackConfig {
  const cfg: SlackConfig = {
    botToken: overrides.botToken ?? requireEnv("SLACK_BOT_TOKEN"),
    channelId: overrides.channelId ?? requireEnv("SLACK_CHANNEL_ID"),
    signingSecret: overrides.signingSecret ?? requireEnv("SLACK_SIGNING_SECRET"),
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    apiBase: overrides.apiBase ?? process.env.SLACK_API_BASE ?? "https://slack.com/api",
  };
  // Settings added after 0.2.0 appear only when given, so a config that sets
  // none of them resolves to exactly the 0.2.0 object.
  const appId = overrides.appId ?? (process.env.SLACK_APP_ID || undefined);
  const teamId = overrides.teamId ?? (process.env.SLACK_TEAM_ID || undefined);
  if (appId !== undefined) cfg.appId = appId;
  if (teamId !== undefined) cfg.teamId = teamId;
  if (overrides.maxSectionTextLength !== undefined) cfg.maxSectionTextLength = overrides.maxSectionTextLength;
  if (overrides.enforceLimits !== undefined) cfg.enforceLimits = overrides.enforceLimits;
  return cfg;
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
  /** The authority public key this adapter signs vouched receipts with — reconciled by wrapAction. */
  get authorityPublicKey(): string {
    return publicKeyFromSecret(this.cfg.authorityKey);
  }
  private readonly pending = new PendingDecisions();
  private readonly cfg: SlackConfig;

  constructor(config: Partial<SlackConfig> = {}) {
    this.cfg = slackConfigFromEnv(config);
  }

  async deliver(intent: Intent): Promise<void> {
    assertVouchedApprovers(intent); // this adapter is vouched-only; keyed approvers use the SigningServer
    const text = formatIntent(intent);
    // Slack rejects an over-long section outright; refuse first, with a clear
    // reason, rather than ask anyone to approve text they cannot see in full.
    // By default only text over the limit in characters (code points), which
    // Slack rejects however it counts, so nothing 0.2.0 delivered is refused;
    // enforceLimits counts UTF-16 code units, never fewer than Slack's characters.
    const limit = this.cfg.maxSectionTextLength ?? SLACK_MAX_SECTION_TEXT_LENGTH;
    const length = this.cfg.enforceLimits ? text.length : [...text].length;
    if (length > limit)
      throw new CountersignError(
        `slack message text would be ${length} characters; the limit is ${limit}. ` +
          `Refusing to deliver text the approver could not read in full: shorten the Intent's summary.`,
      );
    await this.api("chat.postMessage", {
      channel: this.cfg.channelId,
      // plain_text never parses mrkdwn or broadcast mentions (<!channel> etc),
      // and the fallback `text` is escaped, so an attacker-influenced summary
      // cannot break out of the block or ping the channel.
      text: slackEscape(text),
      blocks: [
        { type: "section", text: { type: "plain_text", emoji: false, text } },
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
        // A valid signature proves the request came from Slack, not that it came
        // from THIS app in THIS workspace; check those too when configured.
        if (this.cfg.appId !== undefined && payload.api_app_id !== this.cfg.appId) {
          res.writeHead(403).end("unexpected slack app");
          return;
        }
        if (this.cfg.teamId !== undefined && (payload.team?.id ?? payload.user?.team_id) !== this.cfg.teamId) {
          res.writeHead(403).end("unexpected slack workspace");
          return;
        }
        if (payload.type === "block_actions") {
          const action = payload.actions?.[0];
          const parsed = parseDecisionPayload(action?.value ?? "");
          const intent = parsed ? this.pending.get(parsed.intentId) : undefined;
          if (parsed && intent) {
            const actor = `slack:${payload.user?.id ?? "unknown"}`;
            const result = this.pending.settle(parsed.intentId, parsed.decision, actor, this.cfg.authorityKey);
            if (result && payload.response_url) {
              // Resolved → replace the message: the request stays visible, the
              // buttons go, and a line says the decision was RECORDED, by whom
              // and when (not that the action has run). Pending → an ephemeral
              // progress note, leaving the original message and its buttons
              // intact so other approvers can still complete the quorum.
              const at = result.countersignature.timestamp;
              const request = formatIntent(intent);
              // A request near the limit may not fit a section however Slack counts
              // it; then replace with the decision line alone, as 0.2.0 did.
              const keepRequest = request.length <= (this.cfg.maxSectionTextLength ?? SLACK_MAX_SECTION_TEXT_LENGTH);
              const update =
                result.status === "resolved"
                  ? {
                      replace_original: true,
                      text: `Decision recorded: ${result.decision.toUpperCase()} by <@${payload.user?.id}> at ${at} (intent ${parsed.intentId})`,
                      blocks: [
                        ...(keepRequest ? [{ type: "section", text: { type: "plain_text", emoji: false, text: request } }] : []),
                        {
                          type: "context",
                          elements: [
                            {
                              type: "mrkdwn",
                              text: `Decision recorded: *${result.decision.toUpperCase()}* by <@${payload.user?.id}> at ${at}`,
                            },
                          ],
                        },
                      ],
                    }
                  : {
                      response_type: "ephemeral",
                      text: `Approval ${result.collected}/${result.quorum} recorded: <@${payload.user?.id}> at ${at}. Awaiting more approvers.`,
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
