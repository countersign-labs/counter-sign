// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

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
import { hexToBytes, utf8, verifyRaw } from "../core/keys.js";
import type { Intent, Resolution } from "../core/types.js";

export interface DiscordConfig {
  botToken: string;
  channelId: string;
  /** App public key (hex) from the developer portal; verifies interaction signatures. */
  publicKey: string;
  authorityKey: string;
  apiBase: string;
}

export function discordConfigFromEnv(overrides: Partial<DiscordConfig> = {}): DiscordConfig {
  return {
    botToken: overrides.botToken ?? requireEnv("DISCORD_BOT_TOKEN"),
    channelId: overrides.channelId ?? requireEnv("DISCORD_CHANNEL_ID"),
    publicKey: overrides.publicKey ?? requireEnv("DISCORD_PUBLIC_KEY"),
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    apiBase: overrides.apiBase ?? process.env.DISCORD_API_BASE ?? "https://discord.com/api/v10",
  };
}

/**
 * Discord adapter. Delivers the Intent as a channel message with
 * Approve/Reject button components; the decision arrives on the app's
 * Interactions Endpoint (interactionHandler), which Discord requires to be
 * a public HTTPS URL and to verify the ed25519 signature on every request.
 */
export class DiscordAdapter implements Adapter {
  readonly channel = "discord";
  private readonly pending = new PendingDecisions();
  private readonly cfg: DiscordConfig;

  constructor(config: Partial<DiscordConfig> = {}) {
    this.cfg = discordConfigFromEnv(config);
  }

  async deliver(intent: Intent): Promise<void> {
    const res = await fetch(`${this.cfg.apiBase}/channels/${this.cfg.channelId}/messages`, {
      method: "POST",
      headers: {
        authorization: `Bot ${this.cfg.botToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        content: formatIntent(intent),
        // Never let an attacker-influenced summary/action ping the server.
        allowed_mentions: { parse: [] },
        components: [
          {
            type: 1,
            components: [
              { type: 2, style: 3, label: "Approve", custom_id: decisionPayload(intent, "approve") },
              { type: 2, style: 4, label: "Reject", custom_id: decisionPayload(intent, "reject") },
            ],
          },
        ],
      }),
    });
    if (!res.ok) {
      throw new CountersignError(`discord message send failed: ${res.status} ${await res.text()}`);
    }
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    return this.pending.wait(intent);
  }

  /**
   * Node HTTP handler for the Interactions Endpoint URL. Verifies
   * X-Signature-Ed25519 over timestamp+body per Discord's contract,
   * answers PING, and settles pending intents on button presses.
   */
  interactionHandler(): (req: IncomingMessage, res: ServerResponse) => void {
    return (req, res) => {
      void (async () => {
        if (req.method !== "POST") {
          res.writeHead(405).end();
          return;
        }
        const body = await readBody(req);
        const signature = req.headers["x-signature-ed25519"];
        const timestamp = req.headers["x-signature-timestamp"];
        const valid =
          typeof signature === "string" &&
          typeof timestamp === "string" &&
          verifyRaw(hexToBytes(this.cfg.publicKey), Buffer.concat([utf8(timestamp), body]), hexToBytes(signature));
        if (!valid) {
          res.writeHead(401).end("invalid request signature");
          return;
        }

        const interaction = JSON.parse(body.toString("utf8"));
        const json = (payload: unknown) =>
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(payload));

        if (interaction.type === 1) {
          json({ type: 1 }); // PONG
          return;
        }
        if (interaction.type === 3) {
          const parsed = parseDecisionPayload(interaction.data?.custom_id ?? "");
          const user = interaction.member?.user ?? interaction.user;
          if (!parsed || !this.pending.has(parsed.intentId)) {
            json({ type: 7, data: { content: "Request no longer pending.", components: [] } });
            return;
          }
          const actor = `discord:${user?.id ?? "unknown"}`;
          const result = this.pending.settle(parsed.intentId, parsed.decision, actor, this.cfg.authorityKey);
          const base = interaction.message?.content ?? "";
          if (!result) {
            // settle ignored the click. If the request is STILL pending, the clicker
            // is not one of the Intent's approvers — reply privately and leave the
            // message and its buttons untouched, so a real approver keeps their say
            // (a non-approver must not be able to grief the request by stripping the
            // buttons or faking a resolution). Otherwise the request just closed
            // (deadline or another decision) — remove the now-dead buttons.
            if (this.pending.has(parsed.intentId)) {
              json({ type: 4, data: { content: "You are not an approver for this request.", flags: 64 } });
            } else {
              json({ type: 7, data: { content: `${base}\n\nThis request is closed.`, components: [] } });
            }
            return;
          }
          if (result.status === "pending") {
            // Keep the buttons so other approvers can still complete the quorum.
            json({
              type: 7,
              data: {
                content: `${base}\n\nApproval ${result.collected}/${result.quorum} by <@${user?.id}> — awaiting more`,
                components: interaction.message?.components ?? [],
              },
            });
            return;
          }
          json({
            type: 7, // UPDATE_MESSAGE: strip the buttons now that it is resolved
            data: {
              content: `${base}\n\nResolved: ${result.decision.toUpperCase()} (last: <@${user?.id}>)`,
              components: [],
            },
          });
          return;
        }
        json({ type: 4, data: { content: "Unsupported interaction." } });
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
    };
  }

  close(): void {
    this.pending.abortAll(new CountersignError("discord adapter closed"));
  }
}
