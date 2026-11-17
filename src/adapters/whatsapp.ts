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
  PendingDecisions,
  type Adapter,
  assertVouchedApprovers,
  DeliveryPartialError,
} from "../adapter.js";
import { normalizeActor } from "../core/countersignature.js";
import { CountersignError } from "../core/errors.js";
import { publicKeyFromSecret } from "../core/keys.js";
import type { Intent, Resolution } from "../core/types.js";

/**
 * Meta's documented maximum for a template body (WhatsApp Cloud API template
 * docs, at the time of writing). Checked against the body with the variables
 * filled in, and only with `enforceLimits`: whether Meta refuses or cuts an
 * over-long filled-in body is not confirmed here. Override with
 * `maxTemplateBodyLength` if Meta changes it.
 */
export const WHATSAPP_MAX_TEMPLATE_BODY_LENGTH = 1024;

/**
 * Meta's rule for template variables, at the time of writing: a parameter may
 * not contain a newline or tab (Meta rejects the send, so this is refused by
 * default), nor a long run of spaces (refused only with `enforceLimits`: Meta's
 * error text says "more than 4 consecutive spaces", so four is refused there to
 * be safe, but the exact threshold is not confirmed here).
 */
const NEWLINE_OR_TAB = /[\r\n\t]/;
const RUN_OF_SPACES = / {4,}/;

/**
 * The body of the `countersign_approval` template described in
 * adapters/README.md. If your approved template reads differently, pass its body
 * as `templateBody` so the length check counts the text the approver will see.
 */
export const DEFAULT_WHATSAPP_TEMPLATE_BODY = "{{1}} — action: {{2}} ({{3}})";

/** E.164 number as the Cloud API reports it in a webhook's `from`: digits only, no "+". */
const E164_DIGITS = /^[1-9]\d{6,14}$/;

/** How the adapter picks recipients when `recipientMode` is given. */
export type WhatsAppRecipientMode = "approvers" | "single";
const RECIPIENT_MODES: readonly string[] = ["approvers", "single"];

// DeliveryPartialError is defined in adapter.ts (any adapter may throw it, and
// DurableDecisions recognises it) and re-exported here, beside the adapter that throws it.
export { DeliveryPartialError };

export interface WhatsAppConfig {
  accessToken: string;
  phoneNumberId: string;
  /**
   * Approver's number, E.164 digits without "+". With no `recipientMode`, every
   * Intent is sent to this number, as in 0.2.0. Required unless `recipientMode`
   * is "approvers", where it is not used (and may be empty).
   */
  to: string;
  /** Pre-approved template with a 3-variable body and two quick-reply buttons. */
  templateName: string;
  templateLang: string;
  /** Token echoed back during Meta's webhook GET verification. */
  verifyToken: string;
  /** App secret. REQUIRED — verifies X-Hub-Signature-256 on every webhook POST. */
  appSecret: string;
  authorityKey: string;
  graphBase: string;
  /**
   * Who the request goes to (env WHATSAPP_RECIPIENT_MODE). Not set: to `to`,
   * with no check on the Intent's approvers (0.2.0 behaviour).
   * "approvers": one template to each `whatsapp:<number>` approver the Intent
   * names; refuses an Intent naming none, or naming one not written as bare
   * E.164 digits. "single": to `to` only; refuses an Intent whose WhatsApp
   * approvers are not exactly that number.
   */
  recipientMode?: WhatsAppRecipientMode;
  /** The approved template's body text with {{1}} {{2}} {{3}}; what `enforceLimits` counts. */
  templateBody?: string;
  /** Longest rendered template body sent under `enforceLimits`. Defaults to WHATSAPP_MAX_TEMPLATE_BODY_LENGTH. */
  maxTemplateBodyLength?: number;
  /**
   * Refuse, before sending, a rendered template body over `maxTemplateBodyLength`
   * and a variable with a run of four or more spaces. Off by default. (A
   * variable with a newline or tab is always refused: Meta rejects it.)
   */
  enforceLimits?: boolean;
  /**
   * Only believe a webhook change whose `metadata.phone_number_id` is this
   * adapter's `phoneNumberId`; a change for another number, or with none, is
   * ignored (env WHATSAPP_REQUIRE_PHONE_NUMBER_ID=1). Off by default.
   */
  requirePhoneNumberId?: boolean;
  /**
   * After a press, send the presser a short text saying the decision was recorded,
   * by whom and when (a template message cannot be edited). Off by default.
   */
  confirmDecisions?: boolean;
}

function recipientModeFrom(value: string | undefined, source: string): WhatsAppRecipientMode | undefined {
  if (value === undefined || value === "") return undefined;
  if (!RECIPIENT_MODES.includes(value))
    throw new CountersignError(`${source} must be "approvers" or "single", not ${JSON.stringify(value)}`);
  return value as WhatsAppRecipientMode;
}

export function whatsappConfigFromEnv(overrides: Partial<WhatsAppConfig> = {}): WhatsAppConfig {
  const recipientMode =
    overrides.recipientMode !== undefined
      ? recipientModeFrom(overrides.recipientMode, "recipientMode")
      : recipientModeFrom(process.env.WHATSAPP_RECIPIENT_MODE, "WHATSAPP_RECIPIENT_MODE");
  const templateBody = overrides.templateBody ?? (process.env.WHATSAPP_TEMPLATE_BODY || undefined);
  if (templateBody !== undefined)
    for (const n of [1, 2, 3])
      if (!templateBody.includes(`{{${n}}}`))
        throw new CountersignError(
          `WhatsApp templateBody must contain {{${n}}}: the approver has to see the summary ({{1}}), the action ({{2}}) and the risk and default ({{3}})`,
        );
  // The 0.2.0 fields, read in the 0.2.0 order so a missing one throws the same error.
  const cfg: WhatsAppConfig = {
    accessToken: overrides.accessToken ?? requireEnv("WHATSAPP_ACCESS_TOKEN"),
    phoneNumberId: overrides.phoneNumberId ?? requireEnv("WHATSAPP_PHONE_NUMBER_ID"),
    // Per-approver delivery does not use `to`; every other mode needs it.
    to: recipientMode === "approvers" ? (overrides.to ?? "") : (overrides.to ?? requireEnv("WHATSAPP_TO")),
    templateName: overrides.templateName ?? process.env.WHATSAPP_TEMPLATE_NAME ?? "countersign_approval",
    templateLang: overrides.templateLang ?? process.env.WHATSAPP_TEMPLATE_LANG ?? "en",
    verifyToken: overrides.verifyToken ?? requireEnv("WHATSAPP_VERIFY_TOKEN"),
    // REQUIRED, not optional: without it the webhook would run fail-open and
    // anyone who learns an intent_id could forge a decision.
    appSecret: overrides.appSecret ?? requireEnv("WHATSAPP_APP_SECRET"),
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    graphBase: overrides.graphBase ?? process.env.WHATSAPP_GRAPH_BASE ?? "https://graph.facebook.com/v20.0",
  };
  // Settings added after 0.2.0 appear only when given, so a config that sets
  // none of them resolves to exactly the 0.2.0 object.
  const requirePhoneNumberId =
    overrides.requirePhoneNumberId ?? (process.env.WHATSAPP_REQUIRE_PHONE_NUMBER_ID === "1" ? true : undefined);
  const confirmDecisions = overrides.confirmDecisions ?? (process.env.WHATSAPP_CONFIRM_DECISIONS === "1" ? true : undefined);
  if (recipientMode !== undefined) cfg.recipientMode = recipientMode;
  if (templateBody !== undefined) cfg.templateBody = templateBody;
  if (overrides.maxTemplateBodyLength !== undefined) cfg.maxTemplateBodyLength = overrides.maxTemplateBodyLength;
  if (overrides.enforceLimits !== undefined) cfg.enforceLimits = overrides.enforceLimits;
  if (requirePhoneNumberId !== undefined) cfg.requirePhoneNumberId = requirePhoneNumberId;
  if (confirmDecisions !== undefined) cfg.confirmDecisions = confirmDecisions;
  return cfg;
}

/** The three template variables, in order: summary, action, risk and default. The one source for sending and for counting. */
export function whatsappTemplateParameters(intent: Intent): [string, string, string] {
  return [intent.summary, intent.action, `${intent.risk_tier} risk, default ${intent.default} in ${intent.timeout}s`];
}

/** The template body as the approver will read it, with {{n}} replaced by the n-th variable. */
export function renderWhatsAppTemplateBody(templateBody: string, params: readonly string[]): string {
  return templateBody.replace(/\{\{(\d+)\}\}/g, (m, n: string) => params[Number(n) - 1] ?? m);
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
  /** The authority public key this adapter signs vouched receipts with — reconciled by wrapAction. */
  get authorityPublicKey(): string {
    return publicKeyFromSecret(this.cfg.authorityKey);
  }
  private readonly pending = new PendingDecisions();
  private readonly cfg: WhatsAppConfig;

  constructor(config: Partial<WhatsAppConfig> = {}) {
    this.cfg = whatsappConfigFromEnv(config);
  }

  async deliver(intent: Intent): Promise<void> {
    assertVouchedApprovers(intent); // this adapter is vouched-only; keyed approvers use the SigningServer
    // Every check runs before the first send, so a refusal never leaves a partial delivery.
    const recipients = this.recipientsFor(intent);
    const params = whatsappTemplateParameters(intent);
    this.assertDeliverable(params);
    for (let i = 0; i < recipients.length; i++) {
      try {
        await this.sendTemplate(intent, recipients[i], params);
      } catch (err) {
        if (i === 0) throw err; // nobody holds buttons yet: the plain send error
        const actors = recipients.map((n) => `whatsapp:${n}`);
        throw new DeliveryPartialError(intent.intent_id, actors.slice(0, i), actors.slice(i), err);
      }
    }
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    return this.pending.wait(intent);
  }

  /**
   * Node HTTP handler for the Meta webhook: answers the GET verification
   * challenge, checks X-Hub-Signature-256 against the app secret on every POST,
   * with requirePhoneNumberId ignores changes addressed to another phone number
   * id, and settles pending intents on quick-reply button messages.
   */
  webhookHandler(): (req: IncomingMessage, res: ServerResponse) => void {
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
        if (!this.verifyHubSignature(body, req.headers["x-hub-signature-256"] as string | undefined)) {
          res.writeHead(401).end("invalid hub signature");
          return;
        }
        try {
          const event = JSON.parse(body.toString("utf8"));
          for (const entry of event.entry ?? []) {
            for (const change of entry.changes ?? []) {
              if (!this.isForThisNumber(change.value)) continue;
              for (const message of change.value?.messages ?? []) {
                if (message.type !== "button") continue;
                const parsed = parseDecisionPayload(message.button?.payload ?? "");
                if (parsed && this.pending.has(parsed.intentId)) {
                  const actor = `whatsapp:${message.from}`;
                  const result = this.pending.settle(parsed.intentId, parsed.decision, actor, this.cfg.authorityKey);
                  if (result && this.cfg.confirmDecisions) {
                    const note =
                      result.status === "resolved"
                        ? `Decision recorded: ${result.decision.toUpperCase()} by ${actor} at ${result.countersignature.timestamp} (intent ${parsed.intentId}).`
                        : `Approval ${result.collected}/${result.quorum} recorded: ${actor} at ${result.countersignature.timestamp} (intent ${parsed.intentId}). Awaiting more approvers.`;
                    void this.sendText(String(message.from), note, message.context?.id).catch(() => {});
                  }
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
    if (!header?.startsWith("sha256=")) return false;
    const expected = createHmac("sha256", this.cfg.appSecret).update(rawBody).digest("hex");
    const a = Buffer.from(`sha256=${expected}`);
    const b = Buffer.from(header);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  close(): void {
    this.pending.abortAll(new CountersignError("whatsapp adapter closed"));
  }

  /** One Meta app can serve several numbers; with requirePhoneNumberId, only believe changes for the configured one. */
  private isForThisNumber(value: any): boolean {
    if (this.cfg.requirePhoneNumberId !== true) return true; // 0.2.0 behaviour
    const id = value?.metadata?.phone_number_id;
    return id !== undefined && id !== null && String(id) === this.cfg.phoneNumberId;
  }

  /** Who this Intent goes to. Throws, before anything is sent, if a named approver could not be reached. */
  private recipientsFor(intent: Intent): string[] {
    const mode = this.cfg.recipientMode;
    if (mode === undefined) return [this.cfg.to]; // 0.2.0: always `to`, no approver checks
    const numbers: string[] = [];
    for (const a of intent.approvers) {
      const actor = normalizeActor(a.actor);
      if (!actor.startsWith("whatsapp:")) continue; // served by another channel
      const number = actor.slice("whatsapp:".length);
      if (!E164_DIGITS.test(number))
        throw new CountersignError(
          `whatsapp approver "${a.actor}" must be whatsapp:<E.164 digits, no "+">, e.g. whatsapp:6591234567 — ` +
            `the webhook reports the sender that way, so any other spelling could never be counted (intent ${intent.intent_id})`,
        );
      if (!numbers.includes(number)) numbers.push(number);
    }
    if (mode === "single") {
      const to = this.cfg.to;
      if (!numbers.includes(to))
        throw new CountersignError(
          `whatsapp is in single-recipient mode and intent ${intent.intent_id} does not name the configured recipient ` +
            `whatsapp:${to} as an approver; refusing to ask someone whose answer would not count`,
        );
      const unreached = numbers.filter((n) => n !== to);
      if (unreached.length > 0)
        throw new CountersignError(
          `whatsapp is in single-recipient mode (whatsapp:${to}) but intent ${intent.intent_id} also names ` +
            `${unreached.map((n) => `whatsapp:${n}`).join(", ")}, who would never be asked; use recipientMode "approvers" to deliver to every approver`,
        );
      return [to];
    }
    if (numbers.length === 0)
      throw new CountersignError(
        `intent ${intent.intent_id} names no whatsapp approver (whatsapp:<number>), so there is nobody to send it to`,
      );
    return numbers;
  }

  /**
   * Refuse what Meta would reject or cut, so nobody is asked to approve text they
   * cannot see in full. By default only what Meta rejects outright (a newline or
   * tab in a variable), so nothing 0.2.0 delivered is refused; enforceLimits adds
   * runs of spaces and the rendered body length.
   */
  private assertDeliverable(params: readonly string[]): void {
    const strict = this.cfg.enforceLimits === true;
    params.forEach((p, i) => {
      if (NEWLINE_OR_TAB.test(p) || (strict && RUN_OF_SPACES.test(p)))
        throw new CountersignError(
          `whatsapp template variable {{${i + 1}}} contains a newline, tab or a run of four or more spaces, which Meta rejects; ` +
            `refusing to deliver. Write the Intent's summary on one line.`,
        );
    });
    if (!strict) return;
    const limit = this.cfg.maxTemplateBodyLength ?? WHATSAPP_MAX_TEMPLATE_BODY_LENGTH;
    const length = renderWhatsAppTemplateBody(this.cfg.templateBody ?? DEFAULT_WHATSAPP_TEMPLATE_BODY, params).length;
    if (length > limit)
      throw new CountersignError(
        `whatsapp template body would be ${length} characters; the limit is ${limit}. ` +
          `Refusing to deliver text the approver could not read in full: shorten the Intent's summary.`,
      );
  }

  private async sendTemplate(intent: Intent, to: string, params: readonly string[]): Promise<void> {
    await this.graph({
      messaging_product: "whatsapp",
      to,
      type: "template",
      template: {
        name: this.cfg.templateName,
        language: { code: this.cfg.templateLang },
        components: [
          { type: "body", parameters: params.map((text) => ({ type: "text", text })) },
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
    }, "template send");
  }

  /** A free-form reply; allowed because the presser has just messaged the business. */
  private async sendText(to: string, body: string, replyTo?: string): Promise<void> {
    await this.graph(
      {
        messaging_product: "whatsapp",
        to,
        type: "text",
        ...(replyTo ? { context: { message_id: replyTo } } : {}),
        text: { body },
      },
      "confirmation send",
    );
  }

  private async graph(payload: unknown, what: string): Promise<void> {
    const res = await fetch(`${this.cfg.graphBase}/${this.cfg.phoneNumberId}/messages`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.cfg.accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => String(res.status));
      throw new CountersignError(`whatsapp ${what} failed: ${detail}`);
    }
  }
}
