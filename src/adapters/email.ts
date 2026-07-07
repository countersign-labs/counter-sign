// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import nodemailer, { type Transporter } from "nodemailer";
import {
  authorityKeyFromEnv,
  formatIntent,
  readBody,
  requireEnv,
  PendingDecisions,
  type Adapter,
} from "../adapter.js";
import { canonicalize } from "../core/canonical.js";
import { deadline } from "../core/defaults.js";
import { CountersignError } from "../core/errors.js";
import { quorumOf } from "../core/intent.js";
import { fromB64url, publicKeyFromSecret, signContext, toB64url, verifyContext } from "../core/keys.js";
import { LINK_CONTEXT, type Decision, type Intent, type Resolution } from "../core/types.js";

export interface EmailConfig {
  smtpUrl: string;
  from: string;
  to: string;
  /** Public base URL of the callback server that serves the confirm page. */
  callbackBaseUrl: string;
  authorityKey: string;
  /** Test seam: inject a nodemailer transport instead of dialing smtpUrl. */
  transport?: Transporter;
}

export function emailConfigFromEnv(overrides: Partial<EmailConfig> = {}): EmailConfig {
  return {
    smtpUrl: overrides.smtpUrl ?? (overrides.transport ? "smtp://unused" : requireEnv("SMTP_URL")),
    from: overrides.from ?? requireEnv("EMAIL_FROM"),
    to: overrides.to ?? requireEnv("EMAIL_TO"),
    callbackBaseUrl: overrides.callbackBaseUrl ?? requireEnv("EMAIL_CALLBACK_BASE_URL"),
    authorityKey: overrides.authorityKey ?? authorityKeyFromEnv(),
    transport: overrides.transport,
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface LinkPayload {
  intent_id: string;
  decision: Decision;
  /** epoch milliseconds; always equals the Intent's deadline */
  exp: number;
}

/** Create a signed link token: base64url(payload JSON) + "." + signature. */
export function createLinkToken(intent: Intent, decision: Decision, authoritySecret: string): string {
  const payload: LinkPayload = { intent_id: intent.intent_id, decision, exp: deadline(intent) };
  const body = canonicalize(payload);
  return `${toB64url(Buffer.from(body, "utf8"))}.${signContext(authoritySecret, LINK_CONTEXT, body)}`;
}

/** Verify a link token's signature and shape. Returns null on any failure. */
export function verifyLinkToken(token: string, authorityPublicKey: string): LinkPayload | null {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  const body = fromB64url(token.slice(0, dot));
  if (!verifyContext(authorityPublicKey, LINK_CONTEXT, body.toString("utf8"), token.slice(dot + 1))) return null;
  try {
    const payload = JSON.parse(body.toString("utf8"));
    if (
      typeof payload?.intent_id !== "string" ||
      !UUID_RE.test(payload.intent_id) ||
      (payload.decision !== "approve" && payload.decision !== "reject") ||
      typeof payload.exp !== "number" ||
      !Number.isFinite(payload.exp)
    )
      return null;
    return payload as LinkPayload;
  } catch {
    return null;
  }
}

/**
 * Email adapter (SMTP via nodemailer). The email carries signed, single-use
 * Approve/Reject links whose expiry equals the Intent timeout. The decision
 * executes ONLY on the POST from the served confirm page — a GET renders
 * the page and decides nothing, so mail-scanner prefetch cannot approve.
 */
export class EmailAdapter implements Adapter {
  readonly channel = "email";
  private readonly pending = new PendingDecisions();
  private readonly cfg: EmailConfig;
  private readonly transport: Transporter;
  private readonly authorityPublicKey: string;
  /** Intents already decided via a link; every remaining link for them is dead. */
  private readonly decided = new Set<string>();

  constructor(config: Partial<EmailConfig> = {}) {
    this.cfg = emailConfigFromEnv(config);
    this.transport = this.cfg.transport ?? nodemailer.createTransport(this.cfg.smtpUrl);
    this.authorityPublicKey = publicKeyFromSecret(this.cfg.authorityKey);
  }

  linkFor(intent: Intent, decision: Decision): string {
    return `${this.cfg.callbackBaseUrl}/decide?token=${encodeURIComponent(createLinkToken(intent, decision, this.cfg.authorityKey))}`;
  }

  async deliver(intent: Intent): Promise<void> {
    // Bearer links go to one recipient, so distinct-approver quorum cannot be
    // satisfied — and MUST NOT be faked — over email. Refuse quorum > 1 loudly
    // rather than silently deadlock to the timeout Default.
    if (quorumOf(intent) > 1) {
      throw new CountersignError(
        `email adapter supports a single approver (quorum 1); intent ${intent.intent_id} requires ${quorumOf(intent)}. ` +
          `Use a chat adapter where distinct approvers can each respond.`,
      );
    }
    const approve = this.linkFor(intent, "approve");
    const reject = this.linkFor(intent, "reject");
    const expires = new Date(deadline(intent)).toISOString();
    await this.transport.sendMail({
      from: this.cfg.from,
      to: this.cfg.to,
      subject: `[counter-sign] ${intent.action} (${intent.risk_tier})`,
      text:
        `${formatIntent(intent)}\n\n` +
        `Approve: ${approve}\n\nReject: ${reject}\n\n` +
        `Links are single-use and expire ${expires}. Opening a link never decides by itself; ` +
        `you confirm on the page it opens.`,
      html:
        `<pre>${escapeHtml(formatIntent(intent))}</pre>` +
        `<p><a href="${approve}">Approve</a> &nbsp;|&nbsp; <a href="${reject}">Reject</a></p>` +
        `<p>Links are single-use and expire ${expires}. Opening a link never decides by itself; you confirm on the page it opens.</p>`,
    });
  }

  awaitResolution(intent: Intent): Promise<Resolution> {
    return this.pending.wait(intent);
  }

  /**
   * Callback server handler. GET /decide renders a confirm page (and never
   * decides — safe against mail-scanner prefetch). POST /decide performs
   * the decision if the token verifies, is unexpired, and unused.
   */
  handleRequest(): (req: IncomingMessage, res: ServerResponse) => void {
    return (req, res) => {
      void (async () => {
        const url = new URL(req.url ?? "/", "http://localhost");
        if (url.pathname !== "/decide") {
          res.writeHead(404).end("not found");
          return;
        }
        if (req.method === "GET") {
          const token = url.searchParams.get("token") ?? "";
          const check = this.checkToken(token);
          if (!check.ok) {
            page(res, check.status, "Link not usable", check.reason);
            return;
          }
          const { payload } = check;
          page(
            res,
            200,
            `Confirm: ${escapeHtml(payload.decision)}`,
            `You are about to <strong>${escapeHtml(payload.decision)}</strong> intent <code>${escapeHtml(payload.intent_id)}</code>.` +
              `<form method="POST" action="/decide">` +
              `<input type="hidden" name="token" value="${escapeHtml(token)}">` +
              `<button type="submit">Confirm ${escapeHtml(payload.decision)}</button></form>` +
              `<p>Nothing happens until you press the button.</p>`,
          );
          return;
        }
        if (req.method === "POST") {
          const body = await readBody(req);
          const token = new URLSearchParams(body.toString("utf8")).get("token") ?? "";
          const check = this.checkToken(token);
          if (!check.ok) {
            page(res, check.status, "Link not usable", check.reason);
            return;
          }
          const { payload } = check;
          this.decided.add(payload.intent_id);
          this.pending.settle(payload.intent_id, payload.decision, `email:${this.cfg.to}`, this.cfg.authorityKey);
          page(
            res,
            200,
            "Decision recorded",
            `<strong>${escapeHtml(payload.decision.toUpperCase())}</strong> recorded for intent <code>${escapeHtml(payload.intent_id)}</code>. ` +
              `A signed Countersignature has been issued. You can close this tab.`,
          );
          return;
        }
        res.writeHead(405).end();
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
    };
  }

  private checkToken(
    token: string,
  ): { ok: true; payload: LinkPayload } | { ok: false; status: number; reason: string } {
    const payload = verifyLinkToken(token, this.authorityPublicKey);
    if (!payload) return { ok: false, status: 400, reason: "This link is invalid or has been tampered with." };
    if (Date.now() >= payload.exp)
      return { ok: false, status: 410, reason: "This link has expired; the intent's timeout default has authority now." };
    if (this.decided.has(payload.intent_id))
      return { ok: false, status: 410, reason: "This intent has already been decided; links are single-use." };
    if (!this.pending.has(payload.intent_id))
      return { ok: false, status: 410, reason: "This intent is no longer pending." };
    return { ok: true, payload };
  }

  createServer(): Server {
    return createServer(this.handleRequest());
  }

  close(): void {
    this.transport.close?.();
    this.pending.abortAll(new CountersignError("email adapter closed"));
  }
}

function page(res: ServerResponse, status: number, title: string, bodyHtml: string): void {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" }).end(
    `<!doctype html><html><head><meta charset="utf-8"><title>counter-sign — ${escapeHtml(title)}</title>` +
      `<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;line-height:1.5}` +
      `button{font-size:1.1rem;padding:.6rem 1.4rem;margin-top:1rem;cursor:pointer}</style></head>` +
      `<body><h1>${escapeHtml(title)}</h1><div>${bodyHtml}</div></body></html>`,
  );
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
