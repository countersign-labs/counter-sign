// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.
//
// SigningServer — hosts the passkey (WebAuthn) signing page for KEYED approvers
// and collects their self-signed receipts into a PendingDecisions. A chat/email
// adapter delivers a per-approver deep-link (signingUrl) instead of an inline
// button; the approver taps it, confirms with their passkey, and the assertion
// is POSTed back. The server never holds the approver's key — it only relays and
// verifies (via PendingDecisions.record), so it cannot forge a keyed approval.

import { createHash, randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { PendingDecisions, readBody } from "./adapter.js";
import { canonicalize } from "./core/canonical.js";
import { fromB64url, publicKeyFromSecret, signContext, toB64url, utf8, verifyContext } from "./core/keys.js";
import { normalizeActor } from "./core/countersignature.js";
import { quorumOf } from "./core/intent.js";
import { isWebAuthnCredential, type WebAuthnPolicy } from "./core/webauthn.js";
import { COUNTERSIGN_VERSION, COUNTERSIGNATURE_CONTEXT, LINK_CONTEXT, type Approver, type Countersignature, type Intent } from "./core/types.js";

export interface SigningServerConfig {
  /** The shared decision store the adapter awaits on (record() resolves it). */
  pending: PendingDecisions;
  /** Authority seed — signs and verifies the single-use signing-link tokens. */
  authorityKey: string;
  /** RP policy (rpId + allowed origins) used to verify the passkey assertions. */
  webauthn: WebAuthnPolicy;
  /** Public base URL of this server, e.g. "https://approve.example.com". */
  baseUrl: string;
}

/** How stale a click-time signing timestamp may be at record (clock skew + latency). */
const MAX_SIGNING_SKEW_MS = 5 * 60_000;

interface SignToken {
  typ: "sign";
  intent_id: string;
  actor: string;
  exp: number;
}

/** A signed, expiring token authorizing `actor` to sign for `intent`. */
export function createSigningToken(intent: Intent, actor: string, authoritySecret: string, exp: number): string {
  const body = JSON.stringify({ typ: "sign", intent_id: intent.intent_id, actor, exp } satisfies SignToken);
  return `${toB64url(utf8(body))}.${signContext(authoritySecret, LINK_CONTEXT, body)}`;
}

export function verifySigningToken(token: string, authorityPublicKey: string): SignToken | null {
  try {
    const dot = token.indexOf(".");
    if (dot < 0) return null;
    const body = fromB64url(token.slice(0, dot)).toString("utf8");
    if (!verifyContext(authorityPublicKey, LINK_CONTEXT, body, token.slice(dot + 1))) return null;
    const p = JSON.parse(body) as SignToken;
    if (p.typ !== "sign" || typeof p.intent_id !== "string" || typeof p.actor !== "string" || typeof p.exp !== "number" || !Number.isFinite(p.exp))
      return null;
    return p;
  } catch {
    return null;
  }
}

/** The unsigned receipt fields the assertion challenge is computed over. */
function unsignedReceipt(intentId: string, decision: "approve" | "reject", actor: string, credential: string, timestamp: string) {
  return { countersign: COUNTERSIGN_VERSION, intent_id: intentId, decision, actor, policy: "approver" as const, timestamp, public_key: credential };
}
function challengeFor(unsigned: object): string {
  return toB64url(createHash("sha256").update(utf8(`${COUNTERSIGNATURE_CONTEXT}\n${canonicalize(unsigned)}`)).digest());
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/**
 * Serialize for embedding inside a <script> block. JSON.stringify does NOT escape
 * `</script>` or the U+2028/U+2029 line terminators, so an attacker-influenced
 * field (e.g. intent.summary) could break out of the script context — a stored
 * XSS. Escaping `<` (and the separators) closes that.
 */
function scriptJson(obj: unknown): string {
  // Escape sequences that can break out of a <script> block: `<` (so `</script>`
  // and `<!--` are inert) and the U+2028/U+2029 line terminators (invalid inside JS
  // string literals). JSON.stringify escapes none of these.
  return JSON.stringify(obj).replace(/[<\u2028\u2029]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

export class SigningServer {
  private readonly cfg: SigningServerConfig;
  private readonly authorityPublicKey: string;
  /**
   * normalized `intent_id\nactor` -> the link token's expiry (ms). One entry per
   * approver who has recorded a decision, so the link is single-use. Entries are
   * pruned once their token expires — a spent link past its deadline can't be
   * replayed anyway (the token is rejected upstream), so keeping it only leaks
   * memory on a long-running server.
   */
  private readonly consumed = new Map<string, number>();

  constructor(cfg: SigningServerConfig) {
    this.cfg = cfg;
    this.authorityPublicKey = publicKeyFromSecret(cfg.authorityKey);
  }

  /** Await a keyed approver's decision — the collection point for record(). */
  awaitResolution(intent: Intent) {
    return this.cfg.pending.wait(intent);
  }

  /** Cancel a pending signing wait (e.g. delivery of the links failed) and reclaim
   *  it immediately instead of leaving it for the deadline reaper. */
  cancel(intent: Intent, err: Error): void {
    this.cfg.pending.cancel(intent.intent_id, err);
  }

  /** A per-approver deep-link to the signing page for `actor` (must be a keyed approver). */
  signingUrl(intent: Intent, actor: string): string {
    const approver = intent.approvers.find((a) => normalizeActor(a.actor) === normalizeActor(actor));
    if (!approver || approver.mode !== "keyed") throw new Error(`actor ${actor} is not a keyed approver of this intent`);
    if (!isWebAuthnCredential(approver.public_key ?? "")) throw new Error(`actor ${actor} is not a passkey approver`);
    const token = createSigningToken(intent, approver.actor, this.cfg.authorityKey, deadlineOf(intent));
    return `${this.cfg.baseUrl}/sign?token=${encodeURIComponent(token)}`;
  }

  /** Node HTTP handler for GET /sign (render page) and POST /sign (record assertion). */
  handler(): (req: IncomingMessage, res: ServerResponse) => void {
    return (req, res) => {
      void (async () => {
        const url = new URL(req.url ?? "/", this.cfg.baseUrl);
        if (url.pathname !== "/sign") {
          res.writeHead(404).end();
          return;
        }
        if (req.method === "GET") return this.get(url, res);
        if (req.method === "POST") return this.post(req, res);
        res.writeHead(405).end();
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
    };
  }

  private resolveApprover(token: SignToken): { intent: Intent; approver: Approver } | null {
    const intent = this.cfg.pending.get(token.intent_id);
    if (!intent) return null;
    const approver = intent.approvers.find(
      (a) => a.mode === "keyed" && normalizeActor(a.actor) === normalizeActor(token.actor) && isWebAuthnCredential(a.public_key ?? ""),
    );
    return approver ? { intent, approver } : null;
  }

  private get(url: URL, res: ServerResponse): void {
    const token = verifySigningToken(url.searchParams.get("token") ?? "", this.authorityPublicKey);
    const found = token && Date.now() < token.exp ? this.resolveApprover(token) : null;
    if (!token || !found || Date.now() >= token.exp) {
      res.writeHead(410, { "content-type": "text/html; charset=utf-8" }).end(page("This approval link is invalid, expired, or already decided.", ""));
      return;
    }
    const { intent } = found;
    // The challenge (and its timestamp) is minted at CLICK time via POST phase
    // "challenge", so the receipt's timestamp reflects when the human decided —
    // not when this page rendered (a page left open must not backdate the audit).
    const data = {
      summary: intent.summary,
      action: intent.action,
      rpId: this.cfg.webauthn.rpId,
      quorum: quorumOf(intent),
      // When the deployment requires User Verification, the browser must ASK for it
      // ("required") — else an authenticator may return a UP-only assertion that the
      // verifier then rejects, leaving the approver unable to record at all.
      requireUserVerification: this.cfg.webauthn.requireUserVerification === true,
    };
    // Defense-in-depth CSP: only our nonce'd inline script may run; block objects,
    // base-uri, and framing. The scriptJson escaping is the primary XSS defense.
    const nonce = randomBytes(16).toString("base64");
    res
      .writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
        "x-content-type-options": "nosniff",
      })
      .end(page(null, scriptJson(data), nonce));
  }

  private async post(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const json = (code: number, payload: unknown): void => {
      res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(payload));
    };
    let body: { phase?: string; token?: string; decision?: string; timestamp?: string; signature?: string; authenticator_data?: string; client_data_json?: string };
    try {
      body = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      return json(400, { error: "bad body" });
    }
    const token = verifySigningToken(body.token ?? "", this.authorityPublicKey);
    if (!token || Date.now() >= token.exp) return json(410, { error: "invalid or expired token" });
    if (body.decision !== "approve" && body.decision !== "reject") return json(400, { error: "bad decision" });

    // Phase 1 (click): mint a fresh timestamp + challenge for THIS decision, so the
    // audit timestamp is when the human pressed the button.
    if (body.phase === "challenge") {
      const found = this.resolveApprover(token);
      if (!found) return json(410, { error: "no longer pending" });
      const ts = new Date().toISOString();
      const challenge = challengeFor(unsignedReceipt(token.intent_id, body.decision, found.approver.actor, found.approver.public_key!, ts));
      return json(200, { timestamp: ts, challenge });
    }

    // Phase 2 (record): single-use per (intent, actor) — once recorded, the link is
    // dead (no replay, no approve-then-veto from a second tab). Check BEFORE
    // resolveApprover so a replay after the Intent resolved still reports "used".
    // Prune expired entries first so the map can't grow without bound.
    this.pruneConsumed(Date.now());
    const useKey = `${token.intent_id}\n${normalizeActor(token.actor)}`;
    if (this.consumed.has(useKey)) return json(410, { error: "this approval link has already been used" });
    const found = this.resolveApprover(token);
    if (!found) return json(410, { error: "no longer pending" });
    if (typeof body.timestamp !== "string" || typeof body.signature !== "string" || typeof body.authenticator_data !== "string" || typeof body.client_data_json !== "string")
      return json(400, { error: "missing assertion fields" });
    // The timestamp was minted at click time; reject a stale one (a captured/old
    // challenge). It is also assertion-bound, so it cannot be altered.
    const ts = Date.parse(body.timestamp);
    if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > MAX_SIGNING_SKEW_MS) return json(400, { error: "stale or invalid timestamp" });

    // Reconstruct the receipt the approver signed; record() re-verifies the
    // assertion against the bound credential + RP policy (the challenge binds
    // every field, so a tampered timestamp/decision breaks it).
    const receipt: Countersignature = {
      ...unsignedReceipt(token.intent_id, body.decision, found.approver.actor, found.approver.public_key!, body.timestamp),
      signature: body.signature,
      webauthn: { authenticator_data: body.authenticator_data, client_data_json: body.client_data_json },
    };
    const result = this.cfg.pending.record(receipt, this.cfg.webauthn);
    if (!result) return json(400, { error: "assertion did not verify or request not pending" });
    this.consumed.set(useKey, token.exp); // this approver's link is now spent (until its token expires)
    return json(200, { status: result.status, decision: result.status === "resolved" ? result.decision : undefined, collected: result.collected, quorum: result.quorum });
  }

  /** Drop spent-link entries whose token has already expired: an expired token is
   *  rejected upstream (no replay is possible), so retaining it only leaks memory. */
  private pruneConsumed(now: number): void {
    for (const [key, exp] of this.consumed) if (now >= exp) this.consumed.delete(key);
  }
}

function deadlineOf(intent: Intent): number {
  return Date.parse(intent.created_at) + intent.timeout * 1000;
}

/** The self-contained signing page. `dataJson` seeds the WebAuthn ceremony. */
function page(errorMessage: string | null, dataJson: string, nonce = ""): string {
  if (errorMessage) return `<!doctype html><meta charset=utf-8><title>counter-sign</title><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>counter-sign</h1><p>${esc(errorMessage)}</p></body>`;
  // Inline, no external resources (matches the repo's no-CDN posture).
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Approve — counter-sign</title>
<body style="font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
<h1 style="font-size:1.2rem">counter-sign approval</h1>
<p id=summary style="font-weight:600"></p>
<p id=action style="color:#555;font-size:.9rem"></p>
<div style="display:flex;gap:.75rem;margin-top:1.5rem">
  <button id=approve style="flex:1;padding:.7rem;border:0;border-radius:.5rem;background:#0a7d33;color:#fff;font-size:1rem">Approve with passkey</button>
  <button id=reject style="flex:1;padding:.7rem;border:0;border-radius:.5rem;background:#b3261e;color:#fff;font-size:1rem">Reject</button>
</div>
<p id=status style="margin-top:1rem;min-height:1.5rem"></p>
<script nonce="${esc(nonce)}">
const D = ${dataJson};
const token = new URLSearchParams(location.search).get("token");
const b64urlToBytes = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(s.length/4)*4,"=")), c=>c.charCodeAt(0));
const bytesToB64url = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");
document.getElementById("summary").textContent = D.summary;
document.getElementById("action").textContent = D.action + (D.quorum>1 ? "  ("+D.quorum+" approvals required)" : "");
const status = document.getElementById("status");
const post = (b) => fetch("/sign", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(b) });
async function decide(decision){
  status.textContent = "Waiting for your passkey…";
  try {
    // Mint a fresh challenge + timestamp at click time (accurate audit timestamp).
    const ch = await (await post({ phase:"challenge", token, decision })).json();
    if (!ch.challenge) { status.textContent = "Error: " + (ch.error||"could not start"); return; }
    const assertion = await navigator.credentials.get({ publicKey: {
      challenge: b64urlToBytes(ch.challenge), rpId: D.rpId,
      userVerification: D.requireUserVerification ? "required" : "preferred", timeout: 120000,
    }});
    const r = assertion.response;
    const res = await post({
      token, decision, timestamp: ch.timestamp,
      authenticator_data: bytesToB64url(r.authenticatorData),
      client_data_json: bytesToB64url(r.clientDataJSON),
      signature: bytesToB64url(r.signature),
    });
    const out = await res.json();
    status.textContent = res.ok ? ("Recorded: " + (out.status==="resolved" ? out.decision.toUpperCase() : (out.collected+"/"+out.quorum+" — awaiting more"))) : ("Error: " + (out.error||res.status));
  } catch(e) { status.textContent = "Passkey error: " + (e && e.message || e); }
}
document.getElementById("approve").onclick = () => decide("approve");
document.getElementById("reject").onclick = () => decide("reject");
</script></body>`;
}
