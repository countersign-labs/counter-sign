// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { authorityKeyFromEnv, warnOnce, type Adapter } from "./adapter.js";
import { awaitWithDefault } from "./core/defaults.js";
import { credentialKeyMaterial, isWebAuthnCredential, type WebAuthnPolicy } from "./core/webauthn.js";
import { CountersignError, IntentRejectedError } from "./core/errors.js";
import { createIntent, type AgentIdentity } from "./core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "./core/keys.js";
import type { Countersignature, Intent, IntentFields, Resolution } from "./core/types.js";
import type { ReceiptSink } from "./receipt-log.js";

export interface WrapOptions {
  /** Signing identity of the requesting agent. Defaults to a per-process keypair. */
  agent?: AgentIdentity;
  /** Authority seed used when the timeout Default fires. Defaults to COUNTERSIGN_AUTHORITY_KEY. */
  authorityKey?: string;
  /** Observe the signed Intent before delivery. */
  onIntent?: (intent: Intent) => void;
  /** Observe the decisive receipt (last approval, the veto, or the default). */
  onDecision?: (cs: Countersignature) => void;
  /** Observe the full Resolution — all contributing receipts — once produced. */
  onResolution?: (resolution: Resolution) => void;
  /**
   * Durably record every resolution's receipts where the runtime is installed —
   * pass a `ReceiptLog` (or any `ReceiptSink`) to give this install a persistent
   * approval history. Recording happens for approvals, vetoes, and timeout
   * Defaults alike, and completes *before* the guarded action runs: if the sink
   * throws, the action does not run (fail-closed audit). Omit it to stay stateless.
   */
  receiptLog?: ReceiptSink;
  /**
   * Deployment policy for verifying passkey (WebAuthn) approver receipts — the
   * signing page's RP ID and allowed origins. REQUIRED if any approver is a
   * passkey; without it a passkey receipt fails closed at verification.
   */
  webauthn?: WebAuthnPolicy;
}

let processAgent: AgentIdentity | undefined;

function defaultAgent(): AgentIdentity {
  if (!processAgent) {
    warnOnce(
      "agent:ephemeral",
      "No agent identity was supplied to wrapAction — using an EPHEMERAL agent key that changes every " +
        "restart, so Intents will not be attributable to a stable agent identity. Pass a persistent agent keypair for production.",
    );
    processAgent = { id: process.env.COUNTERSIGN_AGENT_ID ?? "agent:local", keypair: generateKeypair() };
  }
  return processAgent;
}

/**
 * Wrap any function so it only runs once a human countersigns the intent.
 *
 *   const deploy = wrapAction(deployProd,
 *     { action: "deploy.prod", summary: "Deploy v2.1.0 to production",
 *       risk_tier: "high", approvers: ["telegram:8675309"], timeout: 300, default: "reject" },
 *     new TelegramAdapter());
 *   await deploy("v2.1.0");
 *
 * On approve, the wrapped function runs and its result is returned. On
 * reject — explicit or by timeout Default — IntentRejectedError is thrown,
 * carrying the Countersignature as the audit receipt.
 */
export function wrapAction<A extends unknown[], R>(
  fn: (...args: A) => R | Promise<R>,
  fields: IntentFields,
  adapter: Adapter,
  opts: WrapOptions = {},
): (...args: A) => Promise<R> {
  return async (...args: A): Promise<R> => {
    const agent = opts.agent ?? defaultAgent();
    const intent = createIntent(fields, agent);
    // Observe every signed Intent as soon as it exists — before the pre-delivery checks,
    // so an Intent that fails them is still surfaced to the observer.
    opts.onIntent?.(intent);
    const authority = opts.authorityKey ?? authorityKeyFromEnv();
    // The adapter (e.g. SigningLinkAdapter) may carry the WebAuthn policy its signer
    // verifies against; verify with the SAME policy — otherwise the signer accepts an
    // assertion the verifier later rejects (a post-approval split-brain). Reconcile:
    // use whichever is supplied, and if BOTH are given they MUST be identical.
    const webauthn = reconcileWebAuthn(opts.webauthn, adapter.webauthn);
    // Fail fast on configurations that would otherwise be rejected only AFTER a human
    // approves — a split-brain where the approver is told "approved" but the guarded
    // action is silently blocked. Runs before anything is delivered.
    assertDeliverable(intent, authority, webauthn);

    await adapter.deliver(intent);
    const resolution = await awaitWithDefault(intent, adapter.awaitResolution(intent), authority, webauthn);
    const decisive = resolution.countersignatures[resolution.countersignatures.length - 1];
    opts.onResolution?.(resolution);
    if (decisive) opts.onDecision?.(decisive);
    // Persist the receipts before acting: an approval we cannot remember is one
    // we decline to act on (fail-closed audit). Rejections are recorded too.
    if (opts.receiptLog) await opts.receiptLog.record(resolution);
    if (intent.callback) void postCallback(intent.callback, resolution);

    if (resolution.decision !== "approve") throw new IntentRejectedError(resolution, intent);
    return await fn(...args);
  };
}

/** True iff two WebAuthn policies are equivalent (allowed-origins as a SET —
 *  order- and duplicate-insensitive, so ["a","a"] does not match ["a","b"]). */
function samePolicy(a: WebAuthnPolicy, b: WebAuthnPolicy): boolean {
  const oa = new Set(a.allowedOrigins);
  const ob = new Set(b.allowedOrigins);
  return (
    a.rpId === b.rpId &&
    !!a.requireUserVerification === !!b.requireUserVerification &&
    oa.size === ob.size &&
    [...oa].every((o) => ob.has(o))
  );
}

/**
 * The single WebAuthn policy to sign AND verify passkey receipts with. The adapter's
 * signer (SigningServer) and this runtime's verifier (verifyResolution) must agree, or
 * an assertion the signer accepts is rejected at verification — a post-approval
 * split-brain. Use whichever policy is supplied; if BOTH are, they MUST be identical.
 */
function reconcileWebAuthn(fromOpts?: WebAuthnPolicy, fromAdapter?: WebAuthnPolicy): WebAuthnPolicy | undefined {
  if (fromOpts && fromAdapter && !samePolicy(fromOpts, fromAdapter))
    throw new CountersignError(
      "wrapAction: the `webauthn` policy in opts differs from the adapter's SigningServer policy — the signer and verifier must use the SAME policy (rpId, allowedOrigins, requireUserVerification), or a valid assertion would be rejected after approval",
    );
  return fromOpts ?? fromAdapter;
}

/**
 * Reject, at wrap time, an Intent+config combination that `awaitWithDefault` would
 * only reject AFTER delivery and human approval — turning a silent post-approval
 * failure (the approver sees "approved", the action never runs) into an immediate,
 * actionable error before anything is sent.
 */
function assertDeliverable(intent: Intent, authoritySecret: string, webauthn?: WebAuthnPolicy): void {
  const authorityPub = publicKeyFromSecret(authoritySecret);
  // Separation of duty: the authoring agent key must be distinct from the authority key.
  if (intent.agent?.public_key === authorityPub)
    throw new CountersignError(
      "wrapAction: the agent key must be distinct from the authority key — verifyResolution would reject this Intent only after approval",
    );
  for (const a of intent.approvers) {
    if (a.mode !== "keyed" || !a.public_key) continue;
    // A keyed slot bound to the authority key degrades separation of duty (the
    // authority-key holder could sign it): rejected post-approval, so refuse it now.
    if (credentialKeyMaterial(a.public_key) === authorityPub)
      throw new CountersignError(
        `wrapAction: keyed approver ${a.actor} is bound to the authority key — a keyed slot must be the approver's own key`,
      );
    // A passkey receipt can only be verified with a WebAuthn policy; without one it
    // would fail verification AFTER the approver signs (a false "approved").
    if (isWebAuthnCredential(a.public_key) && !webauthn)
      throw new CountersignError(
        `wrapAction: approver ${a.actor} is a passkey but no \`webauthn\` policy was supplied — pass { webauthn: { rpId, allowedOrigins } } (the same policy the SigningServer uses)`,
      );
  }
}

async function postCallback(url: string, resolution: Resolution): Promise<void> {
  try {
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(resolution),
    });
  } catch {
    // Callback delivery is best-effort; the receipts still exist locally.
  }
}
