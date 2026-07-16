// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Phase 1 per-approver-key quorum: keyed receipts verify against each approver's
// OWN bound key, so a compromised authority server cannot forge a quorum. Full
// positive + negative matrix at the verifyResolution boundary, plus the CLI signer.

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/core/canonical.js";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { assertIntentInvariants, createIntent } from "../src/core/intent.js";
import { LocalAdapter } from "../src/adapters/local.js";
import { fromB64url, generateKeypair, publicKeyFromSecret, signContext, type Keypair } from "../src/core/keys.js";
import { INTENT_CONTEXT, type Approver, type Intent, type Resolution } from "../src/core/types.js";

/** A DIFFERENT base64url string that decodes to the same 32 bytes as `key` (non-canonical). */
function nonCanonicalAlias(key: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const bytes = fromB64url(key);
  for (const c of alphabet) {
    const cand = key.slice(0, -1) + c;
    if (cand !== key && fromB64url(cand).length === 32 && fromB64url(cand).equals(bytes)) return cand;
  }
  return "";
}

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const authPub = publicKeyFromSecret(authority.secretKey);

const alice = generateKeypair();
const bob = generateKeypair();
const keyed = (actor: string, kp: Keypair): Approver => ({ actor, mode: "keyed", public_key: kp.publicKey });

function keyedIntent(quorum = 2, over: Record<string, unknown> = {}): Intent {
  return createIntent(
    {
      action: "prod.deploy",
      summary: "Deploy 2.4.0",
      risk_tier: "critical",
      approvers: [keyed("m:alice", alice), keyed("m:bob", bob)],
      quorum,
      timeout: 300,
      default: "reject",
      ...over,
    },
    agent,
  );
}

function res(decision: "approve" | "reject", css: Resolution["countersignatures"]): Resolution {
  return { decision, policy: "approver", countersignatures: css };
}

describe("keyed quorum — positive", () => {
  it("a 2-of-2 signed by each approver's OWN key verifies", () => {
    const i = keyedIntent(2);
    const r = res("approve", [
      signDecision(i, "approve", "m:alice", alice.secretKey, "approver"),
      signDecision(i, "approve", "m:bob", bob.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(i, r, authPub)).not.toThrow();
  });

  it("a vouched-only adapter REFUSES a keyed intent (would otherwise auto-approve on timeout)", async () => {
    // A quorum-1 keyed intent on a button/link adapter: the approver's input can't
    // reach the quorum via settle(), so a default:approve would fire unopposed. The
    // adapter must refuse it at deliver() instead.
    const i = keyedIntent(1);
    const local = new LocalAdapter(authority.secretKey);
    await expect(local.deliver(i)).rejects.toThrow(/keyed approver/);
  });

  it("a single keyed approver's veto is a complete reject", () => {
    const i = keyedIntent(2);
    const r = res("reject", [signDecision(i, "reject", "m:bob", bob.secretKey, "approver")]);
    expect(() => verifyResolution(i, r, authPub)).not.toThrow();
  });

  it("a keyed single-approver (quorum 1) verifies against the approver key, not the authority", () => {
    const i = keyedIntent(1);
    const r = res("approve", [signDecision(i, "approve", "m:alice", alice.secretKey, "approver")]);
    expect(() => verifyResolution(i, r, authPub)).not.toThrow();
  });
});

describe("keyed quorum — negative (a compromised authority key cannot forge it)", () => {
  it("HEADLINE: two AUTHORITY-signed receipts cannot satisfy a keyed 2-of-2", () => {
    const i = keyedIntent(2);
    const forged = res("approve", [
      signDecision(i, "approve", "m:alice", authority.secretKey, "approver"),
      signDecision(i, "approve", "m:bob", authority.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(i, forged, authPub)).toThrow(/not signed by the expected key/);
  });

  it("rejects a keyed slot signed by the WRONG approver's key (bob signing alice's slot)", () => {
    const i = keyedIntent(2);
    const forged = res("approve", [
      signDecision(i, "approve", "m:alice", bob.secretKey, "approver"), // bob's key for alice's slot
      signDecision(i, "approve", "m:bob", bob.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("rejects a receipt signed by a stranger key not bound to any approver", () => {
    const i = keyedIntent(2);
    const stranger = generateKeypair();
    const forged = res("approve", [
      signDecision(i, "approve", "m:alice", alice.secretKey, "approver"),
      signDecision(i, "approve", "m:bob", stranger.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("one keyed approver cannot fill a 2-of-2 alone (same key, two actor strings)", () => {
    const i = keyedIntent(2);
    // alice signs her own slot AND forges an 'm:bob' actor with HER key — the bob
    // slot needs bob's key, so it fails; and distinctness would fail anyway.
    const forged = res("approve", [
      signDecision(i, "approve", "m:alice", alice.secretKey, "approver"),
      signDecision(i, "approve", "m:bob", alice.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(i, forged, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("rejects a non-canonical base64url key twin (one key cannot fill two slots via encodings)", () => {
    // Find a DIFFERENT base64url string that decodes to the SAME 32-byte key.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const bytes = fromB64url(alice.publicKey);
    let twin = "";
    for (const c of alphabet) {
      const cand = alice.publicKey.slice(0, -1) + c;
      if (cand !== alice.publicKey && fromB64url(cand).length === 32 && fromB64url(cand).equals(bytes)) { twin = cand; break; }
    }
    expect(twin).not.toBe("");
    expect(twin).not.toBe(alice.publicKey);
    // A non-canonical key is refused outright, so it cannot be bound as a second
    // "distinct" approver sharing alice's underlying key.
    expect(() =>
      createIntent(
        { action: "a", summary: "s", risk_tier: "low",
          approvers: [keyed("m:alice", alice), { actor: "m:bob", mode: "keyed", public_key: twin }],
          quorum: 2, timeout: 60, default: "reject" },
        agent,
      ),
    ).toThrow(/non-canonical/);
  });

  it("rejects a keyed approver bound to the AUTHORITY key (would degrade separation of duty)", () => {
    const i = createIntent(
      { action: "a", summary: "s", risk_tier: "low", approvers: [{ actor: "m:alice", mode: "keyed", public_key: authPub }], quorum: 1, timeout: 60, default: "reject" },
      agent,
    );
    const r = res("approve", [signDecision(i, "approve", "m:alice", authority.secretKey, "approver")]);
    expect(() => verifyResolution(i, r, authPub)).toThrow(/authority key/);
  });

  it("rejects the authority key WRAPPED as a webauthn-ed25519 descriptor (sees through the wrapper)", () => {
    const i = createIntent(
      { action: "a", summary: "s", risk_tier: "low", approvers: [{ actor: "m:alice", mode: "keyed", public_key: `webauthn-ed25519:${authPub}` }], quorum: 1, timeout: 60, default: "reject" },
      agent,
    );
    const r = res("approve", [signDecision(i, "approve", "m:alice", authority.secretKey, "approver")]);
    expect(() => verifyResolution(i, r, authPub)).toThrow(/authority key/);
  });

  it("refuses one key material across a raw-keyed AND a passkey slot (cross-encoding twin)", () => {
    // The raw ed25519 key K and the passkey descriptor webauthn-ed25519:K are the
    // SAME key — one holder could satisfy both, so they must not be two slots.
    expect(() =>
      createIntent(
        { action: "a", summary: "s", risk_tier: "low",
          approvers: [keyed("m:alice", alice), { actor: "m:bob", mode: "keyed", public_key: `webauthn-ed25519:${alice.publicKey}` }],
          quorum: 2, timeout: 60, default: "reject" },
        agent,
      ),
    ).toThrow(/shares key material/);
  });

  it("rejects a resolution whose Intent was AUTHORED by the authority key (agent == authority)", () => {
    // If the agent key that signs Intents is the authority key, a holder of that
    // one secret mints an Intent binding approver keys it controls and signs every
    // slot — a full quorum forge. verifyResolution has both keys and must refuse.
    const i = createIntent(
      { action: "prod.deploy", summary: "s", risk_tier: "critical",
        approvers: [keyed("m:alice", alice), keyed("m:bob", bob)], quorum: 2, timeout: 300, default: "reject" },
      { id: "agent:evil", keypair: authority }, // agent keypair == authority keypair
    );
    const r = res("approve", [
      signDecision(i, "approve", "m:alice", alice.secretKey, "approver"),
      signDecision(i, "approve", "m:bob", bob.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(i, r, authPub)).toThrow(/agent and .*authority keys must be distinct|authored by the authority key/);
  });

  it("HEADLINE: a non-canonical agent-key ALIAS of the authority cannot forge a keyed quorum", () => {
    // The forge the keyed design must block: a holder of ONLY the authority key emits
    // a non-canonical alias of its own public key (same 32 bytes, different string),
    // authors an Intent under it (agent == authority in disguise, dodging the raw
    // string compare), binds TWO attacker-generated approver keys, and signs both
    // receipts. Without a canonicality gate on the agent key this passed; it must not.
    const alias = nonCanonicalAlias(authPub);
    expect(alias).not.toBe("");
    const unsigned = {
      countersign: "0.2" as const,
      intent_id: randomUUID(),
      agent: { id: "agent:evil", public_key: alias },
      action: "prod.deploy",
      summary: "s",
      risk_tier: "critical" as const,
      approvers: [keyed("m:alice", alice), keyed("m:bob", bob)],
      quorum: 2,
      timeout: 300,
      default: "reject" as const,
      callback: null,
      created_at: new Date().toISOString(),
    };
    const signature = signContext(authority.secretKey, INTENT_CONTEXT, canonicalize(unsigned));
    const forged = { ...unsigned, signature } as unknown as Intent;
    const r = res("approve", [
      signDecision(forged, "approve", "m:alice", alice.secretKey, "approver"),
      signDecision(forged, "approve", "m:bob", bob.secretKey, "approver"),
    ]);
    expect(() => verifyResolution(forged, r, authPub)).toThrow(/canonical/);
  });

  it("assertIntentInvariants rejects a non-canonical agent public key", () => {
    const i = keyedIntent(2);
    const alias = nonCanonicalAlias(i.agent.public_key);
    expect(alias).not.toBe("");
    expect(() => assertIntentInvariants({ ...i, agent: { ...i.agent, public_key: alias } })).toThrow(/canonical/);
  });

  it("rejects a non-canonical expected authority public key (alias bypass)", () => {
    const i = keyedIntent(2);
    const r = res("approve", [
      signDecision(i, "approve", "m:alice", alice.secretKey, "approver"),
      signDecision(i, "approve", "m:bob", bob.secretKey, "approver"),
    ]);
    // A base64url alias of authPub that decodes to the same key but is non-canonical.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const bytes = fromB64url(authPub);
    let twin = "";
    for (const c of alphabet) {
      const cand = authPub.slice(0, -1) + c;
      if (cand !== authPub && fromB64url(cand).length === 32 && fromB64url(cand).equals(bytes)) { twin = cand; break; }
    }
    expect(twin).not.toBe("");
    expect(() => verifyResolution(i, r, twin)).toThrow(/canonical/);
  });

  it("refuses two approvers that normalize to the same actor", () => {
    expect(() =>
      createIntent(
        { action: "a", summary: "s", risk_tier: "low",
          approvers: [keyed("m:alice", alice), keyed("m:Alice ", bob)], // same normalized actor
          quorum: 2, timeout: 60, default: "reject" },
        agent,
      ),
    ).toThrow(/listed more than once/);
  });

  it("createIntent refuses a keyed approver without a key, and duplicate keyed keys", () => {
    expect(() =>
      createIntent(
        { action: "a", summary: "s", risk_tier: "low", approvers: [{ actor: "m:x", mode: "keyed" }], timeout: 60, default: "reject" },
        agent,
      ),
    ).toThrow(/must carry a public_key/);
    expect(() =>
      createIntent(
        {
          action: "a", summary: "s", risk_tier: "low",
          approvers: [keyed("m:x", alice), keyed("m:y", alice)], // same key, two actors
          quorum: 2, timeout: 60, default: "reject",
        },
        agent,
      ),
    ).toThrow(/shares key material/);
  });
});

describe("the approve CLI signs a keyed receipt with the approver's key", () => {
  it("produces a receipt that verifies as a keyed approval, and refuses a wrong key", () => {
    const i = keyedIntent(2);
    const dir = mkdtempSync(join(tmpdir(), "cs-approve-"));
    const intentPath = join(dir, "intent.json");
    writeFileSync(intentPath, JSON.stringify(i));

    const out = execFileSync(
      "npx",
      ["tsx", "scripts/approve.ts", "--intent", intentPath, "--actor", "m:alice", "--decision", "approve", "--key", alice.secretKey],
      { encoding: "utf8" },
    );
    const receipt = JSON.parse(out);
    expect(receipt.public_key).toBe(alice.publicKey);
    const r = res("approve", [receipt, signDecision(i, "approve", "m:bob", bob.secretKey, "approver")]);
    expect(() => verifyResolution(i, r, authPub)).not.toThrow();

    // Signing m:alice's slot with bob's key is refused by the CLI (exit != 0).
    expect(() =>
      execFileSync(
        "npx",
        ["tsx", "scripts/approve.ts", "--intent", intentPath, "--actor", "m:alice", "--decision", "approve", "--key", bob.secretKey],
        { encoding: "utf8", stdio: "pipe" },
      ),
    ).toThrow();
  });
});
