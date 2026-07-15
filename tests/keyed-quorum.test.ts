// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Phase 1 per-approver-key quorum: keyed receipts verify against each approver's
// OWN bound key, so a compromised authority server cannot forge a quorum. Full
// positive + negative matrix at the verifyResolution boundary, plus the CLI signer.

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret, type Keypair } from "../src/core/keys.js";
import type { Approver, Intent, Resolution } from "../src/core/types.js";

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
    ).toThrow(/more than one approver/);
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
