// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// CONFORMANCE SUITE. Re-verifies the reference implementation against the COMMITTED, language-neutral
// test vectors in vectors/countersign-vectors.json (produced by `npm run gen:vectors`). A change to
// canonicalization or signing that would break cross-implementation interop shows up here as a failing
// test + a reviewable vector diff, instead of a silent wire-format drift. Any independent implementation
// (in any language) can consume the same vectors — see vectors/README.md.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/core/canonical.js";
import { fromB64url, publicKeyFromSecret, signContext, verifyContext, toB64url, utf8 } from "../src/core/keys.js";
import { verifyIntent } from "../src/core/intent.js";
import { verifyCountersignature } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { ReceiptLog } from "../src/receipt-log.js";
import type { WebAuthnPolicy } from "../src/core/webauthn.js";
import type { Countersignature, Intent, Resolution } from "../src/core/types.js";

const V = JSON.parse(readFileSync(join(__dirname, "..", "vectors", "countersign-vectors.json"), "utf8"));

describe("conformance vectors", () => {
  it("declares the v0.2 wire version", () => {
    expect(V.version).toBe("0.2");
  });

  describe("canonical JSON", () => {
    for (const c of V.canonical) {
      it(`canonicalizes ${c.name} byte-for-byte`, () => {
        expect(canonicalize(c.value)).toBe(c.canonical);
      });
    }

    // The `undefined-omitted` vector cannot round-trip through JSON — JSON.stringify
    // drops a `b: undefined` member, so the committed vector's `value` is `{a,c}` and
    // the loop above never actually exercises omission of a PRESENT undefined member
    // (a JS-only concept no cross-language vector can carry). Assert that behavior here
    // in memory against the shipped known-answer, so the claim "undefined members
    // omitted" is genuinely tested.
    it("omits a present-but-undefined member (JS-only, against the shipped known-answer)", () => {
      const known = V.canonical.find((c: { name: string }) => c.name === "undefined-omitted");
      expect(canonicalize({ a: 1, b: undefined, c: 3 })).toBe(known.canonical);
      expect(known.canonical).toBe('{"a":1,"c":3}');
    });
  });

  describe("key derivation", () => {
    for (const k of V.keys) {
      it(`derives the public key for ${k.name}`, () => {
        expect(publicKeyFromSecret(k.secret)).toBe(k.public);
      });
    }
  });

  describe("domain-separated signing (signContext)", () => {
    for (const s of V.signing) {
      it(`reproduces the signed message + signature for ${s.name}`, () => {
        // The exact pre-hash bytes another implementation must reproduce…
        expect(toB64url(utf8(`${s.context}\n${s.canonical}`))).toBe(s.message_base64url);
        // …the deterministic ed25519 signature over them…
        expect(signContext(s.secret_key, s.context, s.canonical)).toBe(s.signature);
        // …and that the verifier accepts it.
        expect(verifyContext(s.public_key, s.context, s.canonical, s.signature)).toBe(true);
      });
    }
  });

  describe("Intents", () => {
    for (const iv of V.intents) {
      it(`${iv.name} → verifyIntent === ${iv.valid}`, () => {
        const { signature: _s, ...unsigned } = iv.intent as Intent & { signature: string };
        expect(canonicalize(unsigned)).toBe(iv.canonical_unsigned);
        expect(verifyIntent(iv.intent as Intent)).toBe(iv.valid);
      });
    }
  });

  describe("Countersignatures (receipts)", () => {
    for (const c of V.countersignatures) {
      it(`${c.name} → verifies against its signer key === ${c.valid}`, () => {
        expect(verifyCountersignature(c.receipt, { trustedKeys: [c.signer_public_key] })).toBe(c.valid);
      });
    }
  });

  describe("Resolutions (verifyResolution)", () => {
    for (const r of V.resolutions) {
      it(`${r.name} → ${r.expect}`, () => {
        const run = () => verifyResolution(r.intent as Intent, r.resolution as Resolution, r.expected_authority_public_key);
        if (r.expect === "valid") expect(run).not.toThrow();
        else expect(run).toThrow();
      });
    }
  });

  describe("WebAuthn passkey receipts", () => {
    it("ships a webauthn vector section — receipts + resolutions, each carrying its RP policy", () => {
      expect(V.webauthn).toBeDefined();
      expect(V.webauthn.receipts.length).toBeGreaterThan(0);
      expect(V.webauthn.resolutions.length).toBeGreaterThan(0);
      // Every case declares the policy to verify under (an object, or null = no policy).
      for (const c of [...V.webauthn.receipts, ...V.webauthn.resolutions]) expect(c.policy !== undefined).toBe(true);
    });

    it("recomputes the assertion challenge from the canonical unsigned receipt (known answer)", () => {
      const c = V.webauthn.receipts.find((r: { name: string }) => r.name === "ed25519-approve-ceo");
      const { signature: _s, webauthn: _w, ...unsigned } = c.receipt;
      const challenge = toB64url(
        createHash("sha256").update(utf8(`${V.algorithm.contexts.countersignature}\n${canonicalize(unsigned)}`)).digest(),
      );
      const clientData = JSON.parse(fromB64url(c.receipt.webauthn.client_data_json).toString("utf8"));
      expect(clientData.challenge).toBe(challenge);
    });

    for (const c of V.webauthn.receipts as { name: string; valid: boolean; policy: WebAuthnPolicy | null; receipt: Countersignature }[]) {
      it(`${c.name} → verifyCountersignature === ${c.valid}`, () => {
        // `policy: null` encodes the fail-closed case: a passkey receipt without an RP policy must not verify.
        expect(verifyCountersignature(c.receipt, { trustedKeys: [c.receipt.public_key], webauthn: c.policy ?? undefined })).toBe(c.valid);
      });
    }

    for (const r of V.webauthn.resolutions as { name: string; expect: string; policy: WebAuthnPolicy | null; expected_authority_public_key: string; intent: Intent; resolution: Resolution }[]) {
      it(`${r.name} → ${r.expect}`, () => {
        const run = () => verifyResolution(r.intent, r.resolution, r.expected_authority_public_key, r.policy ?? undefined);
        if (r.expect === "valid") expect(run).not.toThrow();
        else expect(run).toThrow();
      });
    }
  });

  describe("ReceiptLog hash chain", () => {
    it("an empty log's head is the versioned genesis anchor", async () => {
      const log = new ReceiptLog(join(mkdtempSync(join(tmpdir(), "cs-conf-")), "empty.jsonl"));
      const head = await log.head();
      expect(head).toEqual({ length: 0, hash: V.algorithm.receipt_chain.genesis_prev });
    });

    it("reproduces the frozen chain head over the vector's receipts", async () => {
      const log = new ReceiptLog(join(mkdtempSync(join(tmpdir(), "cs-conf-")), "chain.jsonl"));
      for (const r of V.chain.receipts) await log.append(r);
      expect(await log.head()).toEqual(V.chain.expected_head);
      expect(await log.verifyChain()).toMatchObject({ intact: true, length: V.chain.receipts.length });
    });
  });
});
