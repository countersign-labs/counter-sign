// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// Mint the FROZEN P-256 WebAuthn assertion constants embedded in gen-vectors.ts
// (P256_FROZEN). P-256 ECDSA signing is randomized, so the vector cannot be
// regenerated deterministically — instead it is minted ONCE here (the private key
// is discarded when the process exits) and gen-vectors re-verifies the frozen
// assertion on every run. Re-run this manually and paste the output into
// P256_FROZEN whenever the receipt recipe changes:
//
//   npx tsx scripts/mint-p256-vector.ts
//
// The fixture constants and the assertion recipe live in ./_passkey.ts, shared
// with gen-vectors.ts — nothing here can drift from the generator.

import { FIXED_DECIDED, P256_INTENT_ID, mintPasskeyReceipt, p256Credential } from "./_passkey.js";

const cred = p256Credential();
const receipt = mintPasskeyReceipt(P256_INTENT_ID, "approve", "m:cfo", cred.credential, FIXED_DECIDED, cred.sign);

process.stdout.write("Paste into gen-vectors.ts P256_FROZEN:\n" + JSON.stringify({
  credential: cred.credential,
  authenticator_data: receipt.webauthn!.authenticator_data,
  client_data_json: receipt.webauthn!.client_data_json,
  signature: receipt.signature,
}, null, 2) + "\n");
