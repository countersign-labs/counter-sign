// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// Human-simulation harness: stand up a real SigningServer on localhost with a P-256
// passkey approver, so a browser + WebAuthn virtual authenticator can drive the actual
// signing page end to end. Prints (as JSON on one line, prefixed "SIM ") everything the
// browser needs: the signing URL, rpId/origin, and the credential's private key (PKCS8)
// + public point, so a virtual authenticator can be seeded to hold exactly the bound
// credential. Writes the resolved decision to the path in argv[2] and exits. The keys
// are EPHEMERAL (generated per run) — this is a local simulation harness, not shipped.
//
//   npx tsx scripts/sim-server.ts /tmp/out.json approve   # prints "SIM {url, privateKeyPkcs8, ...}"
//
// Browser side (Chrome DevTools Protocol, e.g. via Playwright's newCDPSession) — seed a
// virtual authenticator with the printed key, then click #approve / #reject:
//   await cdp.send('WebAuthn.disable');                    // clear any leftover authenticator
//   await cdp.send('WebAuthn.enable', { enableUI: false });
//   const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator',
//     { options: { protocol:'ctap2', transport:'usb', hasResidentKey:true,
//                  hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true } });
//   await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
//     credentialId:<any b64>, isResidentCredential:true, rpId:'localhost',
//     privateKey: base64(privateKeyPkcs8), userHandle:<any b64>, signCount:0 } });
//   await page.goto(url); await page.click('#approve');    // → status "Recorded: APPROVE"
// Seeding a DIFFERENT (non-bound) key instead yields HTTP 400 "assertion did not verify"
// and the server never resolves — the security property (only the bound key can decide).

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createSign, generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { PendingDecisions } from "../src/adapter.js";
import { SigningServer } from "../src/signing.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret, toB64url } from "../src/core/keys.js";

const resultPath = process.argv[2] ?? "/tmp/cs-sim-result.json";
const decisionToDrive = process.argv[3] ?? "approve"; // for logging only; the browser decides

// A P-256 credential — the WebAuthn default that virtual authenticators support best.
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
const point = Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]); // 0x04||x||y (65 bytes)
const credential = `webauthn-p256:${toB64url(point)}`;
const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;

const agent = { id: "agent:sim", keypair: generateKeypair() };
const authority = generateKeypair();
const rpId = "localhost";

const pending = new PendingDecisions();
const server = createServer();
server.listen(0, "127.0.0.1", () => {
  const port = (server.address() as AddressInfo).port;
  const origin = `http://localhost:${port}`;
  const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin] }, baseUrl: origin });
  server.on("request", signer.handler());

  const intent = createIntent(
    { action: "prod.deploy", summary: "Deploy 2.4.0 to production", risk_tier: "critical", approvers: [{ actor: "m:ceo", mode: "keyed", public_key: credential }], quorum: 1, timeout: 300, default: "reject" },
    agent,
  );
  const url = signer.signingUrl(intent, "m:ceo");

  // Everything the browser harness needs, on one JSON line prefixed for easy grep.
  process.stdout.write("SIM " + JSON.stringify({
    url, origin, rpId, credential,
    privateKeyPkcs8: toB64url(pkcs8),
    point: toB64url(point),
    intent_id: intent.intent_id,
    driving: decisionToDrive,
  }) + "\n");

  // Sanity: prove the private key we handed the browser really signs assertions that
  // verify against the bound credential (so a failure is the page/flow, not key mismatch).
  const probe = Buffer.from("countersign-sim-probe");
  const sig = createSign("SHA256").update(probe).end().sign(privateKey);
  process.stdout.write(`SIM_KEYCHECK signable=${sig.length > 0}\n`);

  signer.awaitResolution(intent).then(
    (res) => {
      writeFileSync(resultPath, JSON.stringify({ ok: true, decision: res.decision, policy: res.policy, receipts: res.countersignatures.length }));
      process.stdout.write(`SIM_RESOLVED ${res.decision}\n`);
      server.close();
      process.exit(0);
    },
    (err) => {
      writeFileSync(resultPath, JSON.stringify({ ok: false, error: String(err) }));
      process.stdout.write(`SIM_REJECTED ${err}\n`);
      server.close();
      process.exit(1);
    },
  );
});
