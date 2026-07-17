// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// END-TO-END POLICY human-simulation harness. Unlike sim-e2e.ts (which hand-builds
// the Intent), this drives the FULL policy path a real deployment runs:
//   1. Enroll two PASSKEY approvers into an ApproverRegistry (with a WebAuthn
//      proof-of-possession, generated here from each credential's own key).
//   2. Build a signed PolicyLog: bootstrap admin -> role -> rule (quorum 2, keyed).
//   3. resolveRule(name) -> IntentFields, expanding the role into the enrolled
//      passkey approvers (and calling store.verify() — fail closed on a bad log).
//   4. wrapAction wraps a guarded action behind that resolved Intent, delivered
//      through SigningLinkAdapter; each approver taps their signing link and
//      confirms with their passkey in a real browser (the driver seeds a CDP
//      virtual authenticator with the printed keys).
//   5. verifyAll re-audits the receipt log after the action runs.
//
// Output protocol matches sim-e2e.ts (grep-friendly single-line JSON):
//   SIM_E2E  {origin, rpId, approvers:[{actor, credential, privateKeyPkcs8}]}
//   SIM_LINK {actor, url}
//   SIM_E2E_DONE {ok, result, actionRan, audit, viaPolicy:true}
// Exit codes: 0 = action ran AND audit ok; 1 = rejected/errored; 3 = ran but audit failed.
// Keys are EPHEMERAL (generated per run) — local simulation harness, not shipped.

import { createHash, createSign, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PendingDecisions } from "../src/adapter.js";
import { SigningServer } from "../src/signing.js";
import { SigningLinkAdapter } from "../src/adapters/signing-link.js";
import { wrapAction } from "../src/shim.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { IntentRejectedError } from "../src/core/errors.js";
import { ApproverRegistry, enrollmentChallenge, type PasskeyEnrollmentProof } from "../src/registry.js";
import { PolicyLog, resolveRule } from "../src/policy/index.js";
import { generateKeypair, publicKeyFromSecret, toB64url, utf8 } from "../src/core/keys.js";
import type { Intent } from "../src/core/types.js";

const resultPath = process.argv[2] ?? "/tmp/cs-sim-policy-result.json";
const timeoutSeconds = Number(process.argv[3] ?? 300);
const rpId = "localhost";

/** A fresh P-256 WebAuthn credential + its PKCS8 key for the virtual authenticator. */
function passkey(actor: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string; y?: string };
  const point = Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]);
  return { actor, credential: `webauthn-p256:${toB64url(point)}`, privateKey, privateKeyPkcs8: toB64url(privateKey.export({ format: "der", type: "pkcs8" }) as Buffer) };
}

/** Build a WebAuthn proof-of-possession for enrollment: an assertion over
 *  enrollmentChallenge(actor, credential), signed by the credential's own key. */
function enrollmentPoP(actor: string, credential: string, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], origin: string): PasskeyEnrollmentProof {
  const challenge = enrollmentChallenge(actor, credential);
  const rpIdHash = createHash("sha256").update(utf8(rpId)).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin }), "utf8");
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  const signature = toB64url(cryptoSign("sha256", signedData, privateKey));
  return { assertion: { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) }, signature, policy: { rpId, allowedOrigins: [origin] } };
}

const ceo = passkey("m:ceo");
const cto = passkey("m:cto");
const agent = { id: "agent:sim-policy", keypair: generateKeypair() };
const authority = generateKeypair(); // runtime authority (distinct from agent + org)
const orgRoot = generateKeypair(); // registry org-root (attests approver keys)
const admin = generateKeypair(); // policy-log admin key (attests rule/role changes)

const pending = new PendingDecisions();
const server = createServer();
server.listen(0, "127.0.0.1", () => {
  const port = (server.address() as AddressInfo).port;
  const origin = `http://localhost:${port}`;
  const policy = { rpId, allowedOrigins: [origin] };
  const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: policy, baseUrl: origin });
  server.on("request", signer.handler());

  // 1. Enroll both passkey approvers (org-root-attested, WebAuthn PoP).
  const registry = new ApproverRegistry();
  for (const p of [ceo, cto]) {
    registry.enroll(p.actor, p.credential, orgRoot.secretKey, { webauthnPop: enrollmentPoP(p.actor, p.credential, p.privateKey, origin) });
  }

  // 2. Build a signed PolicyLog: admin -> finance role -> prod-deploy rule.
  const org = "acme";
  const log = new PolicyLog();
  log.append({ kind: "admin-add", org, public_key: admin.publicKey, name: "root" }, admin.secretKey);
  log.append({ kind: "role-set", role: { id: "finance", org, name: "finance-approvers", members: ["m:ceo", "m:cto"] } }, admin.secretKey);
  log.append({ kind: "rule-set", rule: { id: "deploy", org, name: "prod-deploy", roles: ["finance"], quorum: 2, default: "reject", timeout_seconds: timeoutSeconds, action: "prod.deploy", risk_tier: "critical" } }, admin.secretKey);

  // 3. Resolve the named rule into IntentFields (verifies the log; fails closed if tampered).
  const fields = resolveRule("prod-deploy", { summary: "Policy sim: deploy 2.4.0 to production" }, { store: log, registry, org });

  const adapter = new SigningLinkAdapter({
    server: signer,
    notify: (l) => process.stdout.write("SIM_LINK " + JSON.stringify({ actor: l.actor, url: l.url }) + "\n"),
  });

  const receiptLog = new ReceiptLog(join(mkdtempSync(join(tmpdir(), "cs-sim-policy-")), "receipts.jsonl"));
  let captured: Intent | undefined;
  let actionRan = false;

  // 4. wrapAction behind the RESOLVED policy Intent.
  const deploy = wrapAction(() => { actionRan = true; return "deployed-2.4.0"; }, fields, adapter, {
    agent, authorityKey: authority.secretKey, receiptLog, onIntent: (i) => (captured = i),
  });

  process.stdout.write("SIM_E2E " + JSON.stringify({ origin, rpId, approvers: [ceo, cto].map((p) => ({ actor: p.actor, credential: p.credential, privateKeyPkcs8: p.privateKeyPkcs8 })) }) + "\n");
  // Sanity: prove each private key signs (so a failure is the flow, not a key mismatch).
  for (const p of [ceo, cto]) process.stdout.write(`SIM_KEYCHECK ${p.actor} signable=${createSign("SHA256").update(utf8("probe")).end().sign(p.privateKey).length > 0}\n`);

  deploy().then(
    async (result) => {
      const audit = await receiptLog.verifyAll({ intents: [captured!], authorityKey: publicKeyFromSecret(authority.secretKey), webauthn: policy });
      const out = { ok: true, viaPolicy: true, result, actionRan, audit: { ok: audit.ok, total: audit.total, valid: audit.valid, chainIntact: audit.chain.intact, faults: audit.faults } };
      writeFileSync(resultPath, JSON.stringify(out));
      process.stdout.write("SIM_E2E_DONE " + JSON.stringify(out) + "\n");
      server.close();
      process.exit(audit.ok && actionRan ? 0 : 3);
    },
    async (err) => {
      if (err instanceof IntentRejectedError) {
        const audit = await receiptLog.verifyAll({ intents: [captured!], authorityKey: publicKeyFromSecret(authority.secretKey), webauthn: policy });
        const out = { ok: false, viaPolicy: true, rejected: true, decision: err.resolution.decision, policy: err.resolution.policy, decisiveActor: err.countersignature?.actor, actionRan, audit: { ok: audit.ok, total: audit.total, valid: audit.valid, chainIntact: audit.chain.intact, faults: audit.faults } };
        writeFileSync(resultPath, JSON.stringify(out));
        process.stdout.write("SIM_E2E_DONE " + JSON.stringify(out) + "\n");
        server.close();
        process.exit(!actionRan && audit.ok ? 0 : 3);
      }
      const out = { ok: false, viaPolicy: true, actionRan, error: String(err) };
      writeFileSync(resultPath, JSON.stringify(out));
      process.stdout.write("SIM_E2E_DONE " + JSON.stringify(out) + "\n");
      server.close();
      process.exit(1);
    },
  );
});
