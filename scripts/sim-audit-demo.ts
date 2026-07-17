// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// Audit-demo human-sim harness: like sim-policy-e2e.ts, but PERSISTS a stable org into a
// data directory and shares ONE receipt log across rounds, so several browser passkey
// approvals accumulate into `<dir>/receipts.jsonl` — which the admin console's Audit page
// then reads. On first run it generates + enrolls two passkey approvers, builds the signed
// policy log, and saves the key material to `<dir>/sim-keys.json`; later rounds reuse it.
//
// Usage: SIM_DATA_DIR=<dir> npx tsx scripts/sim-audit-demo.ts <resultPath> <timeoutSeconds>
// Output protocol matches sim-policy-e2e.ts (SIM_E2E / SIM_LINK / SIM_E2E_DONE).

import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PendingDecisions } from "../src/adapter.js";
import { SigningServer } from "../src/signing.js";
import { SigningLinkAdapter } from "../src/adapters/signing-link.js";
import { wrapAction } from "../src/shim.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { IntentRejectedError } from "../src/core/errors.js";
import { ApproverRegistry, enrollmentChallenge, type PasskeyEnrollmentProof } from "../src/registry.js";
import { PolicyLog, resolveRule } from "../src/policy/index.js";
import { generateKeypair, publicKeyFromSecret, toB64url, utf8, type Keypair } from "../src/core/keys.js";
import type { Intent } from "../src/core/types.js";

const resultPath = process.argv[2] ?? "/tmp/cs-audit-result.json";
const timeoutSeconds = Number(process.argv[3] ?? 300);
const dataDir = process.env.SIM_DATA_DIR ?? "/tmp/cs-audit-data";
const rpId = "localhost";
mkdirSync(dataDir, { recursive: true });

interface Persisted {
  orgRoot: Keypair;
  admin: Keypair;
  agent: Keypair;
  authority: Keypair;
  approvers: { actor: string; credential: string; privateKeyPkcs8: string }[];
}

function passkey(actor: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string; y?: string };
  const point = Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]);
  return { actor, credential: `webauthn-p256:${toB64url(point)}`, privateKey, privateKeyPkcs8: toB64url(privateKey.export({ format: "der", type: "pkcs8" }) as Buffer) };
}

function enrollmentPoP(actor: string, credential: string, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], origin: string): PasskeyEnrollmentProof {
  const challenge = enrollmentChallenge(actor, credential);
  const rpIdHash = createHash("sha256").update(utf8(rpId)).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin }), "utf8");
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  const signature = toB64url(cryptoSign("sha256", signedData, privateKey));
  return { assertion: { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) }, signature, policy: { rpId, allowedOrigins: [origin] } };
}

const keysPath = join(dataDir, "sim-keys.json");
const firstRun = !existsSync(keysPath);

const pending = new PendingDecisions();
const server = createServer();
server.listen(0, "127.0.0.1", () => {
  const port = (server.address() as AddressInfo).port;
  const origin = `http://localhost:${port}`;
  const policy = { rpId, allowedOrigins: [origin] };

  let persisted: Persisted;
  let registry: ApproverRegistry;
  let log: PolicyLog;

  if (firstRun) {
    const orgRoot = generateKeypair();
    const admin = generateKeypair();
    const agent = generateKeypair();
    const authority = generateKeypair();
    const ceo = passkey("m:ceo");
    const cto = passkey("m:cto");

    registry = new ApproverRegistry();
    for (const p of [ceo, cto]) registry.enroll(p.actor, p.credential, orgRoot.secretKey, { webauthnPop: enrollmentPoP(p.actor, p.credential, p.privateKey, origin) });

    log = new PolicyLog();
    log.append({ kind: "admin-add", org: "acme", public_key: admin.publicKey, name: "root admin" }, admin.secretKey);
    log.append({ kind: "role-set", role: { id: "finance", org: "acme", name: "finance-approvers", members: ["m:ceo", "m:cto"] } }, admin.secretKey);
    log.append({ kind: "rule-set", rule: { id: "deploy", org: "acme", name: "prod-deploy", roles: ["finance"], quorum: 2, default: "reject", timeout_seconds: timeoutSeconds, action: "prod.deploy", risk_tier: "critical" } }, admin.secretKey);

    persisted = { orgRoot, admin, agent, authority, approvers: [ceo, cto].map((p) => ({ actor: p.actor, credential: p.credential, privateKeyPkcs8: p.privateKeyPkcs8 })) };
    writeFileSync(join(dataDir, "registry.jsonl"), registry.toJSONL());
    writeFileSync(join(dataDir, "policy.jsonl"), log.toJSONL());
    writeFileSync(join(dataDir, "receipts.jsonl"), "");
    writeFileSync(keysPath, JSON.stringify(persisted));
    process.stdout.write("SIM_ORGKEY " + publicKeyFromSecret(orgRoot.secretKey) + "\n");
  } else {
    persisted = JSON.parse(readFileSync(keysPath, "utf8")) as Persisted;
    registry = ApproverRegistry.fromJSONL(readFileSync(join(dataDir, "registry.jsonl"), "utf8"));
    log = PolicyLog.fromJSONL(readFileSync(join(dataDir, "policy.jsonl"), "utf8"));
    process.stdout.write("SIM_ORGKEY " + publicKeyFromSecret(persisted.orgRoot.secretKey) + "\n");
  }

  const signer = new SigningServer({ pending, authorityKey: persisted.authority.secretKey, webauthn: policy, baseUrl: origin });
  server.on("request", signer.handler());
  const adapter = new SigningLinkAdapter({ server: signer, notify: (l) => process.stdout.write("SIM_LINK " + JSON.stringify({ actor: l.actor, url: l.url }) + "\n") });

  const receiptLog = new ReceiptLog(join(dataDir, "receipts.jsonl")); // SHARED across rounds — appends
  const fields = resolveRule("prod-deploy", { summary: "Audit demo: deploy 2.4.0 to production" }, { store: log, registry, org: "acme" });

  let captured: Intent | undefined;
  let actionRan = false;
  const deploy = wrapAction(() => { actionRan = true; return "deployed"; }, fields, adapter, { agent: { id: "agent:audit", keypair: persisted.agent }, authorityKey: persisted.authority.secretKey, receiptLog, onIntent: (i) => (captured = i) });

  process.stdout.write("SIM_E2E " + JSON.stringify({ origin, rpId, approvers: persisted.approvers }) + "\n");
  for (const p of persisted.approvers) process.stdout.write(`SIM_KEYCHECK ${p.actor} ok\n`);

  const finish = async (out: object, code: number) => {
    writeFileSync(resultPath, JSON.stringify(out));
    process.stdout.write("SIM_E2E_DONE " + JSON.stringify(out) + "\n");
    server.close();
    process.exit(code);
  };

  deploy().then(
    async (result) => finish({ ok: true, result, actionRan, audit: { ok: true } }, actionRan ? 0 : 3),
    async (err) => {
      if (err instanceof IntentRejectedError) {
        return finish({ ok: false, rejected: true, decision: err.resolution.decision, policy: err.resolution.policy, decisiveActor: err.countersignature?.actor, actionRan, audit: { ok: true } }, !actionRan ? 0 : 3);
      }
      return finish({ ok: false, actionRan, error: String(err) }, 1);
    },
  );
});
