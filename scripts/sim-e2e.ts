// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// FULL-WORKFLOW human-simulation harness: unlike sim-server.ts (which drives the
// SigningServer surface alone), this exercises the ENTIRE v0.2 path a real
// deployment runs — wrapAction wraps a guarded action behind a 2-of-2 PASSKEY
// quorum delivered through SigningLinkAdapter; each approver taps their own
// signing link in a real browser and confirms with a WebAuthn credential; the
// resolution is verified (verifyResolution via awaitWithDefault), recorded to a
// ReceiptLog BEFORE the action runs, the guarded action executes, and finally the
// log is re-audited with verifyAll({intents, authorityKey, webauthn}).
//
// Output protocol (single-line JSON, grep-friendly):
//   SIM_E2E  {origin, rpId, approvers:[{actor, credential, privateKeyPkcs8}]}   once listening
//   SIM_LINK {actor, url}                                                       per approver at delivery
//   SIM_E2E_DONE {ok, result, actionRan, audit}                                 at the end (also argv[2] file)
// Exit codes: 0 = action ran AND audit ok; 1 = resolution rejected/errored; 3 = ran but audit failed.
// Keys are EPHEMERAL (generated per run) — local simulation harness, not shipped.

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PendingDecisions } from "../src/adapter.js";
import { SigningServer } from "../src/signing.js";
import { SigningLinkAdapter } from "../src/adapters/signing-link.js";
import { wrapAction } from "../src/shim.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { generateKeypair, publicKeyFromSecret, toB64url } from "../src/core/keys.js";
import type { Intent } from "../src/core/types.js";

const resultPath = process.argv[2] ?? "/tmp/cs-sim-e2e-result.json";

/** A fresh P-256 WebAuthn credential + its PKCS8 key for the virtual authenticator. */
function passkey(actor: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string; y?: string };
  const point = Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]);
  return {
    actor,
    credential: `webauthn-p256:${toB64url(point)}`,
    privateKeyPkcs8: toB64url(privateKey.export({ format: "der", type: "pkcs8" }) as Buffer),
  };
}

const ceo = passkey("m:ceo");
const cto = passkey("m:cto");
const agent = { id: "agent:sim-e2e", keypair: generateKeypair() };
const authority = generateKeypair(); // distinct from the agent key (SoD)
const rpId = "localhost";

const pending = new PendingDecisions();
const server = createServer();
server.listen(0, "127.0.0.1", () => {
  const port = (server.address() as AddressInfo).port;
  const origin = `http://localhost:${port}`;
  const policy = { rpId, allowedOrigins: [origin] };
  const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: policy, baseUrl: origin });
  server.on("request", signer.handler());

  const adapter = new SigningLinkAdapter({
    server: signer,
    // "Deliver" each signing link by printing it — the browser harness picks it up.
    notify: (l) => process.stdout.write("SIM_LINK " + JSON.stringify({ actor: l.actor, url: l.url }) + "\n"),
  });

  const log = new ReceiptLog(join(mkdtempSync(join(tmpdir(), "cs-sim-e2e-")), "receipts.jsonl"));
  let captured: Intent | undefined;
  let actionRan = false;

  const deploy = wrapAction(
    () => {
      actionRan = true;
      return "deployed-2.4.0";
    },
    {
      action: "prod.deploy",
      summary: "Sim E2E: deploy 2.4.0 to production",
      risk_tier: "critical",
      approvers: [
        { actor: ceo.actor, mode: "keyed", public_key: ceo.credential },
        { actor: cto.actor, mode: "keyed", public_key: cto.credential },
      ],
      quorum: 2,
      timeout: 300,
      default: "reject",
    },
    adapter,
    { agent, authorityKey: authority.secretKey, receiptLog: log, onIntent: (i) => (captured = i) },
    // NOTE: no opts.webauthn — wrapAction must pick up the adapter's policy (reconcileWebAuthn).
  );

  process.stdout.write(
    "SIM_E2E " + JSON.stringify({ origin, rpId, approvers: [ceo, cto] }) + "\n",
  );

  deploy().then(
    async (result) => {
      // The action ran — now the AUDIT leg: re-verify the persisted receipts end to end.
      const audit = await log.verifyAll({ intents: [captured!], authorityKey: publicKeyFromSecret(authority.secretKey), webauthn: policy });
      const out = {
        ok: true,
        result,
        actionRan,
        audit: { ok: audit.ok, total: audit.total, valid: audit.valid, chainIntact: audit.chain.intact, faults: audit.faults },
      };
      writeFileSync(resultPath, JSON.stringify(out));
      process.stdout.write("SIM_E2E_DONE " + JSON.stringify(out) + "\n");
      server.close();
      process.exit(audit.ok && actionRan ? 0 : 3);
    },
    (err) => {
      const out = { ok: false, actionRan, error: String(err) };
      writeFileSync(resultPath, JSON.stringify(out));
      process.stdout.write("SIM_E2E_DONE " + JSON.stringify(out) + "\n");
      server.close();
      process.exit(1);
    },
  );
});
