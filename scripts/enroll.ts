// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// countersign enroll — append an org-root-attested enrollment (or revocation) to
// an approver registry (JSONL). Binds a keyed approver's key to their actor so a
// verifier can require registry-anchored identities (assertApproversEnrolled).
//
//   # enroll a raw ed25519 approver (proves possession from their secret):
//   tsx scripts/enroll.ts --registry reg.jsonl --actor slack:U024BE7LH \
//       --approver-key <approver-secret> --org-key <org-root-secret>
//
//   # enroll a passkey approver (descriptor from a WebAuthn registration): requires
//   # a WebAuthn proof of possession (assertion over enrollmentChallenge(actor,key)):
//   tsx scripts/enroll.ts --registry reg.jsonl --actor slack:U024BE7LH \
//       --public-key webauthn-p256:<...> --org-key <org-root-secret> \
//       --webauthn-pop pop.json --rp-id approve.example.com --origin https://approve.example.com
//
//   # revoke (key rotation / offboarding):
//   tsx scripts/enroll.ts --registry reg.jsonl --actor slack:U024BE7LH \
//       --public-key <key> --org-key <org-root-secret> --revoke

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { ApproverRegistry, createEnrollmentProof, type PasskeyEnrollmentProof } from "../src/registry.js";
import { isWebAuthnCredential } from "../src/core/webauthn.js";
import { publicKeyFromSecret } from "../src/core/keys.js";
import { arg, has, die } from "./_args.js";

const registryPath = arg("registry");
const actor = arg("actor");
const orgKey = arg("org-key");
const approverKey = arg("approver-key");
const publicKeyArg = arg("public-key");

if (!registryPath || !actor || !orgKey) die("usage: enroll --registry <file> --actor <actor> (--approver-key <secret>|--public-key <key>) --org-key <org-secret> [--revoke]", 2);

let registry: ApproverRegistry;
try {
  registry = existsSync(registryPath!) ? ApproverRegistry.fromJSONL(readFileSync(registryPath!, "utf8")) : new ApproverRegistry();
} catch (e) {
  die(`could not load registry at ${registryPath}: ${(e as Error).message}`, 2);
}

// Never append to a registry that does not verify under the supplied org key —
// otherwise a wrong --org-key silently produces a mixed-root, unverifiable file.
let orgPub: string;
try {
  orgPub = publicKeyFromSecret(orgKey!);
} catch {
  die("--org-key is not a valid ed25519 secret key", 2);
}
if (registry.all.length > 0 && !registry.verifyChain(orgPub))
  die(`existing registry at ${registryPath} does not verify under the supplied --org-key (wrong org key, or the file was tampered) — refusing to write`, 2);

let publicKey: string;
let pop: string | undefined;
let webauthnPop: PasskeyEnrollmentProof | undefined;
if (approverKey) {
  try {
    publicKey = publicKeyFromSecret(approverKey);
    pop = createEnrollmentProof(actor!, approverKey);
  } catch {
    die("--approver-key is not a valid ed25519 secret key", 2);
  }
} else if (publicKeyArg) {
  publicKey = publicKeyArg;
  // A passkey descriptor cannot self-prove possession; enrolling one requires a
  // WebAuthn assertion over enrollmentChallenge(actor, key). Fail closed without it
  // rather than let the org root attest a credential nobody proved they hold.
  if (isWebAuthnCredential(publicKey) && !has("revoke")) {
    const popFile = arg("webauthn-pop");
    const rpId = arg("rp-id");
    const origin = arg("origin");
    if (!popFile || !rpId || !origin)
      die("enrolling a passkey descriptor requires --webauthn-pop <file.json> (authenticator_data, client_data_json, signature over enrollmentChallenge) plus --rp-id and --origin", 2);
    let parsed: { authenticator_data?: string; client_data_json?: string; signature?: string };
    try {
      parsed = JSON.parse(readFileSync(popFile!, "utf8"));
    } catch {
      die(`could not read/parse --webauthn-pop file ${popFile}`, 2);
    }
    if (!parsed.authenticator_data || !parsed.client_data_json || !parsed.signature)
      die("--webauthn-pop file must contain authenticator_data, client_data_json, and signature", 2);
    webauthnPop = {
      assertion: { authenticator_data: parsed.authenticator_data, client_data_json: parsed.client_data_json },
      signature: parsed.signature,
      policy: { rpId: rpId!, allowedOrigins: [origin!], requireUserVerification: has("require-uv") },
    };
  }
} else {
  die("provide --approver-key (raw ed25519 secret, computes proof of possession) or --public-key (a passkey descriptor)", 2);
}

try {
  const rec = has("revoke")
    ? registry.revoke(actor!, publicKey, orgKey!)
    : registry.enroll(actor!, publicKey, orgKey!, { pop, webauthnPop });
  writeFileSync(registryPath!, registry.toJSONL());
  process.stdout.write(`${rec.typ}: ${actor} -> ${publicKey}\nregistry: ${registryPath} (${registry.all.length} records, chain ${registry.verifyChain(rec.org_public_key) ? "ok" : "BROKEN"})\n`);
} catch (e) {
  die(`${(e as Error).message}`);
}
