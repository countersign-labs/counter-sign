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
//   # enroll a passkey approver (descriptor from a WebAuthn registration):
//   tsx scripts/enroll.ts --registry reg.jsonl --actor slack:U024BE7LH \
//       --public-key webauthn-p256:<...> --org-key <org-root-secret>
//
//   # revoke (key rotation / offboarding):
//   tsx scripts/enroll.ts --registry reg.jsonl --actor slack:U024BE7LH \
//       --public-key <key> --org-key <org-root-secret> --revoke

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { ApproverRegistry, createEnrollmentProof } from "../src/registry.js";
import { publicKeyFromSecret } from "../src/core/keys.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const has = (name: string) => process.argv.includes(`--${name}`);
function die(msg: string, code = 1): never {
  process.stderr.write(msg + "\n");
  process.exit(code);
}

const registryPath = arg("registry");
const actor = arg("actor");
const orgKey = arg("org-key");
const approverKey = arg("approver-key");
const publicKeyArg = arg("public-key");

if (!registryPath || !actor || !orgKey) die("usage: enroll --registry <file> --actor <actor> (--approver-key <secret>|--public-key <key>) --org-key <org-secret> [--revoke]", 2);

const registry = existsSync(registryPath!) ? ApproverRegistry.fromJSONL(readFileSync(registryPath!, "utf8")) : new ApproverRegistry();

// Never append to a registry that does not verify under the supplied org key —
// otherwise a wrong --org-key silently produces a mixed-root, unverifiable file.
const orgPub = publicKeyFromSecret(orgKey!);
if (registry.all.length > 0 && !registry.verifyChain(orgPub))
  die(`existing registry at ${registryPath} does not verify under the supplied --org-key (wrong org key, or the file was tampered) — refusing to write`, 2);

let publicKey: string;
let pop: string | undefined;
if (approverKey) {
  publicKey = publicKeyFromSecret(approverKey);
  pop = createEnrollmentProof(actor!, approverKey);
} else if (publicKeyArg) {
  publicKey = publicKeyArg;
} else {
  die("provide --approver-key (raw ed25519 secret, computes proof of possession) or --public-key (a passkey descriptor)", 2);
}

try {
  const rec = has("revoke")
    ? registry.revoke(actor!, publicKey, orgKey!)
    : registry.enroll(actor!, publicKey, orgKey!, { pop });
  writeFileSync(registryPath!, registry.toJSONL());
  process.stdout.write(`${rec.typ}: ${actor} -> ${publicKey}\nregistry: ${registryPath} (${registry.all.length} records, chain ${registry.verifyChain(rec.org_public_key) ? "ok" : "BROKEN"})\n`);
} catch (e) {
  die(`${(e as Error).message}`);
}
