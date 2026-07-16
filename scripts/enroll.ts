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

import { appendFileSync, existsSync, readFileSync } from "node:fs";
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
// --approver-key and --public-key are mutually exclusive: silently letting one win would bind a
// DIFFERENT key than the operator passed (e.g. the ed25519 key derived from the secret instead of the
// explicit passkey descriptor), which then blocks every approval for that actor with no signal.
if (approverKey && publicKeyArg) die("--approver-key and --public-key are mutually exclusive — pass exactly one (a raw ed25519 secret, or a public key/passkey descriptor)", 2);

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
    // JSON.parse("null") (and "1", "\"s\"", "[]") does NOT throw but is not an object; dereferencing
    // parsed.authenticator_data below would then be an uncaught TypeError → exit 1 with a raw stack
    // trace instead of the clean die() error. Guard it, as signing.ts / registry.fromJSONL do.
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      die("--webauthn-pop file must contain authenticator_data, client_data_json, and signature", 2);
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
  // APPEND exactly the one new record line (same JSON.stringify serialization as toJSONL)
  // instead of rewriting the whole file. The registry is append-only JSONL; a full rewrite
  // meant a concurrent enroll/revoke was last-writer-wins — the loser's record (e.g. a
  // REVOKE) vanished while the surviving file still verified. With appends, a concurrent
  // write at worst forks the hash chain, which verifyChain REPORTS instead of hiding, and
  // a crash mid-write truncates only the tail line, which fromJSONL rejects loudly.
  // Guard the trailing newline: fromJSONL accepts (and verifyChain passes) a file whose last
  // line has no "\n", so appending straight onto it would glue two records into one corrupt
  // line while the CLI reports success. Prepend a "\n" iff the file has content not ending in one.
  const existing = existsSync(registryPath!) ? readFileSync(registryPath!, "utf8") : "";
  const sep = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(registryPath!, sep + JSON.stringify(rec) + "\n");
  // The chain was verified under --org-key before appending (line ~51) and enroll/revoke maintain it,
  // so it is intact by construction — no need to re-walk and re-verify every record's signature here
  // (O(records) crypto) just to print a status word.
  process.stdout.write(`${rec.typ}: ${actor} -> ${publicKey}\nregistry: ${registryPath} (${registry.all.length} records)\n`);
} catch (e) {
  die(`${(e as Error).message}`);
}
