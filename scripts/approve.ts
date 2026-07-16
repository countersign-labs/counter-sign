// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// countersign approve — produce a KEYED countersignature over an Intent, signed
// by the APPROVER'S OWN key (raw ed25519, Phase 1). This is how a keyed approver
// or a bot/CI approver decides without the server ever holding their key.
//
//   tsx scripts/approve.ts --intent intent.json --actor slack:U024BE7LH \
//       --decision approve --key <approver-secret-base64url>   > receipt.json
//
// The approver's key can also come from COUNTERSIGN_APPROVER_KEY. The receipt is
// printed to stdout; feed it to the collecting server (PendingDecisions.record).

import { readFileSync } from "node:fs";
import { normalizeActor, signDecision } from "../src/core/countersignature.js";
import { assertIntentInvariants, verifyIntent } from "../src/core/intent.js";
import { publicKeyFromSecret } from "../src/core/keys.js";
import type { Intent } from "../src/core/types.js";
import { arg, die } from "./_args.js";

const intentPath = arg("intent");
const actor = arg("actor");
const decision = arg("decision") ?? "approve";
const key = arg("key") ?? process.env.COUNTERSIGN_APPROVER_KEY;

if (!intentPath || !actor || !key)
  die("usage: approve --intent <file> --actor <actor> --decision approve|reject --key <secret>", 2);
if (decision !== "approve" && decision !== "reject") die("--decision must be approve or reject", 2);

let intent: Intent;
try {
  intent = JSON.parse(readFileSync(intentPath!, "utf8"));
} catch (e) {
  die(`could not read/parse intent: ${(e as Error).message}`, 2);
}

// Never sign over a malformed or forged Intent. A structural violation exits cleanly.
try {
  assertIntentInvariants(intent);
} catch (e) {
  die(`invalid intent: ${(e as Error).message}`, 2);
}
if (!verifyIntent(intent)) die("intent signature does not verify — refusing to sign");

// The actor must be a KEYED approver of this Intent whose bound key is the one we hold.
let pub: string;
try {
  pub = publicKeyFromSecret(key!);
} catch {
  die("--key (or COUNTERSIGN_APPROVER_KEY) is not a valid ed25519 secret key", 2);
}
const approver = intent.approvers.find((a) => normalizeActor(a.actor) === normalizeActor(actor!));
if (!approver) die(`actor ${actor} is not an approver of this intent`);
if (approver.mode !== "keyed") die(`actor ${actor} is a '${approver.mode}' approver — only keyed approvers sign their own receipts`);
if (approver.public_key !== pub) die(`the signing key does not match ${actor}'s bound public_key`);

const receipt = signDecision(intent, decision as "approve" | "reject", approver.actor, key!, "approver");
process.stdout.write(JSON.stringify(receipt, null, 2) + "\n");
