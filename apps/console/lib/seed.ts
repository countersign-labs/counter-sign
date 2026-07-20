// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Dev/test-only: write a minimal SIGNED data dir so the console has something real to
// render and the store tests have a fixture. Not used at runtime by the console itself.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  ApproverRegistry,
  PolicyLog,
  createEnrollmentProof,
  generateKeypair,
  publicKeyFromSecret,
} from "@countersignlabs/counter-sign";

/** Write registry.jsonl + policy.jsonl + receipts.jsonl into `dataDir`. Returns the
 *  org-root public key (needed to verify the registry) and the admin secret used to
 *  sign the policy log (handy for local dev signing experiments). */
export function seedSampleData(dataDir: string): { orgPublicKey: string; adminSecret: string } {
  mkdirSync(dataDir, { recursive: true });
  const orgRoot = generateKeypair();
  const admin = generateKeypair();
  const cfo = generateKeypair();

  const registry = new ApproverRegistry();
  registry.enroll("m:cfo", cfo.publicKey, orgRoot.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });

  const log = new PolicyLog();
  log.append({ kind: "admin-add", org: "acme", public_key: admin.publicKey, name: "root" }, admin.secretKey);
  log.append(
    { kind: "role-set", role: { id: "finance", org: "acme", name: "finance-approvers", members: ["m:cfo"] } },
    admin.secretKey,
  );
  log.append(
    {
      kind: "rule-set",
      rule: { id: "refund", org: "acme", name: "refund", roles: ["finance"], quorum: 1, default: "reject", timeout_seconds: 3600, action: "billing.refund", risk_tier: "high" },
    },
    admin.secretKey,
  );

  writeFileSync(join(dataDir, "registry.jsonl"), registry.toJSONL());
  writeFileSync(join(dataDir, "policy.jsonl"), log.toJSONL());
  writeFileSync(join(dataDir, "receipts.jsonl"), "");
  return { orgPublicKey: publicKeyFromSecret(orgRoot.secretKey), adminSecret: admin.secretKey };
}
