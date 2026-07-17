// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// PolicyLog: a signed, hash-chained, admin-attested append-only log of policy changes
// (admin keys, roles, rules). Mirrors ApproverRegistry/ReceiptLog. Current state is a
// deterministic fold of a verified log.

import { createHash } from "node:crypto";
import { canonicalize } from "../core/canonical.js";
import { CountersignError } from "../core/errors.js";
import { publicKeyFromSecret, signContext, toB64url, utf8, verifyContext } from "../core/keys.js";
import { POLICY_CONTEXT, type PolicyEntry } from "./types.js";

/** Canonical bytes of the unsigned entry — the message an admin key signs. */
export function canonicalPolicyEntry(unsigned: Omit<PolicyEntry, "signature">): string {
  return canonicalize(unsigned);
}

/** sha256 hex of the full signed entry — the `prev` link of the next entry. */
export function hashEntry(entry: PolicyEntry): string {
  return createHash("sha256").update(utf8(canonicalize(entry))).digest("hex");
}
