// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// PolicyLog: a signed, hash-chained, admin-attested append-only log of policy changes
// (admin keys, roles, rules). Mirrors ApproverRegistry/ReceiptLog. Current state is a
// deterministic fold of a verified log.

import { createHash } from "node:crypto";
import { canonicalize } from "../core/canonical.js";
import { CountersignError } from "../core/errors.js";
import { publicKeyFromSecret, signContext, utf8 } from "../core/keys.js";
import { validateRole, validateRule } from "./validate.js";
import { POLICY_CONTEXT } from "./types.js";
import type { AdminKey, PolicyChange, PolicyEntry, PolicyState, PolicyStore, Role, Rule } from "./types.js";

/** Canonical bytes of the unsigned entry — the message an admin key signs. */
export function canonicalPolicyEntry(unsigned: Omit<PolicyEntry, "signature">): string {
  return canonicalize(unsigned);
}

/** sha256 hex of the full signed entry — the `prev` link of the next entry. */
export function hashEntry(entry: PolicyEntry): string {
  return createHash("sha256").update(utf8(canonicalize(entry))).digest("hex");
}

const GENESIS_PREV: null = null;

/** The org a change belongs to. */
function changeOrg(change: PolicyChange): string {
  switch (change.kind) {
    case "role-set": return change.role.org;
    case "rule-set": return change.rule.org;
    default: return change.org; // admin-add | admin-revoke | role-delete | rule-delete
  }
}

export class PolicyLog implements PolicyStore {
  private _entries: PolicyEntry[];
  constructor(entries: PolicyEntry[] = []) {
    this._entries = [...entries];
  }
  get entries(): readonly PolicyEntry[] {
    return this._entries;
  }

  static fromJSONL(text: string): PolicyLog {
    const entries = text.split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l) as PolicyEntry);
    return new PolicyLog(entries);
  }
  toJSONL(): string {
    return this._entries.map((e) => JSON.stringify(e)).join("\n") + (this._entries.length ? "\n" : "");
  }

  /** Append a change, signed by `adminSecret`. Validates the change against current state
   *  and the admin's authority BEFORE persisting. Genesis (seq 0) must be a self-signed
   *  admin-add: the signer key equals the key being added (the root admin bootstraps itself). */
  append(change: PolicyChange, adminSecret: string): PolicyEntry {
    const signer = publicKeyFromSecret(adminSecret);
    const org = changeOrg(change);
    const state = this.foldState(this._entries); // state BEFORE this entry
    const isGenesis = this._entries.length === 0;
    if (isGenesis) {
      if (change.kind !== "admin-add") throw new CountersignError("policy log genesis must be an admin-add");
      if (change.public_key !== signer) throw new CountersignError("policy log genesis admin-add must be self-signed (signer must equal the added key)");
    } else {
      const logOrg = changeOrg(this._entries[0].change);
      if (org !== logOrg) throw new CountersignError(`policy change org "${org}" does not match policy log org "${logOrg}"`);
      if (!state.admins.has(signer)) throw new CountersignError(`signer ${signer} is not an active admin`);
    }
    this.assertChangeValid(change, state, isGenesis);
    const seq = this._entries.length;
    const prev = isGenesis ? GENESIS_PREV : hashEntry(this._entries[seq - 1]);
    const unsigned: Omit<PolicyEntry, "signature"> = {
      countersign: "0.2", seq, change, issued_at: new Date().toISOString(), prev, signer_public_key: signer,
    };
    const signature = signContext(adminSecret, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    const entry: PolicyEntry = { ...unsigned, signature };
    this._entries.push(entry);
    return entry;
  }

  /** Invariants beyond signer authority. `state` is the state BEFORE the change. */
  private assertChangeValid(change: PolicyChange, state: PolicyState, isGenesis: boolean): void {
    switch (change.kind) {
      case "admin-add":
        if (!isGenesis && state.admins.has(change.public_key)) throw new CountersignError(`admin ${change.public_key} already active`);
        return;
      case "admin-revoke":
        if (!state.admins.has(change.public_key)) throw new CountersignError(`admin ${change.public_key} is not active`);
        if (state.admins.size <= 1) throw new CountersignError("cannot revoke the last remaining admin key");
        return;
      case "role-set":
        validateRole(change.role);
        return;
      case "rule-set":
        validateRule(change.rule);
        return;
      case "role-delete":
        if (!state.roles.has(change.id)) throw new CountersignError(`role ${change.id} does not exist`);
        return;
      case "rule-delete":
        if (!state.rules.has(change.id)) throw new CountersignError(`rule ${change.id} does not exist`);
        return;
      default:
        throw new CountersignError(`unknown policy change kind: ${(change as { kind?: string }).kind}`);
    }
  }

  /** Fold a list of entries into current state (no signature checks — see verifyChain). */
  private foldState(entries: readonly PolicyEntry[]): PolicyState {
    const admins = new Map<string, AdminKey>();
    const roles = new Map<string, Role>();
    const rules = new Map<string, Rule>();
    for (const { change } of entries) {
      switch (change.kind) {
        case "admin-add": admins.set(change.public_key, { org: change.org, public_key: change.public_key, name: change.name }); break;
        case "admin-revoke": admins.delete(change.public_key); break;
        case "role-set": roles.set(change.role.id, change.role); break;
        case "role-delete": roles.delete(change.id); break;
        case "rule-set": rules.set(change.rule.id, change.rule); break;
        case "rule-delete": rules.delete(change.id); break;
        default:
          throw new CountersignError(`unknown policy change kind: ${(change as { kind?: string }).kind}`);
      }
    }
    return { admins, roles, rules };
  }

  state(): PolicyState {
    return this.foldState(this._entries);
  }
  head(): { length: number; hash: string } {
    return { length: this._entries.length, hash: this._entries.length ? hashEntry(this._entries[this._entries.length - 1]) : "" };
  }

  // --- PolicyStore read surface ---
  getRule(org: string, name: string): Rule | undefined {
    for (const r of this.state().rules.values()) if (r.org === org && r.name === name) return r;
    return undefined;
  }
  getRoleById(org: string, id: string): Role | undefined {
    const r = this.state().roles.get(id);
    return r && r.org === org ? r : undefined;
  }
  listRoles(org: string): Role[] {
    return [...this.state().roles.values()].filter((r) => r.org === org);
  }
  listRules(org: string): Rule[] {
    return [...this.state().rules.values()].filter((r) => r.org === org);
  }
  listAdmins(org: string): AdminKey[] {
    return [...this.state().admins.values()].filter((a) => a.org === org);
  }
}
