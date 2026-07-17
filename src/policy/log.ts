// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// PolicyLog: a signed, hash-chained, admin-attested append-only log of policy changes
// (admin keys, roles, rules). Mirrors ApproverRegistry/ReceiptLog. Current state is a
// deterministic fold of a verified log.

import { createHash } from "node:crypto";
import { canonicalize } from "../core/canonical.js";
import { CountersignError } from "../core/errors.js";
import { publicKeyFromSecret, signContext, utf8, verifyContext } from "../core/keys.js";
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

  /** Walk the chain: contiguous seq, correct prev links, self-signed admin-add genesis,
   *  every entry signed by a key active as an admin immediately before it, every entry's
   *  change belongs to the genesis org (single-org invariant), every role-set/rule-set
   *  change satisfies validateRole/validateRule (parity with append's assertChangeValid),
   *  and the last-admin invariant held historically. Total — never throws; returns false
   *  on any break. If `expectedHead` is given, also fails unless the log's current head
   *  (length + tip hash) matches it exactly — detects rollback/tail-truncation against an
   *  externally-anchored head (mirrors ApproverRegistry.verifyChain). */
  verifyChain(expectedHead?: { length: number; hash: string }): boolean {
    try {
      const admins = new Map<string, AdminKey>();
      let prevHash: string | null = null;
      let genesisOrg: string | null = null;
      for (let i = 0; i < this._entries.length; i++) {
        const e = this._entries[i];
        if (e.seq !== i) return false;
        if (e.prev !== prevHash) return false;
        const { signature, ...unsigned } = e;
        if (!verifyContext(e.signer_public_key, POLICY_CONTEXT, canonicalPolicyEntry(unsigned), signature)) return false;
        if (i === 0) {
          if (e.change.kind !== "admin-add" || e.change.public_key !== e.signer_public_key) return false;
          genesisOrg = changeOrg(e.change);
        } else if (!admins.has(e.signer_public_key)) {
          return false; // signer was not an active admin at this point
        }
        if (changeOrg(e.change) !== genesisOrg) return false; // single-org invariant
        // Fold this entry into the running admin set for the NEXT iteration's check.
        const c = e.change;
        if (c.kind === "admin-add") {
          if (i > 0 && admins.has(c.public_key)) return false; // duplicate admin-add — impossible via append()
          admins.set(c.public_key, { org: c.org, public_key: c.public_key, name: c.name });
        } else if (c.kind === "admin-revoke") {
          if (!admins.has(c.public_key)) return false; // revoke of a never-active key — impossible via append()
          if (admins.size <= 1) return false;            // last-admin invariant (already present)
          admins.delete(c.public_key);
        } else if (c.kind === "role-set") {
          validateRole(c.role); // parity with append()'s assertChangeValid
        } else if (c.kind === "rule-set") {
          validateRule(c.rule); // parity with append()'s assertChangeValid
        }
        prevHash = hashEntry(e);
      }
      if (expectedHead) {
        if (expectedHead.length !== this._entries.length) return false;
        if (expectedHead.hash !== this.head().hash) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /** PolicyStore.verify: fail-closed chain verification, optionally anchored to a
   *  trusted head (see verifyChain). */
  verify(expectedHead?: { length: number; hash: string }): boolean {
    return this.verifyChain(expectedHead);
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
