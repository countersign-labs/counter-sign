# Policy Layer (library) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure, framework-free RBAC policy layer to the counter-sign library — `Role`, `Rule`, a signed hash-chained `PolicyLog` (admin-attested), and `resolveRule()` that turns a named rule into `IntentFields` for `createIntent`.

**Architecture:** A new `src/policy/` module. Roles group approvers; rules reference roles and carry quorum + default + timeout. All state changes (admin keys, roles, rules) are appended to a signed, hash-chained `PolicyLog` — mirroring `ApproverRegistry` (`src/registry.ts`) and `ReceiptLog` — so a compromised console cannot silently alter a rule. The current state (admins/roles/rules) is a deterministic fold of the log. `resolveRule` reads the current rule, expands its roles into a concrete keyed-approver list using `ApproverRegistry.activeKeyMap()`, and returns `IntentFields`. No wire-format change: this layer *produces* Intents through the existing `createIntent`.

**Tech Stack:** TypeScript (ESM, Node ≥ 20), vitest. Reuses `signContext`/`verifyContext` (`src/core/keys.ts`), `canonicalize` (`src/core/canonical.ts`), `normalizeActor` (`src/core/countersignature.ts`), `ApproverRegistry` (`src/registry.ts`), `createIntent`/`IntentFields` (`src/core/intent.ts`).

## Global Constraints

- Node ≥ 20, ESM, `.js` extensions on relative imports (repo convention).
- All copyright headers: `// Copyright 2026 Haridarman Kumaresan` + `// SPDX-License-Identifier: Apache-2.0` (match existing files).
- Signing domain-separation context for the policy log: `countersign-policy-v0.2` (aligns with the current `COUNTERSIGN_VERSION = "0.2"`).
- Timeout bounds reused from core: `MAX_TIMEOUT_SECONDS = 2147483`, minimum `1`, integer seconds.
- Safety invariant (must hold everywhere): `quorum > 1` ⇒ `default === "reject"` AND every approver is `keyed`. Mirrors `createIntent`.
- Verifiers are total: never throw on hostile input except where a method's contract is "throws on invalid" (validation/append). Chain verification returns `boolean`.
- Tests use vitest; run a single file with `npx vitest run tests/<file>`.

---

## File Structure

- Create `src/policy/types.ts` — `Role`, `Rule`, `AdminKey`, `PolicyChange`, `PolicyEntry`, `PolicyState`, `PolicyStore`, `RuleRequest`, `ResolveDeps`, `POLICY_CONTEXT`.
- Create `src/policy/validate.ts` — `validateRole(role)`, `validateRule(rule)`.
- Create `src/policy/log.ts` — `PolicyLog` class (append/state/head/verifyChain/JSONL) + `canonicalPolicyEntry`.
- Create `src/policy/resolve.ts` — `resolveRule(ruleName, request, deps)`.
- Create `src/policy/index.ts` — barrel re-export.
- Modify `src/index.ts` — add `export * from "./policy/index.js";`.
- Tests: `tests/policy-validate.test.ts`, `tests/policy-log.test.ts`, `tests/policy-resolve.test.ts`, `tests/policy-integration.test.ts`.

---

## Task 1: Types + validation

**Files:**
- Create: `src/policy/types.ts`
- Create: `src/policy/validate.ts`
- Test: `tests/policy-validate.test.ts`

**Interfaces:**
- Consumes: `Decision`, `RiskTier` (`src/core/types.ts`), `Approver`, `IntentFields`, `CountersignError` (`src/core/errors.ts`), `ApproverRegistry` (`src/registry.ts`), `COUNTERSIGN_VERSION` (`src/core/types.ts`).
- Produces: the types listed in File Structure, plus `validateRole(role: Role): void` and `validateRule(rule: Rule): void` (throw `CountersignError` on invalid, return void on valid).

- [ ] **Step 1: Write `src/policy/types.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// The policy layer: approvers (from ApproverRegistry) grouped into Roles, referenced
// by Rules that carry quorum + default + timeout. Every change is a signed, hash-chained
// PolicyLog entry (admin-attested). resolveRule turns a named Rule into IntentFields.

import type { ApproverRegistry } from "../registry.js";
import type { Decision, RiskTier } from "./../core/types.js";
import { COUNTERSIGN_VERSION } from "../core/types.js";

/** Domain-separation context for policy-log entry signatures. */
export const POLICY_CONTEXT = "countersign-policy-v0.2" as const;

/** A named group of approvers (by actor id) within an org. Membership only. */
export interface Role {
  id: string;
  org: string;
  name: string;
  description?: string;
  members: string[]; // approver actor ids
}

/** A named approval rule an agent references. Resolves to IntentFields. */
export interface Rule {
  id: string;
  org: string;
  name: string;
  roles: string[]; // role ids whose members may approve
  quorum: number;
  default: Decision;
  timeout_seconds: number;
  risk_tier?: RiskTier;
  action?: string;
}

/** An admin key that may sign policy-log changes and access the console. */
export interface AdminKey {
  org: string;
  public_key: string; // raw ed25519 or a webauthn-* descriptor
  name?: string;
}

/** One change recorded in the policy log. */
export type PolicyChange =
  | { kind: "admin-add"; org: string; public_key: string; name?: string }
  | { kind: "admin-revoke"; org: string; public_key: string }
  | { kind: "role-set"; role: Role }
  | { kind: "role-delete"; org: string; id: string }
  | { kind: "rule-set"; rule: Rule }
  | { kind: "rule-delete"; org: string; id: string };

/** A signed, hash-chained policy-log entry. */
export interface PolicyEntry {
  countersign: typeof COUNTERSIGN_VERSION;
  seq: number; // 0-based
  change: PolicyChange;
  issued_at: string; // ISO 8601
  prev: string | null; // sha256 hex of the previous entry; null for genesis
  signer_public_key: string; // the admin key that signed this entry
  signature: string; // signContext(adminSecret, POLICY_CONTEXT, canonicalPolicyEntry(unsigned))
}

/** The current state derived by folding a verified policy log. */
export interface PolicyState {
  admins: Map<string, AdminKey>; // public_key -> active AdminKey
  roles: Map<string, Role>; // role id -> Role
  rules: Map<string, Rule>; // rule id -> Rule
}

/** Read surface consumed by resolveRule and the console. */
export interface PolicyStore {
  getRule(org: string, name: string): Rule | undefined;
  getRoleById(org: string, id: string): Role | undefined;
  listRoles(org: string): Role[];
  listRules(org: string): Rule[];
  listAdmins(org: string): AdminKey[];
}

/** The specific request context an agent supplies when resolving a rule. */
export interface RuleRequest {
  summary: string; // the concrete action description
  action?: string; // overrides rule.action when given
  risk_tier?: RiskTier; // overrides rule.risk_tier when given
}

/** Dependencies resolveRule needs. */
export interface ResolveDeps {
  store: PolicyStore;
  registry: ApproverRegistry;
  org: string;
}
```

- [ ] **Step 2: Write the failing test `tests/policy-validate.test.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { validateRole, validateRule } from "../src/policy/validate.js";
import type { Role, Rule } from "../src/policy/types.js";

const role: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] };
const rule = (over: Partial<Rule> = {}): Rule => ({
  id: "u1", org: "o1", name: "large-refund", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 3600, ...over,
});

describe("validateRole", () => {
  it("accepts a well-formed role", () => expect(() => validateRole(role)).not.toThrow());
  it("rejects an empty name", () => expect(() => validateRole({ ...role, name: "" })).toThrow());
  it("rejects a role with no members", () => expect(() => validateRole({ ...role, members: [] })).toThrow());
  it("rejects duplicate members (normalized)", () =>
    expect(() => validateRole({ ...role, members: ["m:cfo", "M:CFO"] })).toThrow());
});

describe("validateRule", () => {
  it("accepts a well-formed rule", () => expect(() => validateRule(rule())).not.toThrow());
  it("rejects quorum < 1 or non-integer", () => {
    expect(() => validateRule(rule({ quorum: 0 }))).toThrow();
    expect(() => validateRule(rule({ quorum: 1.5 }))).toThrow();
  });
  it("rejects quorum > 1 with default approve (timeout would bypass approvers)", () =>
    expect(() => validateRule(rule({ quorum: 2, default: "approve" }))).toThrow());
  it("accepts quorum 1 with default approve", () =>
    expect(() => validateRule(rule({ quorum: 1, default: "approve" }))).not.toThrow());
  it("rejects a timeout outside [1, 2147483]", () => {
    expect(() => validateRule(rule({ timeout_seconds: 0 }))).toThrow();
    expect(() => validateRule(rule({ timeout_seconds: 2147484 }))).toThrow();
  });
  it("rejects an empty roles list", () => expect(() => validateRule(rule({ roles: [] }))).toThrow());
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npx vitest run tests/policy-validate.test.ts`
Expected: FAIL — `validate.js` does not exist / `validateRole` is not a function.

- [ ] **Step 4: Write `src/policy/validate.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { CountersignError } from "../core/errors.js";
import { normalizeActor } from "../core/countersignature.js";
import type { Role, Rule } from "./types.js";

const MAX_TIMEOUT_SECONDS = 2147483; // = src/core/intent.ts

export function validateRole(role: Role): void {
  if (!role || typeof role !== "object") throw new CountersignError("role must be an object");
  for (const f of ["id", "org", "name"] as const)
    if (typeof role[f] !== "string" || role[f].length === 0) throw new CountersignError(`role.${f} must be a non-empty string`);
  if (!Array.isArray(role.members) || role.members.length === 0)
    throw new CountersignError(`role ${role.name} must have at least one member`);
  const seen = new Set<string>();
  for (const m of role.members) {
    if (typeof m !== "string" || m.length === 0) throw new CountersignError(`role ${role.name} has an empty member`);
    const norm = normalizeActor(m);
    if (seen.has(norm)) throw new CountersignError(`role ${role.name} has a duplicate member ${m}`);
    seen.add(norm);
  }
}

export function validateRule(rule: Rule): void {
  if (!rule || typeof rule !== "object") throw new CountersignError("rule must be an object");
  for (const f of ["id", "org", "name"] as const)
    if (typeof rule[f] !== "string" || rule[f].length === 0) throw new CountersignError(`rule.${f} must be a non-empty string`);
  if (!Array.isArray(rule.roles) || rule.roles.length === 0)
    throw new CountersignError(`rule ${rule.name} must reference at least one role`);
  if (!Number.isInteger(rule.quorum) || rule.quorum < 1)
    throw new CountersignError(`rule ${rule.name}: quorum must be an integer >= 1`);
  if (rule.default !== "approve" && rule.default !== "reject")
    throw new CountersignError(`rule ${rule.name}: default must be "approve" or "reject"`);
  if (rule.quorum > 1 && rule.default === "approve")
    throw new CountersignError(`rule ${rule.name}: quorum > 1 must not combine with default: approve (a timeout would bypass required approvers)`);
  if (!Number.isInteger(rule.timeout_seconds) || rule.timeout_seconds < 1 || rule.timeout_seconds > MAX_TIMEOUT_SECONDS)
    throw new CountersignError(`rule ${rule.name}: timeout_seconds must be an integer in [1, ${MAX_TIMEOUT_SECONDS}]`);
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run tests/policy-validate.test.ts`
Expected: PASS (10 tests).

- [ ] **Step 6: Commit**

```bash
git add src/policy/types.ts src/policy/validate.ts tests/policy-validate.test.ts
git commit -m "feat(policy): Role/Rule types + validation"
```

---

## Task 2: Policy entry canonicalization + sign/verify

**Files:**
- Create: `src/policy/log.ts` (partial — the two functions below)
- Test: `tests/policy-log.test.ts` (first describe block)

**Interfaces:**
- Consumes: `canonicalize` (`src/core/canonical.ts`), `signContext`/`verifyContext`/`utf8`/`toB64url`/`publicKeyFromSecret` (`src/core/keys.ts`), `createHash` (`node:crypto`), `PolicyEntry`, `POLICY_CONTEXT`.
- Produces: `canonicalPolicyEntry(unsigned: Omit<PolicyEntry, "signature">): string`; `hashEntry(entry: PolicyEntry): string` (sha256 hex of the canonical *signed* entry, for the `prev` chain).

- [ ] **Step 1: Write the failing test (append to `tests/policy-log.test.ts`)**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { canonicalPolicyEntry, hashEntry } from "../src/policy/log.js";
import { POLICY_CONTEXT, type PolicyEntry } from "../src/policy/types.js";
import { generateKeypair, signContext, verifyContext } from "../src/core/keys.js";

const admin = generateKeypair();
function unsigned(): Omit<PolicyEntry, "signature"> {
  return {
    countersign: "0.2", seq: 0,
    change: { kind: "admin-add", org: "o1", public_key: admin.publicKey, name: "root" },
    issued_at: "2026-01-01T00:00:00.000Z", prev: null, signer_public_key: admin.publicKey,
  };
}

describe("policy entry signing", () => {
  it("round-trips a signature over the canonical unsigned entry", () => {
    const u = unsigned();
    const sig = signContext(admin.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(u));
    expect(verifyContext(admin.publicKey, POLICY_CONTEXT, canonicalPolicyEntry(u), sig)).toBe(true);
  });
  it("hashEntry is stable and changes when a field changes", () => {
    const e: PolicyEntry = { ...unsigned(), signature: "sig" };
    expect(hashEntry(e)).toBe(hashEntry({ ...e }));
    expect(hashEntry(e)).not.toBe(hashEntry({ ...e, seq: 1 }));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/policy-log.test.ts`
Expected: FAIL — `log.js` / `canonicalPolicyEntry` not found.

- [ ] **Step 3: Create `src/policy/log.ts` with the two helpers**

```ts
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run tests/policy-log.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/policy/log.ts tests/policy-log.test.ts
git commit -m "feat(policy): canonical entry + signing helpers"
```

---

## Task 3: PolicyLog — append, genesis, fold, admin lifecycle, invariants

**Files:**
- Modify: `src/policy/log.ts` (add the `PolicyLog` class)
- Test: `tests/policy-log.test.ts` (add "PolicyLog append/state" describe)

**Interfaces:**
- Consumes: everything from Task 1–2, plus `validateRole`/`validateRule` (`src/policy/validate.ts`), `normalizeActor` (`src/core/countersignature.js`), `PolicyChange`, `PolicyState`, `AdminKey`, `Role`, `Rule`, `PolicyStore`.
- Produces: `class PolicyLog` implementing `PolicyStore` with:
  - `constructor(entries?: PolicyEntry[])`
  - `append(change: PolicyChange, adminSecret: string): PolicyEntry`
  - `state(): PolicyState`
  - `head(): { length: number; hash: string }`
  - `get entries(): readonly PolicyEntry[]`
  - `getRule(org,name)`, `getRoleById(org,id)`, `listRoles(org)`, `listRules(org)`, `listAdmins(org)`

- [ ] **Step 1: Write the failing tests (append to `tests/policy-log.test.ts`)**

```ts
import { PolicyLog } from "../src/policy/log.js";
import type { Role, Rule } from "../src/policy/types.js";

const rootA = generateKeypair();
const adminB = generateKeypair();
const role: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo"] };
const rule: Rule = { id: "u1", org: "o1", name: "refund", roles: ["r1"], quorum: 1, default: "reject", timeout_seconds: 3600 };

function bootstrapped(): PolicyLog {
  const log = new PolicyLog();
  log.append({ kind: "admin-add", org: "o1", public_key: rootA.publicKey, name: "root" }, rootA.secretKey);
  return log;
}

describe("PolicyLog append/state", () => {
  it("genesis must be a self-signed admin-add", () => {
    const log = new PolicyLog();
    expect(() => log.append({ kind: "role-set", role }, rootA.secretKey)).toThrow(/genesis/i);
    expect(() => log.append({ kind: "admin-add", org: "o1", public_key: adminB.publicKey }, rootA.secretKey)).toThrow(/self/i);
  });

  it("records roles and rules and folds them into state", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    log.append({ kind: "rule-set", rule }, rootA.secretKey);
    expect(log.getRule("o1", "refund")).toMatchObject({ id: "u1", quorum: 1 });
    expect(log.getRoleById("o1", "r1")?.members).toEqual(["m:cfo"]);
    expect(log.listAdmins("o1").map((a) => a.public_key)).toEqual([rootA.publicKey]);
  });

  it("rejects a change signed by a non-admin key", () => {
    const log = bootstrapped();
    expect(() => log.append({ kind: "role-set", role }, adminB.secretKey)).toThrow(/not an active admin/i);
  });

  it("an existing admin can add a second admin, who can then sign", () => {
    const log = bootstrapped();
    log.append({ kind: "admin-add", org: "o1", public_key: adminB.publicKey, name: "b" }, rootA.secretKey);
    expect(() => log.append({ kind: "role-set", role }, adminB.secretKey)).not.toThrow();
    expect(log.listAdmins("o1").length).toBe(2);
  });

  it("refuses to revoke the last remaining admin", () => {
    const log = bootstrapped();
    expect(() => log.append({ kind: "admin-revoke", org: "o1", public_key: rootA.publicKey }, rootA.secretKey)).toThrow(/last/i);
  });

  it("validates rule invariants on rule-set (quorum>1 + default approve rejected)", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    const bad: Rule = { ...rule, id: "u2", name: "bad", quorum: 2, default: "approve" };
    expect(() => log.append({ kind: "rule-set", rule: bad }, rootA.secretKey)).toThrow(/quorum > 1/);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/policy-log.test.ts`
Expected: FAIL — `PolicyLog` is not exported.

- [ ] **Step 3: Add the `PolicyLog` class to `src/policy/log.ts`**

```ts
import { normalizeActor } from "../core/countersignature.js";
import { validateRole, validateRule } from "./validate.js";
import type { AdminKey, PolicyChange, PolicyState, PolicyStore, Role, Rule } from "./types.js";

const GENESIS_PREV: null = null;

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
    const state = this.foldState(this._entries); // state BEFORE this entry
    const isGenesis = this._entries.length === 0;
    if (isGenesis) {
      if (change.kind !== "admin-add") throw new CountersignError("policy log genesis must be an admin-add");
      if (change.public_key !== signer) throw new CountersignError("policy log genesis admin-add must be self-signed (signer must equal the added key)");
    } else {
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run tests/policy-log.test.ts`
Expected: PASS (all describes).

- [ ] **Step 5: Commit**

```bash
git add src/policy/log.ts tests/policy-log.test.ts
git commit -m "feat(policy): PolicyLog append/fold + admin lifecycle + invariants"
```

---

## Task 4: PolicyLog.verifyChain (tamper + forgery resistance)

**Files:**
- Modify: `src/policy/log.ts` (add `verifyChain`)
- Test: `tests/policy-log.test.ts` (add "verifyChain" describe)

**Interfaces:**
- Produces: `verifyChain(): boolean` on `PolicyLog` — true iff every entry's `prev` links correctly, `seq` is contiguous from 0, genesis is a self-signed admin-add, and each entry's signature verifies against a key that was an active admin *immediately before* that entry (genesis verifies against its own added key).

- [ ] **Step 1: Write the failing tests (append to `tests/policy-log.test.ts`)**

```ts
describe("PolicyLog.verifyChain", () => {
  it("accepts an honest log", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    expect(log.verifyChain()).toBe(true);
  });
  it("rejects a tampered change (signature no longer matches)", () => {
    const log = bootstrapped();
    log.append({ kind: "rule-set", rule }, rootA.secretKey);
    const entries = JSON.parse(JSON.stringify(log.entries)) as typeof log.entries;
    (entries[1].change as { rule: Rule }).rule.quorum = 5; // tamper post-signature
    expect(new PolicyLog([...entries]).verifyChain()).toBe(false);
  });
  it("rejects an entry forged by a non-admin key", () => {
    const log = bootstrapped();
    // Hand-forge a role-set signed by adminB (never added) with a correct prev/seq.
    const prev = hashEntry(log.entries[0]);
    const unsigned = { countersign: "0.2" as const, seq: 1, change: { kind: "role-set" as const, role }, issued_at: "2026-01-01T00:00:00.000Z", prev, signer_public_key: adminB.publicKey };
    const signature = signContext(adminB.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    expect(new PolicyLog([...log.entries, { ...unsigned, signature }]).verifyChain()).toBe(false);
  });
  it("rejects a broken prev link", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    const entries = JSON.parse(JSON.stringify(log.entries)) as PolicyEntry[];
    entries[1].prev = "deadbeef";
    expect(new PolicyLog(entries).verifyChain()).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/policy-log.test.ts`
Expected: FAIL — `verifyChain` is not a function.

- [ ] **Step 3: Add `verifyChain` to `PolicyLog`**

```ts
  /** Walk the chain: contiguous seq, correct prev links, self-signed admin-add genesis,
   *  and every entry signed by a key active as an admin immediately before it. Total —
   *  never throws; returns false on any break. */
  verifyChain(): boolean {
    try {
      const admins = new Map<string, AdminKey>();
      let prevHash: string | null = null;
      for (let i = 0; i < this._entries.length; i++) {
        const e = this._entries[i];
        if (e.seq !== i) return false;
        if (e.prev !== prevHash) return false;
        const { signature, ...unsigned } = e;
        if (!verifyContext(e.signer_public_key, POLICY_CONTEXT, canonicalPolicyEntry(unsigned), signature)) return false;
        if (i === 0) {
          if (e.change.kind !== "admin-add" || e.change.public_key !== e.signer_public_key) return false;
        } else if (!admins.has(e.signer_public_key)) {
          return false; // signer was not an active admin at this point
        }
        // Fold this entry into the running admin set for the NEXT iteration's check.
        const c = e.change;
        if (c.kind === "admin-add") admins.set(c.public_key, { org: c.org, public_key: c.public_key, name: c.name });
        else if (c.kind === "admin-revoke") {
          if (admins.size <= 1) return false; // last-admin invariant must hold historically too
          admins.delete(c.public_key);
        }
        prevHash = hashEntry(e);
      }
      return true;
    } catch {
      return false;
    }
  }
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run tests/policy-log.test.ts`
Expected: PASS (all describes).

- [ ] **Step 5: Commit**

```bash
git add src/policy/log.ts tests/policy-log.test.ts
git commit -m "feat(policy): verifyChain (tamper + forgery resistance)"
```

---

## Task 5: resolveRule

**Files:**
- Create: `src/policy/resolve.ts`
- Test: `tests/policy-resolve.test.ts`

**Interfaces:**
- Consumes: `PolicyStore`, `ResolveDeps`, `RuleRequest`, `Rule` (`src/policy/types.js`); `validateRule` (`src/policy/validate.js`); `ApproverRegistry.activeKeyMap()` (`src/registry.js`); `normalizeActor` (`src/core/countersignature.js`); `Approver`, `IntentFields`, `RiskTier` (`src/core/types.js`); `CountersignError`.
- Produces: `resolveRule(ruleName: string, request: RuleRequest, deps: ResolveDeps): IntentFields`.

- [ ] **Step 1: Write the failing test `tests/policy-resolve.test.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PolicyLog } from "../src/policy/log.js";
import { resolveRule } from "../src/policy/resolve.js";
import { ApproverRegistry, createEnrollmentProof } from "../src/registry.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Role, Rule } from "../src/policy/types.js";

const org = generateKeypair(); // org-root (registry attester)
const agent = { id: "agent:x", keypair: generateKeypair() };
const cfo = generateKeypair();
const ceo = generateKeypair();

function enrolledRegistry(): ApproverRegistry {
  const reg = new ApproverRegistry();
  reg.enroll("m:cfo", cfo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });
  reg.enroll("m:ceo", ceo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:ceo", ceo.secretKey) });
  return reg;
}

function storeWith(role: Role, rule: Rule): PolicyLog {
  const admin = generateKeypair();
  const log = new PolicyLog();
  log.append({ kind: "admin-add", org: "o1", public_key: admin.publicKey, name: "root" }, admin.secretKey);
  log.append({ kind: "role-set", role }, admin.secretKey);
  log.append({ kind: "rule-set", rule }, admin.secretKey);
  return log;
}

describe("resolveRule", () => {
  const role: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] };
  const rule: Rule = { id: "u1", org: "o1", name: "big-refund", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 3600, risk_tier: "high" };

  it("resolves a rule into IntentFields that produce a valid Intent", () => {
    const store = storeWith(role, rule);
    const fields = resolveRule("big-refund", { summary: "Refund $9,000 to cust 42", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" });
    expect(fields.quorum).toBe(2);
    expect(fields.default).toBe("reject");
    expect(fields.timeout).toBe(3600);
    expect(fields.approvers.map((a) => a.actor).sort()).toEqual(["m:ceo", "m:cfo"]);
    expect(fields.approvers.every((a) => a.mode === "keyed" && a.public_key)).toBe(true);
    const intent = createIntent(fields, agent);
    expect(verifyIntent(intent)).toBe(true);
  });

  it("throws on an unknown rule name", () => {
    const store = storeWith(role, rule);
    expect(() => resolveRule("nope", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/no rule/i);
  });

  it("throws when a member has no active enrolled key", () => {
    const store = storeWith({ ...role, members: ["m:cfo", "m:unknown"] }, rule);
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/no active enrolled key/i);
  });

  it("throws when the rule references an unknown role", () => {
    const store = storeWith(role, { ...rule, roles: ["r-missing"] });
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/unknown role/i);
  });

  it("requires an action (from rule or request)", () => {
    const store = storeWith(role, { ...rule, action: undefined });
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/action/i);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/policy-resolve.test.ts`
Expected: FAIL — `resolve.js` not found.

- [ ] **Step 3: Write `src/policy/resolve.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { CountersignError } from "../core/errors.js";
import { normalizeActor } from "../core/countersignature.js";
import { validateRule } from "./validate.js";
import type { Approver, IntentFields } from "../core/types.js";
import type { ResolveDeps, RuleRequest } from "./types.js";

/**
 * Resolve a named rule into IntentFields for createIntent. The rule supplies the POLICY
 * (which roles approve, quorum, default, timeout); the request supplies the concrete
 * action context (summary, and optionally action/risk_tier overrides). Roles are expanded
 * into keyed approvers by looking each member's ACTIVE bound key up from the registry, so
 * a member with no active enrollment fails closed. Pure; never mints an Intent itself.
 */
export function resolveRule(ruleName: string, request: RuleRequest, deps: ResolveDeps): IntentFields {
  const rule = deps.store.getRule(deps.org, ruleName);
  if (!rule) throw new CountersignError(`no rule named "${ruleName}" for org ${deps.org}`);
  validateRule(rule);

  const memberActors = new Set<string>();
  for (const roleId of rule.roles) {
    const role = deps.store.getRoleById(deps.org, roleId);
    if (!role) throw new CountersignError(`rule "${ruleName}" references unknown role ${roleId}`);
    for (const m of role.members) memberActors.add(normalizeActor(m));
  }
  if (memberActors.size === 0) throw new CountersignError(`rule "${ruleName}" resolves to zero approvers`);
  if (memberActors.size < rule.quorum)
    throw new CountersignError(`rule "${ruleName}" needs quorum ${rule.quorum} but only ${memberActors.size} distinct approver(s) are available`);

  const active = deps.registry.activeKeyMap();
  const approvers: Approver[] = [];
  for (const actor of memberActors) {
    const keys = active.get(actor);
    if (!keys || keys.size === 0) throw new CountersignError(`approver ${actor} has no active enrolled key`);
    if (keys.size > 1) throw new CountersignError(`approver ${actor} has multiple active keys; policy resolution requires exactly one (rotate/revoke to disambiguate)`);
    approvers.push({ actor, mode: "keyed", public_key: [...keys][0] });
  }

  const action = request.action ?? rule.action;
  if (!action) throw new CountersignError(`rule "${ruleName}" has no action and the request supplied none`);
  const risk_tier = request.risk_tier ?? rule.risk_tier;
  if (!risk_tier) throw new CountersignError(`rule "${ruleName}" has no risk_tier and the request supplied none`);
  if (!request.summary) throw new CountersignError("request.summary is required");

  return { action, summary: request.summary, risk_tier, approvers, quorum: rule.quorum, timeout: rule.timeout_seconds, default: rule.default };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run tests/policy-resolve.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/policy/resolve.ts tests/policy-resolve.test.ts
git commit -m "feat(policy): resolveRule (rule -> IntentFields via registry)"
```

---

## Task 6: Barrel export + end-to-end integration test

**Files:**
- Create: `src/policy/index.ts`
- Modify: `src/index.ts` (add one export line)
- Test: `tests/policy-integration.test.ts`

**Interfaces:**
- Consumes: all of `src/policy/*`.
- Produces: `src/policy/index.ts` re-exporting everything; `src/index.ts` exposing the policy layer from the package root.

- [ ] **Step 1: Write `src/policy/index.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
export * from "./types.js";
export { validateRole, validateRule } from "./validate.js";
export { PolicyLog, canonicalPolicyEntry, hashEntry } from "./log.js";
export { resolveRule } from "./resolve.js";
```

- [ ] **Step 2: Add the export to `src/index.ts`**

Add this line alongside the other `export * from` lines:

```ts
export * from "./policy/index.js";
```

- [ ] **Step 3: Write the failing integration test `tests/policy-integration.test.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PolicyLog, resolveRule } from "../src/index.js";
import { ApproverRegistry, createEnrollmentProof } from "../src/registry.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";

describe("policy layer end-to-end", () => {
  it("bootstrap admin -> role -> rule -> resolve -> Intent, with a verifiable policy chain", () => {
    const root = generateKeypair();
    const org = generateKeypair();
    const agent = { id: "agent:x", keypair: generateKeypair() };
    const cfo = generateKeypair();
    const ceo = generateKeypair();

    const reg = new ApproverRegistry();
    reg.enroll("m:cfo", cfo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });
    reg.enroll("m:ceo", ceo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:ceo", ceo.secretKey) });

    const log = new PolicyLog();
    log.append({ kind: "admin-add", org: "o1", public_key: root.publicKey, name: "root" }, root.secretKey);
    log.append({ kind: "role-set", role: { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] } }, root.secretKey);
    log.append({ kind: "rule-set", rule: { id: "u1", org: "o1", name: "wire", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 7200, action: "treasury.wire", risk_tier: "critical" } }, root.secretKey);

    expect(log.verifyChain()).toBe(true);

    const fields = resolveRule("wire", { summary: "Wire $250k to escrow" }, { store: log, registry: reg, org: "o1" });
    const intent = createIntent(fields, agent);
    expect(verifyIntent(intent)).toBe(true);
    expect(intent.quorum).toBe(2);
    expect(intent.timeout).toBe(7200);

    // Round-trips through JSONL unchanged.
    const reloaded = PolicyLog.fromJSONL(log.toJSONL());
    expect(reloaded.verifyChain()).toBe(true);
    expect(reloaded.getRule("o1", "wire")?.action).toBe("treasury.wire");
  });
});
```

- [ ] **Step 4: Run to verify it fails, then passes after the exports exist**

Run: `npx vitest run tests/policy-integration.test.ts`
Expected: initially FAIL if `src/index.ts` export missing; PASS once Steps 1–2 are in.

- [ ] **Step 5: Run the whole suite + build**

Run: `npm run build && npm test`
Expected: build clean; all tests pass (existing 361 + the new policy tests).

- [ ] **Step 6: Commit**

```bash
git add src/policy/index.ts src/index.ts tests/policy-integration.test.ts
git commit -m "feat(policy): export policy layer + end-to-end integration test"
```

---

## Self-Review

**Spec coverage** (against `2026-07-18-policy-layer-admin-console-design.md`):
- §4 data model (Role, Rule, AdminKey) → Task 1 types. ✓
- §5 `resolveRule` → Task 5. ✓
- §5 `PolicyStore` interface → Task 1 (`PolicyStore`), implemented by `PolicyLog` (Task 3). ✓
- §5 signed hash-chained `PolicyLog`, org-root-admin-attested → Tasks 2–4. ✓ (context `countersign-policy-v0.2`; genesis self-signed root admin; verifyChain forgery/tamper). ✓
- §5 tests (unknown rule, unenrolled/revoked approver, quorum>1 guards, timeout bounds, chain tamper/forgery) → Tasks 1,3,4,5. ✓
- §8 admin lifecycle (one root at bootstrap, add more, cannot revoke last) → Task 3 (`admin-add` genesis self-sign, `admin-revoke` last-admin guard). ✓
- **Deferred to the console plan (not this plan):** the `apps/console` app, Postgres store, admin-passkey *access* flow (the library provides the verification primitives; the console consumes them), the audit UI. `resolveRule` and `PolicyLog` are the library foundation the console builds on.

**Placeholder scan:** none — every step has complete code and exact commands.

**Type consistency:** `PolicyLog` implements `PolicyStore` (Task 1 interface). `resolveRule(ruleName, request, deps)` signature matches Task 1's `ResolveDeps`/`RuleRequest` and is used identically in Tasks 5–6. `canonicalPolicyEntry`/`hashEntry` defined in Task 2 are used in Tasks 3–4. `IntentFields` shape (action/summary/risk_tier/approvers/quorum/timeout/default) matches `src/core/types.ts` verified during planning.

**Note for the executor:** run `npm run build` after Task 6 — the repo compiles with `tsc`; a type error in any policy file will surface there even if a single test file passed.

## Next plan

After this lands, the **console plan** (`apps/console`) covers: the Next.js app, the admin-passkey access/session flow (reusing `verifyWebAuthnAssertion`), the five screens (Approvers, Roles, Rules, Admins, Audit), a Postgres `PolicyStore`/registry/receipt backend for SaaS, and the Playwright onboard→role→rule→audit smoke test.
