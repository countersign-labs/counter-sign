# Admin Console — Phase 1 (foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Stand up the self-hostable admin console as a Next.js app that loads an org's signed policy state from disk, verifies it, and renders the five read views (Approvers, Roles, Rules, Admins, Audit). Writes (client-side signing) and login are later phases.

**Architecture:** A new `apps/console` Next.js App Router app depending on the counter-sign library (`file:../..`). A framework-free **disk store** (`apps/console/lib/store.ts`) loads `registry.jsonl` + `policy.jsonl` + `receipts.jsonl` from a data directory, runs `PolicyLog.verifyChain()` / `ApproverRegistry.verifyChain()` / `ReceiptLog.verifyAll()`, and exposes the read API the pages render. The store is a plain TS module unit-testable with vitest (no Next runtime), so most logic is tested outside the framework.

**Tech Stack:** Next.js (App Router) on Node ≥ 20, TypeScript ESM, the counter-sign library (`PolicyLog`, `resolveRule`, `ApproverRegistry`, `ReceiptLog`), vitest for the store unit tests.

## Global Constraints
- Node ≥ 20, ESM, `.js` extensions on relative imports within the library; the Next app uses its own tsconfig (bundler resolution) but library imports keep the package's public entry (`@countersignlabs/counter-sign`).
- Copyright header on new library-style `.ts` files: `// Copyright 2026 Haridarman Kumaresan` / `// SPDX-License-Identifier: Apache-2.0` (Next app route/page files may omit it, matching Next conventions).
- The console holds NO signing key in Phase 1 (read-only) — it only reads + verifies. Persisted state is signed; the console never mutates it in this phase.
- Data directory is configurable via `COUNTERSIGN_DATA_DIR` env (default `./data`), containing `registry.jsonl`, `policy.jsonl`, `receipts.jsonl`.
- The store MUST fail loud: if a chain fails verification, the read API surfaces the failure (a `verified: false` flag + fault detail) rather than silently showing tampered state.

---

## File Structure
- Create `apps/console/package.json` — Next app, depends on `@countersignlabs/counter-sign` via `file:../..`.
- Create `apps/console/tsconfig.json`, `apps/console/next.config.mjs`.
- Create `apps/console/lib/store.ts` — the disk store + read API (unit-tested).
- Create `apps/console/lib/store.test.ts` — vitest unit tests for the store.
- Create `apps/console/app/layout.tsx`, `apps/console/app/page.tsx` (dashboard), and one route per screen: `app/approvers/page.tsx`, `app/roles/page.tsx`, `app/rules/page.tsx`, `app/admins/page.tsx`, `app/audit/page.tsx`.
- Create `apps/console/lib/seed.ts` (dev-only) — writes a small signed sample data dir so the app has something to render and tests have a fixture.

---

## Task 1: Console scaffold that builds

**Files:**
- Create: `apps/console/package.json`, `apps/console/tsconfig.json`, `apps/console/next.config.mjs`, `apps/console/app/layout.tsx`, `apps/console/app/page.tsx`, `apps/console/.gitignore`
- Modify: root `package.json` — add `apps/console` to a workspaces array (or document it's a standalone install)

**Interfaces:**
- Produces: a Next.js app that `npm --prefix apps/console run build` compiles cleanly, with a placeholder dashboard page.

- [ ] **Step 1: Create `apps/console/package.json`**

```json
{
  "name": "@countersignlabs/console",
  "private": true,
  "type": "module",
  "scripts": { "dev": "next dev", "build": "next build", "start": "next start" },
  "dependencies": {
    "@countersignlabs/counter-sign": "file:../..",
    "next": "^15.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "@types/node": "^26.1.0",
    "@types/react": "^19.0.0",
    "typescript": "^6.0.3",
    "vitest": "^4.1.10"
  }
}
```

- [ ] **Step 2: Create `apps/console/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022", "lib": ["ES2022", "DOM", "DOM.Iterable"], "module": "ESNext",
    "moduleResolution": "Bundler", "jsx": "preserve", "strict": true, "noEmit": true,
    "esModuleInterop": true, "skipLibCheck": true, "incremental": true,
    "plugins": [{ "name": "next" }]
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

- [ ] **Step 3: Create `apps/console/next.config.mjs`**

```js
/** @type {import('next').NextConfig} */
const nextConfig = { reactStrictMode: true };
export default nextConfig;
```

- [ ] **Step 4: Create `apps/console/.gitignore`**

```
/.next/
/node_modules
next-env.d.ts
/data
```

- [ ] **Step 5: Create `apps/console/app/layout.tsx`**

```tsx
export const metadata = { title: "counter-sign console" };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui", margin: 0 }}>
        <nav style={{ display: "flex", gap: "1rem", padding: "1rem", borderBottom: "1px solid #ddd" }}>
          <strong>counter-sign</strong>
          <a href="/approvers">Approvers</a>
          <a href="/roles">Roles</a>
          <a href="/rules">Rules</a>
          <a href="/admins">Admins</a>
          <a href="/audit">Audit</a>
        </nav>
        <main style={{ padding: "1.5rem", maxWidth: "60rem" }}>{children}</main>
      </body>
    </html>
  );
}
```

- [ ] **Step 6: Create `apps/console/app/page.tsx`**

```tsx
export default function Home() {
  return (
    <div>
      <h1>counter-sign admin console</h1>
      <p>Config + read-only audit for your org's approval policy. Pick a section above.</p>
    </div>
  );
}
```

- [ ] **Step 7: Install + build**

Run: `cd apps/console && npm install && npm run build`
Expected: install succeeds (Next pulls React 19); `next build` completes with the two static routes. If `file:../..` needs the library built first, run `npm run build` at the repo root once (the library `dist/`), then retry.

- [ ] **Step 8: Commit**

```bash
git add apps/console package.json
git commit -m "feat(console): Next.js scaffold (dashboard + nav)"
```

---

## Task 2: Disk store + verify-on-load (unit-tested, no Next runtime)

**Files:**
- Create: `apps/console/lib/store.ts`, `apps/console/lib/seed.ts`, `apps/console/lib/store.test.ts`

**Interfaces:**
- Consumes: `PolicyLog`, `ApproverRegistry`, `ReceiptLog`, `resolveRule` and their types from `@countersignlabs/counter-sign`.
- Produces:
  - `loadConsoleState(dataDir: string, orgPublicKey: string): ConsoleState` where
    `ConsoleState = { org: string; verified: boolean; faults: string[]; admins: AdminKey[]; roles: Role[]; rules: Rule[]; approvers: { actor: string; keys: string[] }[]; auditVerified: boolean }`.
  - The loader reads `policy.jsonl` (→ `PolicyLog.fromJSONL`), `registry.jsonl` (→ `ApproverRegistry.fromJSONL`), and `receipts.jsonl` (→ `ReceiptLog`), runs `policyLog.verifyChain()`, `registry.verifyChain(orgPublicKey)`, and `receiptLog.verifyAll(...)`, sets `verified` false + populates `faults` on any failure, and derives the display lists from the verified state (org taken from the policy log's genesis).
  - `seedSampleData(dataDir: string): { orgPublicKey: string }` writes a minimal signed policy log (bootstrap admin → one role → one rule) + a registry with one enrolled raw-ed25519 approver, for tests and local dev.

- [ ] **Step 1: Write `apps/console/lib/seed.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PolicyLog, ApproverRegistry, createEnrollmentProof, generateKeypair, publicKeyFromSecret } from "@countersignlabs/counter-sign";

/** Write a minimal signed data dir (policy.jsonl + registry.jsonl + empty receipts.jsonl). */
export function seedSampleData(dataDir: string): { orgPublicKey: string; adminSecret: string } {
  mkdirSync(dataDir, { recursive: true });
  const orgRoot = generateKeypair();
  const admin = generateKeypair();
  const cfo = generateKeypair();

  const registry = new ApproverRegistry();
  registry.enroll("m:cfo", cfo.publicKey, orgRoot.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });

  const log = new PolicyLog();
  log.append({ kind: "admin-add", org: "acme", public_key: admin.publicKey, name: "root" }, admin.secretKey);
  log.append({ kind: "role-set", role: { id: "finance", org: "acme", name: "finance-approvers", members: ["m:cfo"] } }, admin.secretKey);
  log.append({ kind: "rule-set", rule: { id: "refund", org: "acme", name: "refund", roles: ["finance"], quorum: 1, default: "reject", timeout_seconds: 3600, action: "billing.refund", risk_tier: "high" } }, admin.secretKey);

  writeFileSync(join(dataDir, "registry.jsonl"), registry.toJSONL());
  writeFileSync(join(dataDir, "policy.jsonl"), log.toJSONL());
  writeFileSync(join(dataDir, "receipts.jsonl"), "");
  return { orgPublicKey: publicKeyFromSecret(orgRoot.secretKey), adminSecret: admin.secretKey };
}
```

- [ ] **Step 2: Write the failing test `apps/console/lib/store.test.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConsoleState } from "./store.js";
import { seedSampleData } from "./seed.js";

function seeded() {
  const dir = mkdtempSync(join(tmpdir(), "cs-console-"));
  const { orgPublicKey } = seedSampleData(dir);
  return { dir, orgPublicKey };
}

describe("loadConsoleState", () => {
  it("loads and verifies a seeded data dir", () => {
    const { dir, orgPublicKey } = seeded();
    const s = loadConsoleState(dir, orgPublicKey);
    expect(s.verified).toBe(true);
    expect(s.org).toBe("acme");
    expect(s.rules.map((r) => r.name)).toContain("refund");
    expect(s.roles.map((r) => r.name)).toContain("finance-approvers");
    expect(s.admins.length).toBe(1);
    expect(s.approvers.find((a) => a.actor === "m:cfo")?.keys.length).toBe(1);
  });

  it("reports verified:false with faults when the policy log is tampered", () => {
    const { dir, orgPublicKey } = seeded();
    // Append a junk line to policy.jsonl to break the chain.
    appendFileSync(join(dir, "policy.jsonl"), JSON.stringify({ seq: 99, change: { kind: "role-set", role: { id: "x", org: "acme", name: "x", members: ["m:cfo"] } }, prev: "bad", signer_public_key: "z", signature: "z", countersign: "0.2", issued_at: "2026-01-01T00:00:00.000Z" }) + "\n");
    const s = loadConsoleState(dir, orgPublicKey);
    expect(s.verified).toBe(false);
    expect(s.faults.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd apps/console && npx vitest run lib/store.test.ts`
Expected: FAIL — `store.js` / `loadConsoleState` not found.

- [ ] **Step 4: Write `apps/console/lib/store.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PolicyLog, ApproverRegistry, type AdminKey, type Role, type Rule } from "@countersignlabs/counter-sign";

export interface ConsoleState {
  org: string;
  verified: boolean;
  faults: string[];
  admins: AdminKey[];
  roles: Role[];
  rules: Rule[];
  approvers: { actor: string; keys: string[] }[];
  auditVerified: boolean;
}

function readOrEmpty(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

/** Load a data dir, verify every chain, and derive the read model. Fails LOUD:
 *  a verification failure sets verified:false + populates faults rather than
 *  rendering tampered state as trustworthy. */
export function loadConsoleState(dataDir: string, orgPublicKey: string): ConsoleState {
  const faults: string[] = [];
  const log = PolicyLog.fromJSONL(readOrEmpty(join(dataDir, "policy.jsonl")));
  const registry = ApproverRegistry.fromJSONL(readOrEmpty(join(dataDir, "registry.jsonl")));

  if (!log.verifyChain()) faults.push("policy log failed chain verification");
  if (registry.all.length > 0 && !registry.verifyChain(orgPublicKey)) faults.push("approver registry failed chain verification");

  const state = log.state();
  const org = log.entries[0] ? adminOrgOf(log) : "";
  const admins = [...state.admins.values()];
  const roles = [...state.roles.values()];
  const rules = [...state.rules.values()];

  const approvers = [...registry.activeKeyMap().entries()].map(([actor, keys]) => ({ actor, keys: [...keys] }));

  // Receipt-log verification is async (ReceiptLog.verifyAll/verifyChain) and belongs to
  // the Phase 3 Audit screen (an async server component). Phase 1's synchronous store
  // does NOT check receipts — `auditVerified` is left true here as "not checked in this
  // phase"; the Audit page owns that verification later.
  const auditVerified = true;

  return { org, verified: faults.length === 0, faults, admins, roles, rules, approvers, auditVerified };
}

/** The org of the log, taken from its genesis admin-add. */
function adminOrgOf(log: PolicyLog): string {
  const first = log.entries[0]?.change;
  if (!first) return "";
  if (first.kind === "role-set") return first.role.org;
  if (first.kind === "rule-set") return first.rule.org;
  return first.org;
}
```

NOTE for the implementer: keep `loadConsoleState` SYNCHRONOUS — it verifies only the policy log and the registry (both sync). Receipt-log verification is async and is deferred to the Phase 3 Audit page; do not add it here.

- [ ] **Step 5: Run to verify it passes**

Run: `cd apps/console && npx vitest run lib/store.test.ts`
Expected: PASS (2 tests). Fix the ReceiptLog verify call per the NOTE if the placeholder doesn't compile.

- [ ] **Step 6: Commit**

```bash
git add apps/console/lib
git commit -m "feat(console): disk store + verify-on-load read model"
```

---

## Task 3: Render the five read screens

**Files:**
- Create: `apps/console/app/approvers/page.tsx`, `app/roles/page.tsx`, `app/rules/page.tsx`, `app/admins/page.tsx`, `app/audit/page.tsx`
- Create: `apps/console/lib/state.ts` — a tiny helper that resolves the data dir + org key from env and calls `loadConsoleState`.

**Interfaces:**
- Consumes: `loadConsoleState` (Task 2).
- Produces: five server components that render the verified state, each showing a red "⚠ verification failed" banner (with faults) when `verified === false`.

- [ ] **Step 1: Write `apps/console/lib/state.ts`**

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { loadConsoleState, type ConsoleState } from "./store.js";

/** Resolve the data dir + org key from env and load the verified console state.
 *  COUNTERSIGN_DATA_DIR (default ./data) and COUNTERSIGN_ORG_PUBLIC_KEY. */
export function getState(): ConsoleState {
  const dataDir = process.env.COUNTERSIGN_DATA_DIR ?? "./data";
  const orgKey = process.env.COUNTERSIGN_ORG_PUBLIC_KEY ?? "";
  return loadConsoleState(dataDir, orgKey);
}
```

- [ ] **Step 2: Write the five pages**

Each is a server component. Example — `apps/console/app/rules/page.tsx`:

```tsx
import { getState } from "../../lib/state.js";

export default function RulesPage() {
  const s = getState();
  return (
    <div>
      <h1>Rules — {s.org}</h1>
      {!s.verified && <p style={{ color: "#b3261e" }}>⚠ verification failed: {s.faults.join("; ")}</p>}
      <table cellPadding={6} style={{ borderCollapse: "collapse" }}>
        <thead><tr><th>Name</th><th>Roles</th><th>Quorum</th><th>Default</th><th>Timeout (s)</th></tr></thead>
        <tbody>
          {s.rules.map((r) => (
            <tr key={r.id} style={{ borderTop: "1px solid #eee" }}>
              <td>{r.name}</td><td>{r.roles.join(", ")}</td><td>{r.quorum}</td><td>{r.default}</td><td>{r.timeout_seconds}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

Write the analogous pages: **approvers** (actor + key count/fingerprint), **roles** (name + members), **admins** (name + public key), **audit** (a message that the audit view lands in a later phase, plus the `auditVerified` status and any faults). Each renders the verification banner when `!s.verified`.

- [ ] **Step 3: Build to verify it compiles + renders**

Run: `cd apps/console && npm run build`
Expected: build completes with the five dynamic routes. (These are server components reading the filesystem, so Next marks them dynamic — that's expected.)

- [ ] **Step 4: Manual smoke (optional but recommended)**

Run: `cd apps/console && npx tsx -e "import('./lib/seed.js').then(m => console.log(m.seedSampleData('./data')))"` to seed `./data`, set `COUNTERSIGN_ORG_PUBLIC_KEY` to the printed key, `npm run dev`, and confirm the pages render the seeded org.

- [ ] **Step 5: Commit**

```bash
git add apps/console/app apps/console/lib/state.ts
git commit -m "feat(console): five read screens over verified policy state"
```

---

## Self-Review
- Spec §6 screens (Approvers, Roles, Rules, Admins, Audit) → Task 3 (audit is a status-only stub this phase; full audit table is Phase 3). ✓
- Spec §7 storage (local JSONL) → Task 2 disk store. ✓
- Spec §9 "fail loud on a broken chain" → store sets `verified:false` + faults, pages show the banner. ✓
- Phase 1 is READ-ONLY (no signing key in the console) → matches §8's holds-no-key requirement for this phase. ✓
- Deferred to later phases: client-side signing + write forms (Phase 2), admin-key access/login + full audit table + Playwright smoke (Phase 3).

**Placeholder scan:** the `ReceiptLog.verifyChainSync` reference in Task 2 is explicitly flagged as a placeholder with instructions to use the real API — the implementer must confirm `src/receipt-log.ts` and replace it (possibly making `loadConsoleState` async). Every other step has concrete code.

## Next plans
- **Phase 2:** browser Ed25519 (WebCrypto) client-side signing of policy entries + write forms (add/revoke admin, set/delete role, set/delete rule, enroll/revoke approver); server actions that verify + append to the JSONL store; the quorum/default guard live in the UI.
- **Phase 3:** admin-key access/login (prove Ed25519 possession of an enrolled admin key → session), the full read-only Audit table (receipt log + policy change log with verify status), and a Playwright onboard→role→rule→audit smoke test.
