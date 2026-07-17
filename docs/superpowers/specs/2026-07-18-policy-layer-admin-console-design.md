# Policy layer + admin console — design

Status: draft for review
Date: 2026-07-18
Owner: Haridarman

## 1. Summary

Add a **policy/role layer** to the counter-sign library and a self-hostable
**admin console** on top of it. An admin onboards approvers, groups them into
**roles**, and writes **rules** (which roles must approve, quorum, the default on
no-confirmation, and the timeout window). An agent then references a rule *by
name*, and the library resolves it into a concrete signed Intent using the
existing `createIntent`.

The console is **configuration + read-only audit** only. It does not host the
approval runtime, hold the authority key, or hold any approver/admin private key.
It is built as a reference app that can grow into a hosted multi-tenant SaaS
without a rewrite (every store row is `org`-scoped from day one).

## 2. Motivation and current state

Three things prompted this, and two already exist in the protocol:

- **"The timeout is too small."** Not a limit — `Intent.timeout` already accepts
  `1 .. MAX_TIMEOUT_SECONDS` (2,147,483 s ≈ 24.8 days;
  `src/core/intent.ts`). The demos just use 300 s. The real gap is *ergonomics*:
  there is no place for an adopter to set a window (in human units) once, per
  rule, instead of hand-coding it per Intent.
- **"Admin sets the default (yes/no) on no-confirmation."** Already a first-class
  field: `Intent.default: "approve" | "reject"` (`src/core/types.ts`). Safety
  invariant already enforced: `quorum > 1` may not combine with
  `default: "approve"` (a timeout must never bypass required approvers,
  `src/core/intent.ts`). The gap is letting an admin set it per *rule* in a UI.
- **Onboarding.** Already exists: `ApproverRegistry` (`src/registry.ts`) + the
  `enroll` CLI do org-root-attested, hash-chained `actor → key` binding with
  proof-of-possession. The gap is a UI wrapper.

What is genuinely new: (a) a **role/rule abstraction** that produces Intents from
admin-defined rules, and (b) an **admin console** to manage onboarding, roles,
rules, and view audit history. There is no front-end today beyond the `docs/`
landing page.

## 3. Goals / non-goals

**Goals (v1)**
- A pure, framework-free policy layer in the library: `Role`, `Rule`,
  `resolveRule()`, a pluggable `PolicyStore`, and validation mirroring the Intent
  invariants.
- Rule/role changes are **cryptographically signed and hash-chained**
  (org-root-admin-attested), mirroring `ApproverRegistry`. A compromised console
  cannot silently alter a rule.
- A self-hostable Next.js admin console: Approvers, Roles, Rules, Audit.
- Multi-tenant-ready schema (`org` scope everywhere); works single-org today.

**Non-goals (v1, explicitly deferred)**
- Hosting the `SigningServer` / live approval runtime (the "full control plane").
- A live "pending approvals" dashboard, notifications, or dispatch.
- Billing, org self-signup, admin-account management / RBAC-of-admins.
- Signed **rules** do *not* change the wire format; this is a config layer that
  produces Intents through the existing `createIntent`.

## 4. Data model

All entities are `org`-scoped.

- **Approver** *(exists — registry entry)*: `actor` id, display name, bound public
  key (raw ed25519 or a `webauthn-*` passkey descriptor), enrollment status
  (active/revoked). Managed through `ApproverRegistry` + `enroll`. The console
  onboards a **public** key only; proof-of-possession is required by the registry.
- **Role** *(new)*: `{ id, org, name, description, members: string[] }` where
  `members` are approver `actor` ids. Membership only — no rule logic.
- **Rule** *(new — the named policy)*:
  `{ id, org, name, roles: string[], quorum: number, default: "approve" | "reject", timeout_seconds: number, risk_tier?: string, action?: string }`.
  `name` is what an agent references. `roles` are the role ids whose members may
  approve. Invariants (validated at write time and in `resolveRule`):
  - `quorum >= 1`, integer.
  - `timeout_seconds` in `[1, MAX_TIMEOUT_SECONDS]`.
  - `quorum > 1 ⇒ default === "reject"` and every referenced approver must be
    **keyed** (raw ed25519 or passkey) — matches `createIntent`'s rule that a
    vouched slot cannot fill a multi-person quorum.

## 5. Library additions (pure TS, in the counter-sign package)

New module `src/policy.ts` (or `src/policy/`):

- `Role`, `Rule` types + a JSON Schema (draft 2020-12) alongside the existing
  Intent/Countersignature schemas.
- **`resolveRule(ruleName, org, deps) → IntentFields`**: looks up the rule from
  the `PolicyStore`, expands `roles` into a concrete `approvers` list by reading
  each member's active bound key from the `ApproverRegistry` (via the existing
  `assertApproversEnrolled`), applies quorum/default/timeout, validates the
  invariants, and returns the fields for `createIntent`. Pure and deterministic
  given its inputs; **reusable by the console and by an adopter's own runtime.**
- **`PolicyStore`** interface (modeled on `ReceiptSink`): CRUD for roles + rules,
  `org`-scoped. The registry remains the source of truth for `actor → key`; the
  store holds only roles + rules that *reference* actor ids.
- **Signed, hash-chained policy log.** Every role/rule create/update/delete is a
  signed entry in an append-only, hash-chained log (`PolicyLog`), reusing the
  same primitives as `ApproverRegistry` (`signContext` with a new domain-separation
  context, e.g. `countersign-policy-v0.1`; `prev`-hash chaining; `head()`
  checkpoint). Signed by an **org-root admin key** — the admin key of §8 (one at
  bootstrap; admins can add more), distinct from the runtime authority key. `verifyPolicyChain()` walks the links; `resolveRule` uses only
  the latest *verified* state. The console **relays and verifies** changes — the
  admin key is never held by the console; a CLI or passkey signs the change
  (proof-of-possession, exactly as approver enrollment works).

Tests (conformance-style, matching the existing suite's rigor):
- `resolveRule` expands roles → approvers correctly and pins each member's bound
  key.
- Rejects: unknown rule, unknown/empty role, unenrolled or revoked approver,
  `quorum > 1` with `default: "approve"`, `quorum > 1` with a vouched member,
  out-of-range timeout.
- `PolicyLog` sign/verify: a tampered or reordered entry fails
  `verifyPolicyChain`; an entry signed by a non-org-root key is rejected.

## 6. Console app (`apps/console`)

Next.js App Router on Vercel. Five screens:

1. **Approvers** — list enrolled approvers with status; onboard a new one (name +
   public key or passkey enrollment, driven through the registry/`enroll` flow,
   proof-of-possession); revoke.
2. **Roles** — CRUD roles; add/remove approver members.
3. **Rules** — CRUD rules; pick role(s), set quorum, set `default` (the UI
   disables `approve` when `quorum > 1`), set the timeout in human units
   (minutes/hours/days → stored seconds). Live validation via the library's
   `resolveRule`/validation so the UI never saves an unsafe rule.
4. **Admins** — list admin keys; the root admin (or any admin) enrolls an
   additional admin key (name + passkey/raw-ed25519 enrollment, signed by an
   existing admin) and revokes one. The UI enforces the safety invariant: the
   last remaining admin key cannot be revoked.
5. **Audit** — read-only:
   - The **receipt log**: past decisions (action, decision, approver(s),
     `policy` = `approver` vs `default`, timestamps) with chain-intact status
     from `verifyChain`/`verifyAll`.
   - The **policy change log**: who changed which rule/role/admin, when,
     before/after, with `verifyPolicyChain` status.

Server side: Next.js server actions / route handlers call the library
(`PolicyStore`, `ApproverRegistry`, a `ReceiptSink` reader). All signing happens
**client-side or via CLI**, never on the server — the console holds no signing
key and only verifies + appends:
- A **rule/role change** is signed by the org-root admin key.
- An **enrollment** carries two signatures: the org-root admin key attests the
  `actor → key` binding, and the approver proves possession of the key being
  bound (a raw-ed25519 self-signature or a WebAuthn passkey assertion).

## 7. Storage

- **Local / self-host**: SQLite or a JSON file for the `PolicyStore`, registry
  file, and receipt-log file.
- **SaaS-ready**: Postgres (Vercel Marketplace). `PolicyStore`, `ReceiptSink`,
  and the registry each get a Postgres implementation. Every row carries `org`;
  every query is `org`-scoped. No cross-org read path exists.

## 8. Access and key separation — the admin key

The console is **admin-only**: no signup, no non-admin access, ever. Access is
gated by an **admin key**, not a password. Setup starts with a single **root
admin key**; that admin can enroll additional admin keys (see lifecycle below).
Each is held as a **passkey (WebAuthn)** or raw ed25519 key, enrolled and
attested like approvers. One concept does double duty, and the two uses are kept
distinct:

- **Reaching the UI** (even on a public URL): a WebAuthn ceremony proving
  possession of an enrolled admin key establishes a session. No password, no
  shared secret — only a holder of an enrolled admin key gets in. (A localhost
  dev mode may bypass this for convenience; production/URL always requires it.)
- **Authorizing a change** (what makes a rule/role/enrollment write *valid*):
  each write requires a **fresh** admin-key signature over that specific change —
  which *is* the org-root signature on the signed policy-log entry (§5). A stolen
  session therefore still cannot alter a rule without a fresh ceremony, and the
  signed log records *which* admin key signed each change, so the signature — not
  a session — is the identity of record (per-admin audit, no account system).

**Admin-key lifecycle.** Setup establishes exactly **one** admin key — the root
admin, self-declared at bootstrap and the initial trust anchor. That admin can
then **enroll additional admin keys** from the console (each addition signed by
an existing admin key) and revoke them the same way, mirroring the registry's
org-root model. Safety invariant: the **last remaining admin key cannot be
revoked** (no lock-out). There is no fixed cap — you run with one until you
choose to add more.

**Reuse.** Both access and change-authorization go through the same passkey
verification path already in the library (`verifyWebAuthnAssertion` and the
`SigningServer` ceremony), so no new crypto is introduced — the console is a new
consumer of an existing, hardened surface. Cost note: a passkey access flow
(register/assert + session) is more to build than a single env secret, and is
the deliberate trade for a URL-exposable admin console with per-admin identity.

## 9. Security model

- The console holds **no private keys** — not the runtime authority key, not
  approver keys (public/passkey only, registry-attested), not the org-root admin
  key (changes are signed out-of-band by CLI/passkey, relayed + verified).
- Because the console is config + read-only audit and holds no authority key, its
  compromise **cannot forge an approval**. The worst it can do is *display* wrong
  data or *attempt* a rule change — which fails without a valid org-root
  signature, and every accepted change is in the verifiable policy chain.
- Strict `org` isolation on every store access.
- The existing `verifyResolution` / keyed-quorum guarantees are untouched: rules
  only *produce* Intents; every downstream verification is unchanged.

## 10. Testing

- **Library**: unit + conformance tests for `resolveRule`, the rule/role
  invariants, and `PolicyLog` sign/verify (as in §5).
- **Console**: component/integration tests for the CRUD flows and the
  quorum/default guard; a Playwright **onboard → role → rule → audit** smoke test,
  reusing the existing human-sim/browser tooling.

## 11. Future / revisitable

- Richer admin management (org self-signup, tiers/roles of admins, delegated
  permissions) — deferred to SaaS. v1 already has per-admin identity for free via
  the admin-key signatures; SaaS adds the org/account management around it.
- Full control plane: host the `SigningServer`, live pending dashboard,
  notifications, dispatch.
- Org self-signup, billing, admin-user management.
- Optional: sign the *audit export* so a downloaded history is independently
  verifiable off-console.

## 12. Open questions

- Exact `PolicyStore` local backend: SQLite vs flat JSON for v1 (leaning SQLite
  for query ergonomics; JSON is simpler to inspect/diff). Decide at plan time.
- Whether roles are also referenced by *risk_tier*/*action* auto-matching in a
  later version, or always by explicit rule name (v1: explicit rule name only).
