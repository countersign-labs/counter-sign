# Per-approver-key quorum — Phase 1 (protocol core)

**Status:** Design, awaiting review
**Date:** 2026-07-16
**Author:** Haridarman Kumaresan (with Claude)
**Milestone:** resolves the documented "single authority key defeats M-of-N" trust-model gap (spec §1 *Trust model*, §6 planned extension). Raised in external review: *"all approvals are signed by a single Authority Key… anyone with access to key has super powers."*

## Problem

`Intent.approvers` is a list of **actor strings**; every countersignature — including all N in an M-of-N quorum — is signed by the **single authority key** held by the integration server. `verifyResolution` enforces quorum by counting distinct actor strings, all verified against that one key. Therefore a holder of the authority key can mint `quorum` receipts with distinct `actor` values and satisfy "2 managers approved" alone. Four-eyes is a control the *trusted authority* enforces, not one the mathematics enforces against that authority. This is acceptable only under a trusted-server threat model; it fails an audit that expects cryptographic segregation of duties.

## Goal

Give each approver the option to sign with **their own key**, so that a **compromised or malicious authority server cannot forge a quorum**, and a quorum receipt is independently verifiable as "these N distinct people each signed." Preserve the frictionless button flow where crypto separation isn't needed.

## Threat model (decided)

Defend against a **compromised/malicious authority-key holder** (breached integration server, rogue admin). Out of scope for Phase 1: compromise of an approver's own key/device (later hardening), and compromise of the *agent* key (the agent authors Intents by definition; agent and authority keys MUST remain distinct — already recommended in spec §5, and load-bearing here).

## Approach (decided)

Two approval **modes**, chosen **per approver** on each Intent:

- **`vouched`** — today's flow. The server signs "actor X approved" with the authority key. A button press suffices. Fine for low-stakes.
- **`keyed`** — approver X signs the receipt with **their own** key. The server never holds it, so it cannot forge it, and the receipt verifies independently as X's.

Phase 1 implements `keyed` with **raw ed25519** signatures (a CLI/programmatic signer). The passkey/WebAuthn UX for humans is **Phase 2**; the enrollment/registry that sources approver keys is **Phase 3**. Phase 1 is fully testable end-to-end with a CLI signer and is the part that actually closes the hole.

## Scope

**In scope (Phase 1):**
- v0.2 Intent wire format: keyed approvers with bound public keys (back-compatible parse of the v0.1 `string[]`).
- Keyed countersignatures (raw ed25519, signed by the approver key).
- `verifyResolution` per-approver-mode verification.
- The quorum guardrail (`quorum > 1` ⇒ all approvers keyed).
- A minimal `approve` signer (library function + CLI) so a keyed approver/bot can produce a receipt.
- Tests, including the headline: an authority-key holder **cannot** satisfy a keyed 2-of-2.

**Out of scope (later phases):** passkey/WebAuthn signing page and adapter deep-links (Phase 2); approver enrollment / `actor → pubkey` registry / IdP integration (Phase 3); the keyed, self-anchoring receipt log (separate §6 item).

**Non-goals:** changing single-approver `vouched` behavior; changing the Default/timeout mechanism (the timeout Default stays authority-minted — for a keyed quorum it is always `reject`, i.e. fail-closed non-authorization, which is not a separation-of-duty artifact).

## Design

### Wire format (`countersign: "0.2"`)

An approver becomes an object; `Intent.approvers` is `Approver[]`:

```ts
type ApproverMode = "vouched" | "keyed";
interface Approver {
  actor: string;                 // channel:address, as today
  mode: ApproverMode;            // default "vouched" on parse of a bare string
  public_key?: string;           // base64url raw ed25519; REQUIRED iff mode === "keyed"
}
```

- **Back-compat:** a v0.1 `approvers: string[]` parses to `[{actor, mode:"vouched"}]` for each string, so existing Intents and adapters behave exactly as before. `IntentFields.approvers` accepts `(string | Approver)[]` and normalizes.
- `COUNTERSIGN_VERSION` → `"0.2"`; `INTENT_CONTEXT` → `"countersign-intent-v0.2"` (the signed bytes change). `COUNTERSIGNATURE_CONTEXT` → `"countersign-countersignature-v0.2"`. Domain separation is preserved; a v0.1 and v0.2 artifact can never share a signature.

### Countersignature

Shape is unchanged. For a **keyed** receipt, `public_key` is the **approver's** key (not the authority's); the signature is the approver's. The receipt does not self-declare its mode — the **Intent** (agent-signed) is the source of truth for each actor's mode and bound key, so the mode is not attacker-controllable via the receipt.

### Verification rule (`verifyResolution`)

For each receipt, resolve the approver entry from `intent.approvers` by normalized `actor`, then:

- **`keyed`:** require `receipt.public_key === entry.public_key` **and** `verifyCountersignature(receipt, { trustedKeys: entry.public_key })`. The receipt must be signed by the bound approver key.
- **`vouched`:** require the receipt be signed by the **authority** key, exactly as today.
- A keyed slot satisfied by an authority-signed (vouched) receipt is **rejected**, and vice versa — the mode/key binding is enforced, not merely the actor string.

Quorum counting is unchanged (distinct approver actors), but a receipt only counts once it has verified **under its approver's declared mode**. The timeout Default remains authority-signed and is handled by the existing `policy:"default"` branch (unchanged; keyed quorums are `default:"reject"`).

Why this resists a compromised authority server: keyed receipts require approver private keys the server lacks; the `actor → public_key` binding lives in the **agent-signed** Intent, so a compromised *authority* key can neither forge keyed receipts nor swap the bound keys (that would break the agent signature). Residual trust: the agent key and the source of approver keys (Phase 3).

### Guardrail (Intent creation / `assertIntentInvariants`)

- `quorum > 1` ⇒ **every** approver MUST be `keyed` (throw otherwise) — a "four-eyes" can never be silently all-`vouched` (server-forgeable). (Composes with the existing `quorum > 1` ⇒ `default:"reject"` rule.)
- Each `keyed` approver MUST carry a syntactically valid `public_key`; keyed approver keys MUST be distinct (one key can't fill two slots).

### Signing (Phase 1)

- Library: a keyed approver signs the canonical receipt with their ed25519 secret key (reuse `signDecision` with the approver key + the keyed context, or a thin `signApproverDecision` wrapper).
- A minimal `countersign approve --intent <file> --key <approver-secret> --decision approve|reject` CLI that emits a keyed receipt. This is what makes Phase 1 exercisable and is what a bot/CI approver uses directly.

### Backward compatibility

v0.1 Intents (`approvers: string[]`, all-`vouched`) remain valid via back-compat parsing, and the shipped adapters produce `vouched` receipts and are untouched in Phase 1 — the runtime *behavior* of an all-vouched flow is unchanged. Note this is still a **breaking wire change** (the canonical Intent shape and version bump to `0.2`), so example payload fixtures are regenerated at `0.2` and a few tests that hard-code the v0.1 approver shape or version string are updated. Keyed behavior itself is purely additive.

## Testing strategy

- **Wire/back-compat:** `string[]` approvers parse to all-`vouched`; round-trip and signature-verify a v0.2 Intent with mixed modes.
- **Keyed verify — positive:** a 2-of-2 keyed quorum with two distinct approver-key receipts verifies.
- **Keyed verify — negatives:** wrong key; authority key presented for a keyed slot; a keyed receipt presented for a vouched slot; a keyed receipt whose `public_key` ≠ the bound key.
- **Headline (resolves the finding):** holding **only the authority key**, you cannot satisfy a keyed 2-of-2 — every attempt (two authority-signed receipts with distinct actors) is rejected by `verifyResolution`.
- **Guardrail:** `createIntent` throws on `quorum > 1` with any `vouched` approver, on a `keyed` approver missing a key, and on duplicate approver keys.
- **Distinctness still holds:** one keyed approver can't fill a multi-person quorum via actor variants (existing CS-hardening carried forward).

## Deferred decisions (do not block Phase 1)

- **Enrollment / key trust (Phase 3):** how `actor → public_key` is sourced and attested (standalone attested registry vs. existing IdP such as Okta/Google Workspace). Phase 1 takes approver keys as caller-provided input to `createIntent`, bound into the agent-signed Intent.
- **Passkey/WebAuthn (Phase 2):** the browser signing ceremony and adapter deep-links.

## Rollout

Ship as **v0.2** (breaking wire change, per the spec's minor-bump-until-1.0 policy). Update spec §1/§3/§6 to describe keyed quorum as delivered (Phase 1), with Phases 2–3 still noted as planned.
