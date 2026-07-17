![counter-sign — an agent signs its intent; a human countersigns it into authority.](assets/banner.svg)

# counter-sign

**MCP gave agents tools. A2A gave agents colleagues. counter-sign gives agents a boss.**

**[countersignlabs.com](https://countersignlabs.com)** · [Spec](spec/countersign-spec.md) · [Releases](https://github.com/countersign-labs/counter-sign/releases)

[![counter-sign in motion — an autonomous agent's $42,000 action is gated, a human taps Approve, and a signed portable receipt is produced.](assets/countersign-brag.gif)](assets/countersign-brag.mp4)

counter-sign is an open protocol for agent-to-human authorization: an agent
signs its intent; a human countersigns it into authority.

The agent stack has a missing leg. MCP standardizes **agent-to-tool**. A2A
standardizes **agent-to-agent**. Neither says what happens at the moment
that actually matters — when an agent is about to do something irreversible
and needs a human's yes, on whatever channel that human actually reads.
counter-sign standardizes **agent-to-human authority** with four nouns and
nothing else:

- **Intent** — a signed JSON envelope: what the agent wants to do, the risk
  tier, who may approve it, how many must approve (`quorum`, for two-person /
  M-of-N control), how long to wait, and what silence means.
- **Route** — delivery to where approvers live (Telegram, Discord, Slack,
  WhatsApp, email) via deliberately dumb, pluggable adapters.
- **Countersignature** — a signed, portable receipt of the decision,
  verifiable offline by any party. The only artifact that conveys authority.
- **Default** — declared timeout behavior. Silence is never ambiguous.

Read the spec: [spec/countersign-spec.md](spec/countersign-spec.md) (~3 pages).

## Quickstart

Add approval to any tool call in five lines:

```ts
import { wrapAction } from "@countersignlabs/counter-sign";
import { TelegramAdapter } from "@countersignlabs/counter-sign/adapters/telegram";

const deploy = wrapAction(deployProd,
  { action: "deploy.prod", summary: "Deploy v2.1.0 to production", risk_tier: "high",
    approvers: ["telegram:8675309"], timeout: 300, default: "reject" },
  new TelegramAdapter());
await deploy("v2.1.0");
```

On approve, `deployProd` runs. On reject — explicit or by timeout default —
it throws `IntentRejectedError` carrying the signed Countersignature as the
audit receipt. Try it with zero tokens:

```sh
npm install && npm run demo:local    # approver is you, at this terminal
npm run demo:email                   # full email flow, offline, no accounts
```

## Adapters

All seven adapters implement one interface — `deliver(intent)` plus a
decision callback returning a `Countersignature`. The five chat/email channels
are configured via env vars (see [.env.example](.env.example) and
[adapters/README.md](adapters/README.md) for setup); the local approver needs
none:

| Channel  | Setup effort | Interaction pattern |
| -------- | ------------ | ------------------- |
| Telegram | Low — a BotFather token | Buttons → callback webhook (or long-poll: no public URL needed) |
| Discord  | Medium — app + bot + public interactions endpoint | Buttons → interaction webhook (ed25519-verified) |
| Slack    | Medium — app, bot token, signing secret, public URL | Block Kit buttons → interactivity webhook (signature-verified) |
| WhatsApp | High — Meta app, approved template, webhook | Template quick-reply buttons → webhook (Meta Cloud API only) |
| Email    | Low — any SMTP credentials | Signed single-use links → confirm-page POST (GET never decides) |
| Signing link | Medium — mount a `SigningServer`, pick a delivery callback | Per-approver deep-links → passkey (WebAuthn) ceremony in the approver's browser |
| Local    | None | stdin approve/reject (demos, tests, CI) |

A Countersignature is byte-for-byte the same shape and equally verifiable
whichever adapter produced it — receipts don't care whether the yes came
from a chat button, an email link, or a passkey ceremony.

**Two-person / M-of-N approval.** Set `quorum: N` on an Intent to require N
*distinct* approvers before the action runs; any single approver vetoes. Two
strengths exist, and the Intent's `approvers` declare which one you get:

- **Vouched** (chat channels): the trusted authority observes the person's
  response and vouches for it with the authority key. That is enforcement, not
  proof — a holder of the authority key could mint such a receipt — so vouched
  slots are accepted only at `quorum: 1` (you may still list several vouched
  approvers; any one of them decides). Mixing a vouched slot into `quorum > 1`
  is rejected at construction.
- **Keyed** (`quorum > 1` requires it): every approver signs their own receipt
  with their **own key, which the authority never holds** — four-eyes becomes
  *cryptographic separation of duty*: a compromised authority server can neither
  forge the quorum nor swap an approver's bound key (each key is pinned inside
  the agent-signed Intent). A keyed approver signs either with a raw ed25519 key
  via the `approve` CLI, or with a **passkey** in their browser (next section).

Delivery constraints still apply per channel: the single-recipient **email**
adapter and single-terminal **local** adapter deliver `quorum: 1` only and
refuse more (neither can independently authenticate distinct humans), and the
chat/email/local adapters are vouched-only. The **signing-link** adapter
delivers keyed Intents whose approvers are all **passkeys**; a raw-keyed
(bot/CLI) approver signs out of band with the `approve` CLI instead of
receiving a link, so an Intent that mixes passkey and raw-keyed approvers
needs a custom delivery adapter — verification accepts the mixed quorum
either way.

## Passkey approvals (browser WebAuthn)

The human-grade keyed path: each approver taps a personal signing link, sees
what they are approving, and confirms with their passkey (Touch ID / Face ID /
security key). The resulting receipt is signed by *their* authenticator against
the credential bound in the Intent — the server only relays and verifies, so it
cannot forge an approval.

```ts
import { PendingDecisions, SigningServer, wrapAction } from "@countersignlabs/counter-sign";
import { SigningLinkAdapter } from "@countersignlabs/counter-sign/adapters/signing-link";

const server = new SigningServer({
  pending: new PendingDecisions(),
  authorityKey: process.env.COUNTERSIGN_AUTHORITY_KEY!,      // signs the single-use links
  webauthn: { rpId: "approve.example.com", allowedOrigins: ["https://approve.example.com"] },
  baseUrl: "https://approve.example.com",
});
httpServer.on("request", server.handler());                  // GET/POST /sign

const adapter = new SigningLinkAdapter({
  server,
  notify: ({ actor, url }) => sendHowYouLike(actor, url),    // email, chat DM, SMS…
});

const deploy = wrapAction(deployProd,
  { action: "deploy.prod", summary: "Deploy v2.1.0", risk_tier: "critical",
    approvers: [
      { actor: "m:ceo", mode: "keyed", public_key: CEO_PASSKEY },   // webauthn-p256:… | webauthn-ed25519:…
      { actor: "m:cto", mode: "keyed", public_key: CTO_PASSKEY },
    ],
    quorum: 2, timeout: 600, default: "reject" },
  adapter, { agent, authorityKey: process.env.COUNTERSIGN_AUTHORITY_KEY! });
```

Each link is single-use and expires with the Intent; the signing page is
self-contained (no external resources, CSP-pinned) and the assertion challenge
binds the approver's passkey signature to the exact receipt being minted —
decision, actor, intent and timestamp. Delivery fails closed: if no approver
could be reached (or any approver under `default: "approve"`), the action never
runs. Enroll approver credentials with the `enroll` CLI (an org-root-attested,
hash-chained registry); passkey receipts are covered by the conformance
vectors ([`vectors/`](vectors/)).

## Why receipts, not booleans

An approval that evaporates after the `if` statement is worth nothing in an
audit. A Countersignature is ed25519-signed, names the actor and the policy
(explicit approver vs. timeout default), pins the exact `intent_id`, and
verifies offline with no access to the system that produced it. Timeout
defaults produce receipts too — silence has a signature here.

**Integrity is not authority.** A receipt that verifies against its *own*
embedded key only proves it wasn't tampered with — anyone can mint one. To
*act* on a receipt, bind it to the authority you trust:

```ts
import { verifyCountersignature } from "@countersignlabs/counter-sign";
// Only true if the receipt was signed by an authority key you trust:
verifyCountersignature(receipt, { trustedKeys: [OUR_AUTHORITY_PUBLIC_KEY] });
```

The `wrapAction` shim does this for you: it only accepts a decision signed by
the same authority key the runtime holds, so the adapter that collects the
decision must share that key (set `COUNTERSIGN_AUTHORITY_KEY`).

CLAIRE by Agentsstack Pte. Ltd. is the first reference deployment.

## Approval history

counter-sign never persists on its own — it hands you signed receipts and lets
you decide where they live. Pass a `ReceiptLog` (opt-in) and every resolution —
approval, veto, or timeout Default — is durably recorded where the runtime is
installed, one canonical JSON line per receipt:

```ts
import { wrapAction, ReceiptLog } from "@countersignlabs/counter-sign";

const receiptLog = new ReceiptLog("./receipts.jsonl");
const refund = wrapAction(issueRefund, fields, adapter, { receiptLog });
```

The file records the audit trail, and it gives you two different guarantees —
one keyed and strong, one that depends on an anchor:

- **Authenticity (keyed).** Each line carries an independently verifiable
  Countersignature; a forged or altered receipt fails verification against the
  trusted authority key — *this* holds with no trust in the process that wrote
  the file, because the signatures are keyed. Recording completes *before* the
  guarded action runs, so an approval you cannot remember is one the runtime
  declines to act on.
- **Completeness (relative to an anchor).** Entries are hash-chained — every
  line commits to a SHA-256 of the one before it. The chain is **keyless**, so
  on its own it catches accidental corruption and naive edits, but it is **not**
  evidence against someone who can rewrite the file: they can recompute every
  downstream hash and produce an intact-looking chain. To get real
  tamper-evidence, checkpoint `head()` somewhere the writer cannot reach and
  verify against it — then *any* edit, reorder, insertion, deletion, or
  truncation at or below the anchor is caught (`diverged` / `truncated`).

```ts
const head = await receiptLog.head();   // { length, hash } — anchor this out of band
// …later, audit against your anchor:
const report = await receiptLog.verifyAll({ trustedKeys: [OUR_AUTHORITY_PUBLIC_KEY], expectedHead: head });
// { total, valid, ok, faults: [...], chain: { intact, brokenAt?, reason? } }
// ok === true  ⇢  every receipt is genuine AND the log is intact against your anchor.
// Without expectedHead, ok proves signatures + internal chain consistency — NOT
// that nothing was removed by a writer who re-chained.
const perIntent = await receiptLog.history(); // Map<intent_id, Countersignature[]>
```

`ReceiptLog` is a **single-writer** file-backed `ReceiptSink` (point separate
processes at separate files). For multi-writer storage or standalone
tamper-evidence that needs no external anchor, put SQLite, Postgres, or a
*signed* transparency log behind the `ReceiptSink` interface. (A keyed,
self-anchoring chain — a signed head on every append — is on the roadmap.)

## Compliance and evidence

counter-sign gives regulated teams a machine-enforceable, auditable
human-oversight control — and the evidence auditors ask for: a signed,
portable record of who authorized a consequential action, under which rule,
and when, with optional two-person / M-of-N sign-off for the most sensitive
actions. It is a mechanism for *implementing* oversight — such as the human
oversight expected under EU AI Act Article 14 (Regulation (EU) 2024/1689) —
not a guarantee of compliance; a protocol produces evidence, while
organizations are what pass audits. See [COMPLIANCE.md](COMPLIANCE.md) for how
a Countersignature maps to control areas in SOC 2, ISO/IEC 27001, the NIST AI
RMF, and EU AI Act Article 14.

## Repository layout

| Path | What |
| ---- | ---- |
| `spec/` | The protocol specification (v0.1) |
| `schemas/` | JSON Schema (draft 2020-12) for Intent and Countersignature |
| `src/` | Reference implementation: core, shim, adapters (TypeScript, Node 20+, ESM) |
| `examples/` | One runnable demo per adapter + offline local/email demos |
| `adapters/` | Per-channel setup guides |

## Licensing

- **Code** (`src/`, `schemas/`, `examples/`, `tests/`): [Apache-2.0](LICENSE),
  Copyright 2026 Haridarman Kumaresan
- **Specification text** (`spec/`): CC BY 4.0 — see [LICENSE-CC-BY-4.0.txt](LICENSE-CC-BY-4.0.txt) (<https://creativecommons.org/licenses/by/4.0/>).
- Spec author: Haridarman Kumaresan.
- Sponsor: Agentsstack Pte. Ltd.
