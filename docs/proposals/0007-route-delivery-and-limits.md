# 0007 · Route: deliver to the named approvers, and refuse rather than truncate

**Status:** proposal, not applied · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

Spec §2 says an adapter "MUST NOT alter, summarize, or re-sign the Intent" and that
"what the approver sees is derived from the signed envelope". It says nothing about
**who** an adapter delivers to, or what happens when the envelope does not fit the
channel. Kaviyam met both:

- **Recipients.** The WhatsApp adapter sends every Intent to one configured number
  (`WHATSAPP_TO`), whatever the Intent's `approvers` list says; the Telegram and
  Slack adapters post to one configured chat or channel. An Intent naming
  `whatsapp:<the owner's number>` may be delivered to someone else entirely. Only listed approvers
  can decide (the adapter ignores everyone else), so this is not a forgery, but the
  people who may decide may never see the request, and the Intent falls silently to
  its Default.
- **Message limits.** A LinkedIn post is up to 3,000 characters and Kaviyam puts the
  exact words in `summary` (proposal 0001). Telegram allows 4,096 UTF-16 units per
  message, a Slack section 3,000 characters, a WhatsApp template body 1,024 and no
  newlines in a parameter. No adapter checks: Telegram and Slack fail at send time,
  and the design's fallback was to send the first line plus a link, which lets a
  person approve words they never saw on the surface where they pressed.

## Proposed text for spec §2

> **Recipients.** An adapter MUST deliver an Intent only to destinations that
> belong to approvers the Intent names, and SHOULD deliver to every approver it can
> reach on its channel. An adapter that serves a fixed destination (a group chat, a
> channel) MUST refuse an Intent none of whose approvers it can reach there.
>
> **Limits.** If the rendered request — everything the approver needs to decide,
> including the full `summary` — does not fit the channel's limits, or contains
> characters the channel cannot carry faithfully, the adapter MUST refuse to deliver
> it (an error from `deliver`) rather than truncate, reflow, or move part of it
> behind a link. An adapter MAY offer a richer surface (a signing page) as a
> separate Route on which the full text and the decision appear together.
>
> **Formatting.** An adapter MUST render `summary` as plain text, or escape it, so
> that markup in the summary cannot change what the approver sees.

## Options

1. Adopt the text above (normative for recipients and refusal, both MUST).
2. Make the recipient rule a SHOULD only, since some channels (a shared ops room)
   have no per-person address.
3. Leave to adapters; document per adapter.

## Recommendation

Option 1, with the fixed-destination clause covering the shared-room case. In the
reference adapters: a `maxSummary`-style length check per channel (counted in the
channel's own units: UTF-16 for Telegram) that throws from `deliver`, and per-Intent
recipients for WhatsApp taken from the `whatsapp:` approvers. Because
`awaitWithDefault` treats an adapter error as fail-closed, a refused delivery never
runs the action.

Already shipped on this branch, as opt-in adapter features (no spec change): the
length checks (`enforceLimits: true` on the chat adapters, counted in the channel's
strict units; without it they refuse only what the platform rejects anyway) and
per-approver WhatsApp delivery (`recipientMode: "approvers"`). What remains is the
spec text above.

## Wire and vectors

None. These are delivery rules; the Intent, receipt and verifier are unchanged.
Conformance here is behavioural and belongs in adapter tests, not the vectors.

## What integrators can do today

Measure the full `formatIntent(intent)` text in the channel's units before
`deliver`, and do not send the Intent if it does not fit; ask through a signing
page instead. Configure each adapter's destination to be the approvers the Intent
names (one adapter instance per recipient where needed), and refuse in your own
code any Intent whose approvers are not on that destination. The policy layer can
now resolve a rule to vouched approvers on one channel:
`resolveRule(name, request, { store, org }, { approvers: "vouched", channel: "slack" })`.
