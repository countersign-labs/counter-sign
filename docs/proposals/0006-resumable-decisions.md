# 0006 · Resumable decisions: what the spec should say about restarts

**Status:** proposal, not applied (non-normative guidance) · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

Kaviyam asks for approval of a weekly post and waits up to 72 hours. The router
that holds the chat adapter will be restarted in that time (a deploy, a reboot).
In the reference implementation as released (0.2.0) every pending decision lives in memory:
`PendingDecisions` keeps its entries and its finality tombstones in a `Map`, the
Default timer is a `setTimeout`, and the `SigningServer` keeps spent links in
memory. After a restart:

- a press on the old message is ignored ("no longer pending"), and the Default
  never fires unless the Intent is registered again;
- if the integrator does register it again, there is no tombstone, so an Intent
  that was already decided can be decided a second time;
- a crash between the button press (the chat already shows "Recorded") and the
  receipt-log write leaves a person who was told "approved" and a log with nothing.

The security review lists this as a known limit. The spec says nothing: §3 says
"Once resolved, further decisions on the same `intent_id` MUST be ignored" and §4
says the Default fires at the deadline, but not what a runtime that restarts must
do to keep those promises. The reference implementation now has an opt-in durable
store, not yet released: `DurableDecisions`, backed by a `PendingStore` such as
`FilePendingStore`, built along the lines of the guidance below (spent links in the
`SigningServer` are still kept in memory). The spec should say what any such store
must guarantee.

## Proposed guidance (non-normative text for spec §4 or a new §4.1)

> A runtime that can restart while Intents are pending SHOULD keep, in durable
> storage, every Intent it has delivered and not yet resolved, and the resolution
> of every Intent until its deadline has passed.
>
> **Finality across restarts.** Before accepting a decision after a restart, the
> runtime MUST check its durable record of resolutions; an Intent already resolved
> stays resolved (§3). Writing the resolution durably is the moment of decision:
> a runtime SHOULD NOT tell the approver a decision was recorded until it is.
>
> **Exactly one resolution per Intent.** Acceptance of a decision and the write of
> its resolution SHOULD be one atomic step (a compare-and-set on the Intent's
> state). Two processes, or a retry of the same platform callback, must not both
> resolve the same `intent_id`. Retried callbacks from the same approver are
> idempotent.
>
> **The Default after downtime.** On restart, an Intent whose deadline has passed
> with no recorded resolution resolves to its Default at once; the receipt is
> stamped no earlier than the deadline (§4), even though it is minted later.
>
> **Delivery.** A pending Intent whose delivery is not recorded as complete MAY be
> delivered again; duplicates are harmless because decisions bind to `intent_id`
> and finality is per Intent. A runtime SHOULD tell an approver whose answer was
> lost to answer again rather than let the Intent fall silently to its Default.
>
> **Spent links.** Single-use link tokens (§2) stay single-use across restarts:
> the record of spent tokens is durable for at least the token's lifetime.

## Options

1. Add the guidance above as non-normative text now.
2. Make the finality and exactly-once rules normative at the next minor version.
3. Leave it to implementations.

## Recommendation

Option 1 now, alongside the reference durable store, then option 2 once two
implementations have followed it. None of it changes what a receipt is.

## Wire and vectors

None. This is runtime behaviour; receipts, Intents and the verifier are unchanged.
Tests belong in the reference implementation (restart before and after the
deadline, a crash between press and log write, two processes racing one Intent),
not in the vectors.

## What integrators can do today

With the reference implementation (unreleased, after 0.2.0): open a
`FilePendingStore`, call `DurableDecisions.restore()` at start before anything
else, then ask with `issue()` and `decide()`; or pass
`wrapAction(fn, fields, adapter, { receiptLog, pendingStore })`. Adapter authors can
hand a store to `new PendingDecisions({ store })` and call its `restore()`. The
README section "Resumable decisions" has the details.

With 0.2.0 or another runtime, store each signed Intent when you deliver it. At
start, for each stored Intent with no receipt in your log: re-register it
(`awaitResolution` under `awaitWithDefault`) before its deadline, or let the
Default resolve it at once after. Check your
durable log before re-registering, write receipts with an fsync before acting, and
send a fresh message when the old buttons may already be gone.
