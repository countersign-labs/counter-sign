# 0002 · Verifiers should check that an approver's receipt is before the deadline

**Status:** proposal, not applied · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

The Kaviyam design said a chat receipt "proves the press came before the
deadline". Its review found that no verifier checks this:

- `verifyResolution` (src/core/defaults.ts) checks the timestamp of a
  `policy: "default"` receipt (it must be at or after the deadline) but never the
  timestamp of a `policy: "approver"` receipt.
- The Python `verify_resolution` (clients/python/countersign/resolution.py) mirrors
  it.

The deadline is enforced only by the runtime that collected the decision:
`PendingDecisions.settle` and `record` ignore a press at or after the deadline, the
`SigningServer` refuses a stamped time at or after it, and `awaitWithDefault`
discards a resolution it observes late. A third party holding only the Intent and
the receipts cannot tell an on-time approval from one stamped after the window
closed. In Kaviyam's case: if the web app is down for two days, a Monday approval
can still be acted on Wednesday, and nothing in the evidence says whether it was in
time.

The spec already leans this way: §4 says a decision after the deadline MUST be
ignored, and §5 says "Verifiers SHOULD also check `timestamp` falls within the
Intent's validity window." The reference verifiers do not implement the SHOULD.

## Options

1. **Make the check normative in `verifyResolution`.** Reject any
   `policy: "approver"` receipt whose signed `timestamp` is unparseable or at or
   after `created_at + timeout`, for approve and reject resolutions alike. Only an
   upper bound: no comparison with `created_at`, for the same reason the
   SigningServer gives (the agent's and the server's clocks differ, and an early
   stamp carries no escalation).
2. **Opt-in only.** A `{ requireInWindow: true }` option on `verifyResolution` and
   `ReceiptLog.verifyAll`; default behaviour unchanged.
3. **Leave it to the runtime** and correct the docs that suggest otherwise.

## Recommendation

Option 1, shipped first as option 2 in a patch release so deployments can turn it
on, then made the default at the next minor version. It closes the gap between what
a receipt is said to prove and what a verifier checks, and it matches what the
runtime already enforces, so no honest resolution changes outcome. The late-reject
exception in `awaitWithDefault` (a veto on a `default: "approve"` Intent observed a
microtask late) is unaffected: `settle` and `record` already gate on the clock, so
that receipt is stamped in time.

## Wire and vectors

- No envelope or schema change: `timestamp` is already signed.
- Every existing resolution vector stays valid: each approver receipt in
  `vectors/countersign-vectors.json` (`resolutions` and `webauthn`) is stamped
  `00:01` against a `00:05` deadline.
- New negative vectors: a vouched approve stamped at the deadline, a keyed approve
  stamped after it, and an unparseable timestamp; all must be rejected. The spec's
  §5 SHOULD becomes a MUST in §3's verifier checks at the next minor version.

## What integrators can do today

After `verifyResolution` succeeds, check yourself that every receipt with
`policy: "approver"` has `Date.parse(timestamp) < deadline(intent)` (exported from
the core). Separately, decide how long after an approval you are still willing to
act, and ask again past that.
