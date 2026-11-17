# Proposals

Changes to the counter-sign protocol that are written up for discussion and **not
applied**. Each one is a page: the problem as it was met in a real deployment, the
options, a recommendation, what it would change on the wire and in the
[conformance vectors](../../vectors/), and what an integrator can do today without
it. Nothing here changes the [spec](../../spec/countersign-spec.md), the
[schemas](../../schemas/) or the vectors until it is accepted and lands in a
release.

These seven came from designing Kaviyam, the first reference deployment, on top of
counter-sign 0.2.0: chat approval of social posts, one approvals router per
workspace, Python on the deciding side.

| # | Proposal | Wire change if adopted |
|---|---|---|
| [0001](0001-content-binding.md) | Binding content to an Intent: document the `action` digest convention; later an optional signed digest field | none now; a new optional field and minor version later |
| [0002](0002-approver-receipt-deadline.md) | Verifiers check that an approver's receipt is timestamped before the deadline | none; new negative vectors, existing ones unaffected |
| [0003](0003-withdraw-and-change-request.md) | Withdrawing an Intent with a signed record; "change requested" as a reason on a reject | a new artifact and an optional receipt field, next minor version |
| [0004](0004-signed-receipt-chain.md) | A signed, self-anchoring receipt chain: what the head covers and who signs | log format only; receipts unchanged |
| [0005](0005-canonical-json-rfc8785.md) | Pinning canonical JSON to RFC 8785, with today's matches and differences pinned by tests | none for existing envelopes; new canonical vectors |
| [0006](0006-resumable-decisions.md) | Non-normative guidance on restarts and exactly-once decisions | none |
| [0007](0007-route-delivery-and-limits.md) | Route: deliver to the approvers the Intent names; refuse rather than truncate | none |

To propose a change, add the next number with the same headings and open a pull
request; see [CONTRIBUTING.md](../../CONTRIBUTING.md).
