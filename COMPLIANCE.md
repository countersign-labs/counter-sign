# counter-sign and compliance

counter-sign is not itself "compliant" with anything: it is a protocol, and a
protocol cannot be certified. What counter-sign does is **produce evidence** and
provide a **control mechanism** — a signed, portable record that a named human
authorized a specific consequential action — that helps organizations satisfy
specific requirements in the frameworks they are audited against. Compliance is
a property of an organization's audited operations, not of a wire format. The
table below maps what a Countersignature provides to the control *areas* those
frameworks care about; it names control areas, not invented control IDs.

| Framework | Relevant control area | What a Countersignature provides |
| --------- | --------------------- | -------------------------------- |
| **SOC 2** (Trust Services Criteria) | Access control and change authorization (CC-series common criteria) | Signed proof that a named human authorized a specific consequential action — evidence relevant to demonstrating that authorization controls were operating. |
| **ISO/IEC 27001** (Annex A) | Access management and event logging controls | Tamper-evident authorization records that support these controls and can be used as audit evidence. |
| **NIST AI Risk Management Framework** | The "Manage" function / human-oversight outcomes | A machine-enforceable human decision point with an auditable record — a mechanism for implementing and evidencing oversight of consequential automated actions. |
| **EU AI Act** (Regulation (EU) 2024/1689), Article 14 "Human Oversight" | Human oversight of high-risk AI systems. Article 14 requires high-risk AI systems to be designed so natural persons can effectively oversee them, including the ability to intervene in or halt the system, with oversight measures proportionate to the system's risk, autonomy, and context. | counter-sign provides a technical mechanism for implementing such oversight over consequential automated actions: a designed-in, machine-enforceable human intervention point that produces a verifiable record of the oversight exercised. For the most sensitive high-risk uses it can require an M-of-N approval quorum — e.g. two-person ("four-eyes") sign-off — of distinct approvers before the action proceeds, with any single approver able to veto. |

*counter-sign is a tool for implementing human oversight; it does not by itself make a system Article 14 compliant, which depends on the deployer's overall system design and operation.*

A note on scope, so the table is not read as more than it is: EU AI Act
Article 14 does **not** require a human to approve every AI decision before it
takes effect. It requires that *effective human oversight be possible by
design*. counter-sign supplies one such designed-in intervention point for the
consequential actions a deployer chooses to gate; whether an overall system
meets Article 14 depends on that deployer's design and operation, not on any
single component.

Two honest limits an auditor should know:

- **Approvals, quorum, and identity.** By default one human authorization per
  Intent authorizes the action. For heightened control an Intent can require an
  M-of-N *quorum* of **distinct** approvers (e.g. two-person / four-eyes), and
  any single approver can veto; the authorization is then evidenced by the set
  of approval receipts. Distinctness is by approver identity, so a quorum needs
  a channel where distinct approvers can each respond (chat channels, or the
  local approver) — the single-recipient email flow supports quorum 1 only, and
  identity assurance of each approver is the channel's responsibility, not the
  protocol's.
- **Silence is governed by the Default.** Only a receipt with `policy:
  approver` evidences an actual human decision; a `policy: default` receipt
  records that oversight was *not* exercised before the deadline. An oversight
  posture should therefore pair each gated action with a `reject` Default
  (fail-closed) — an `approve` Default lets an action proceed with no human
  decision behind it, and with a quorum it would bypass the required approvers
  entirely.

Richer evidence handling — export, retention, search, and reporting — is
deliberately out of scope for the protocol and belongs to implementing
products.
