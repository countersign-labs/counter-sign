# 0003 · Withdrawing an Intent, and "change requested" as a third answer

**Status:** proposal, not applied · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

**Withdraw.** Kaviyam sends a request to approve a post. Before anyone answers, a
teammate edits the words in the app. The open request now describes words that
will never be posted. counter-sign has no way for the agent to take a request back:
the old Approve button stays live until the deadline, a press on it is recorded
honestly, and Kaviyam must refuse it on its own side ("the words changed after you
were asked"). The person sees a working button for a request that is already dead,
and the log shows an approval of something that was superseded, with no signed
record that it was.

**Change requested.** The commonest answer to a draft post is neither yes nor no
but "change the second line". Today `Decision` is `approve | reject`, every adapter
offers exactly two buttons, and the button parser accepts only those two words. So
Kaviyam's person must press Reject and then go and edit in the app; the receipt
says "reject", which an auditor reads as a veto, not as a request for changes.

## Options

**Withdraw**

1. **Adapter-level only.** An optional `Adapter.withdraw(intent_id, reason)` that
   edits the message, removes the buttons and settles the pending entry. No receipt.
2. **A signed withdrawal.** A new artifact signed by the **agent** key under its own
   context (`countersign-withdrawal-v0.3`): `{intent_id, reason?, timestamp}`. A
   runtime that holds a valid withdrawal resolves the Intent to `reject` with a new
   `policy: "withdrawn"`, and the withdrawal travels with the resolution as evidence.

**Change requested**

3. **A `reason` on a reject receipt.** Optional signed free text; the decision is
   still `reject`. Small, and keeps the decision set binary.
4. **A third decision `change`.** Resolves like a reject for the guarded action
   (fail closed) but is recorded as "changes requested", with a note.

## Recommendation

Ship option 1 now, because it is additive to the reference adapters and needs no
wire change. For the next minor version, add option 2 (only the agent can withdraw
its own request, so the agent key is the right signer, and a withdrawal must never
be able to approve anything) and option 3 rather than option 4: a third decision
would touch every verifier, the quorum rules and the Default logic, while a reason
on a reject gives auditors the distinction without a new outcome. The note is
untrusted text from a chat; it must never be fed back as an instruction without
going through the same checks as any other input.

## Wire and vectors

- Option 1: none.
- Option 2: a new artifact, schema and signing context; a new `policy` value;
  vectors for a valid withdrawal, a withdrawal signed by the authority key (must
  fail), and a withdrawal arriving after a resolution (must be ignored).
- Option 3: an optional `reason` string in the countersignature schema, included in
  the signed bytes when present; vectors with and without it, and a tampered reason.

## What integrators can do today

Keep your own "superseded" state per Intent and refuse an approval of a superseded
request before acting; tell the person why. Use `PendingDecisions.cancel` to stop
waiting, and edit the chat message yourself with the platform API. For "change",
send a separate free-text prompt after a reject and treat the reply as untrusted.
