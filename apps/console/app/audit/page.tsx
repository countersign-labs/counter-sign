import { getState } from "../../lib/state";
import { VerifyBanner } from "../ui";

export const dynamic = "force-dynamic";

export default function AuditPage() {
  const s = getState();
  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Audit{s.org && ` — ${s.org}`}</h1>
      <VerifyBanner state={s} />
      <p style={{ color: "#555" }}>
        The policy log currently verifies as{" "}
        <strong style={{ color: s.verified ? "#0a7d33" : "#b3261e" }}>{s.verified ? "intact" : "BROKEN"}</strong>.
      </p>
      <p style={{ color: "#777" }}>
        The full audit view — the tamper-evident <em>receipt log</em> (who approved what, when, and
        whether the chain is intact) alongside the <em>policy change log</em> (who changed which
        rule/role/admin) — lands in the next phase. It reads the same signed, hash-chained artifacts
        this console already verifies on load.
      </p>
    </div>
  );
}
