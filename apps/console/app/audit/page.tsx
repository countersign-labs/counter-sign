import { getState } from "../../lib/state";
import { VerifyBanner } from "../ui";

export const dynamic = "force-dynamic";

export default function AuditPage() {
  const s = getState();
  return (
    <div>
      <h1>Audit{s.org && ` — ${s.org}`}</h1>
      <VerifyBanner state={s} />
      <p className="muted">
        The policy log currently verifies as{" "}
        <strong className={s.verified ? "ok" : "bad"}>{s.verified ? "intact" : "BROKEN"}</strong>.
      </p>
      <p className="muted">
        The full audit view — the tamper-evident <em>receipt log</em> (who approved what, when, and
        whether the chain is intact) alongside the <em>policy change log</em> (who changed which
        rule/role/admin) — lands in the next phase. It reads the same signed, hash-chained artifacts
        this console already verifies on load.
      </p>
    </div>
  );
}
