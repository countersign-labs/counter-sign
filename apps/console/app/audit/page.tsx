import { getState } from "../../lib/state";
import { loadAuditData } from "../../lib/audit";
import { VerifyBanner, Empty, fingerprint } from "../ui";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const s = getState();
  const audit = await loadAuditData(process.env.COUNTERSIGN_DATA_DIR ?? "./data");
  return (
    <div>
      <h1>Audit{s.org && ` — ${s.org}`}</h1>
      <VerifyBanner state={s} />

      <p className="muted">
        Policy log: <strong className={s.verified ? "ok" : "bad"}>{s.verified ? "verified" : "BROKEN"}</strong>
        {" · "}
        Receipt chain:{" "}
        <strong className={audit.receiptChain.intact ? "ok" : "bad"}>
          {audit.decisions.length === 0 ? "empty" : audit.receiptChain.intact ? "intact" : `broken (${audit.receiptChain.reason})`}
        </strong>
      </p>

      <h2 style={{ fontSize: "1.05rem", marginTop: "2rem" }}>Decisions <span className="muted" style={{ fontSize: "0.8rem" }}>— the tamper-evident receipt log</span></h2>
      {audit.decisions.length === 0 ? (
        <Empty>No decisions recorded yet. Approvals, vetoes, and timeout Defaults land here as signed receipts.</Empty>
      ) : (
        <table className="cs">
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Decision</th>
              <th>How</th>
              <th>Intent</th>
            </tr>
          </thead>
          <tbody>
            {audit.decisions.map((d, i) => (
              <tr key={i}>
                <td className="mono">{fmt(d.timestamp)}</td>
                <td>{d.actor}</td>
                <td className={d.decision === "approve" ? "ok" : "bad"}>{d.decision}</td>
                <td>{d.policy === "default" ? "timeout default" : "human"}</td>
                <td className="mono" title={d.intent_id}>{d.intent_id.slice(0, 8)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2 style={{ fontSize: "1.05rem", marginTop: "2.5rem" }}>Policy changes <span className="muted" style={{ fontSize: "0.8rem" }}>— the signed change log</span></h2>
      {audit.changes.length === 0 ? (
        <Empty>No policy changes yet.</Empty>
      ) : (
        <table className="cs">
          <thead>
            <tr>
              <th>#</th>
              <th>When</th>
              <th>Change</th>
              <th>Target</th>
              <th>Signed by</th>
            </tr>
          </thead>
          <tbody>
            {audit.changes.map((c) => (
              <tr key={c.seq}>
                <td className="mono">{c.seq}</td>
                <td className="mono">{fmt(c.issued_at)}</td>
                <td>{c.kind}</td>
                <td>{c.target}</td>
                <td className="mono" title={c.signer}>{fingerprint(c.signer)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function fmt(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}
