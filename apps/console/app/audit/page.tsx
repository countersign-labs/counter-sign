import { getState } from "../../lib/state";
import { loadAuditData } from "../../lib/audit";
import { VerifyBanner, Empty, fingerprint } from "../ui";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const s = getState();
  const audit = await loadAuditData(process.env.COUNTERSIGN_DATA_DIR ?? "./data");
  const r = audit.receipts;
  return (
    <div>
      <h1>Audit{s.org && ` — ${s.org}`}</h1>
      <VerifyBanner state={s} />

      <p className="muted">
        Policy log: <strong className={s.policyVerified ? "ok" : "bad"}>{s.policyVerified ? "verified" : "BROKEN"}</strong>
        {" · "}
        {r.total === 0 && r.readable ? (
          <>Receipts: <strong>none yet</strong></>
        ) : !r.readable ? (
          <>Receipts: <strong className="bad">unreadable{r.error ? ` (${r.error})` : ""}</strong></>
        ) : (
          <>
            Receipt signatures:{" "}
            {/* Green ONLY when every receipt verified. Unverifiable/malformed receipts mean fewer
                than `total` were checked, so `valid === total` — not `invalid === 0` — is the test. */}
            <strong className={r.valid === r.total ? "ok" : r.invalid > 0 ? "bad" : "muted"}>{r.valid}/{r.total} verified</strong>
            {r.invalid > 0 && <strong className="bad">{" · "}{r.invalid} INVALID</strong>}
            {r.malformed > 0 && <span className="bad">{" · "}{r.malformed} malformed</span>}
            {r.unverifiable > 0 && <span>{" · "}{r.unverifiable} unverifiable</span>}
            {" · "}chain structure:{" "}
            <strong className={r.chainIntact ? "ok" : "bad"}>{r.chainIntact ? "intact" : `broken (${r.chainReason})`}</strong>
          </>
        )}
      </p>
      {r.unverifiable > 0 && (
        <p className="muted" style={{ fontSize: "0.8rem" }}>
          Unverifiable receipts are passkey (WebAuthn) receipts — set <code className="mono">COUNTERSIGN_RP_ID</code> and{" "}
          <code className="mono">COUNTERSIGN_RP_ORIGINS</code> to verify their assertions here.
        </p>
      )}

      <h2 style={{ fontSize: "1.05rem", marginTop: "2rem" }}>Decisions <span className="muted" style={{ fontSize: "0.8rem" }}>— recorded receipts (signatures verified below)</span></h2>
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
              <th>Signature</th>
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
                <td className={d.signature === "valid" ? "ok" : d.signature === "invalid" || d.signature === "malformed" ? "bad" : "muted"}>
                  {d.signature === "valid" ? "✓ verified" : d.signature === "invalid" ? "✗ INVALID" : d.signature === "malformed" ? "⚠ malformed" : "— unverifiable"}
                </td>
                <td className="mono" title={d.intent_id}>{d.intent_id.slice(0, 8)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted" style={{ fontSize: "0.78rem", marginTop: "0.6rem" }}>
        Signatures are verified for integrity (each receipt was signed by the key it carries). Confirming that each
        signer was <em>authorized</em> for its request additionally requires the org&rsquo;s runtime authority key and the
        signed Intents, which this console does not hold — audit those with <code className="mono">verifyAll</code>.
      </p>

      <h2 style={{ fontSize: "1.05rem", marginTop: "2.5rem" }}>Policy changes <span className="muted" style={{ fontSize: "0.8rem" }}>— the signed change log</span></h2>
      {audit.changes.length === 0 ? (
        <Empty>{audit.policyReadable ? "No policy changes yet." : "Policy log is unreadable or corrupt — see the banner above."}</Empty>
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
            {audit.changes.map((c, i) => (
              <tr key={i}>
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
