import { getState } from "../../lib/state";
import { VerifyBanner, Empty, table, th, td, mono, fingerprint } from "../ui";

export const dynamic = "force-dynamic";

export default function ApproversPage() {
  const s = getState();
  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Approvers{s.org && ` — ${s.org}`}</h1>
      <p style={{ color: "#555" }}>People with an active, org-root-attested key binding, from the enrollment registry.</p>
      <VerifyBanner state={s} />
      {s.approvers.length === 0 ? (
        <Empty>No approvers enrolled yet. Onboard one with the <code>enroll</code> CLI.</Empty>
      ) : (
        <table style={table}>
          <thead>
            <tr>
              <th style={th}>Actor</th>
              <th style={th}>Active keys</th>
              <th style={th}>Key fingerprints</th>
            </tr>
          </thead>
          <tbody>
            {s.approvers.map((a) => (
              <tr key={a.actor}>
                <td style={td}>{a.actor}</td>
                <td style={td}>{a.keys.length}</td>
                <td style={{ ...td, ...mono }}>{a.keys.map(fingerprint).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
