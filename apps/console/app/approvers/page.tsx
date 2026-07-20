import { getState } from "../../lib/state";
import { VerifyBanner, Empty, fingerprint } from "../ui";

export const dynamic = "force-dynamic";

export default function ApproversPage() {
  const s = getState();
  return (
    <div>
      <h1>Approvers{s.org && ` — ${s.org}`}</h1>
      <p className="muted">People with an active, org-root-attested key binding, from the enrollment registry.</p>
      <VerifyBanner state={s} />
      {s.approvers.length === 0 ? (
        <Empty>No approvers enrolled yet. Onboard one with the <code>enroll</code> CLI.</Empty>
      ) : (
        <table className="cs">
          <thead>
            <tr>
              <th>Actor</th>
              <th>Active keys</th>
              <th>Key fingerprints</th>
            </tr>
          </thead>
          <tbody>
            {s.approvers.map((a) => (
              <tr key={a.actor}>
                <td>{a.actor}</td>
                <td>{a.keys.length}</td>
                <td className="mono">{a.keys.map(fingerprint).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
