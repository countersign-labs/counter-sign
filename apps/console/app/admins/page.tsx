import { getState } from "../../lib/state";
import { VerifyBanner, Empty, fingerprint } from "../ui";

export const dynamic = "force-dynamic";

export default function AdminsPage() {
  const s = getState();
  return (
    <div>
      <h1>Admins{s.org && ` — ${s.org}`}</h1>
      <p className="muted">
        Keys authorized to sign policy changes. Every change in the policy log is signed by one
        of these keys; the console holds none of them.
      </p>
      <VerifyBanner state={s} />
      {s.admins.length === 0 ? (
        <Empty>No admin keys — the policy log has not been bootstrapped.</Empty>
      ) : (
        <table className="cs">
          <thead>
            <tr>
              <th>Name</th>
              <th>Public key</th>
            </tr>
          </thead>
          <tbody>
            {s.admins.map((a) => (
              <tr key={a.public_key}>
                <td>{a.name ?? "—"}</td>
                <td className="mono" title={a.public_key}>{fingerprint(a.public_key)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
