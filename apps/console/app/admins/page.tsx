import { getState } from "../../lib/state";
import { VerifyBanner, Empty, table, th, td, mono, fingerprint } from "../ui";

export const dynamic = "force-dynamic";

export default function AdminsPage() {
  const s = getState();
  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Admins{s.org && ` — ${s.org}`}</h1>
      <p style={{ color: "#555" }}>
        Keys authorized to sign policy changes. Every change in the policy log is signed by one
        of these keys; the console holds none of them.
      </p>
      <VerifyBanner state={s} />
      {s.admins.length === 0 ? (
        <Empty>No admin keys — the policy log has not been bootstrapped.</Empty>
      ) : (
        <table style={table}>
          <thead>
            <tr>
              <th style={th}>Name</th>
              <th style={th}>Public key</th>
            </tr>
          </thead>
          <tbody>
            {s.admins.map((a) => (
              <tr key={a.public_key}>
                <td style={td}>{a.name ?? "—"}</td>
                <td style={{ ...td, ...mono }} title={a.public_key}>{fingerprint(a.public_key)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
