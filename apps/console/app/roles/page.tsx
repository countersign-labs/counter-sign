import { getState } from "../../lib/state";
import { VerifyBanner, Empty, table, th, td } from "../ui";

export const dynamic = "force-dynamic";

export default function RolesPage() {
  const s = getState();
  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Roles{s.org && ` — ${s.org}`}</h1>
      <p style={{ color: "#555" }}>Named groups of approvers. Rules reference roles.</p>
      <VerifyBanner state={s} />
      {s.roles.length === 0 ? (
        <Empty>No roles defined yet.</Empty>
      ) : (
        <table style={table}>
          <thead>
            <tr>
              <th style={th}>Name</th>
              <th style={th}>Members</th>
              <th style={th}>Description</th>
            </tr>
          </thead>
          <tbody>
            {s.roles.map((r) => (
              <tr key={r.id}>
                <td style={td}>{r.name}</td>
                <td style={td}>{r.members.join(", ")}</td>
                <td style={td}>{r.description ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
