import { getState } from "../../lib/state";
import { VerifyBanner, Empty } from "../ui";
import { NewRoleForm } from "./new-role";

export const dynamic = "force-dynamic";

export default function RolesPage() {
  const s = getState();
  return (
    <div>
      <h1>Roles{s.org && ` — ${s.org}`}</h1>
      <p className="muted">Named groups of approvers. Rules reference roles.</p>
      <VerifyBanner state={s} />
      <NewRoleForm org={s.org || "acme"} approverActors={s.approvers.map((a) => a.actor)} />
      {s.roles.length === 0 ? (
        <Empty>No roles defined yet.</Empty>
      ) : (
        <table className="cs">
          <thead>
            <tr>
              <th>Name</th>
              <th>Members</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {s.roles.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>{r.members.join(", ")}</td>
                <td className="muted">{r.description ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
