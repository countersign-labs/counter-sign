import { getState } from "../../lib/state";
import { VerifyBanner, Empty } from "../ui";
import { NewRuleForm } from "./new-rule";

export const dynamic = "force-dynamic";

export default function RulesPage() {
  const s = getState();
  return (
    <div>
      <h1>Rules{s.org && ` — ${s.org}`}</h1>
      <p className="muted">
        Named approval policies an agent references. A rule resolves to a signed Intent:
        which roles must approve, the quorum, the default on no-confirmation, and the review window.
      </p>
      <VerifyBanner state={s} />
      <NewRuleForm org={s.org || "acme"} roleIds={s.roles.map((r) => r.id)} />
      {s.rules.length === 0 ? (
        <Empty>No rules defined yet.</Empty>
      ) : (
        <table className="cs">
          <thead>
            <tr>
              <th>Name</th>
              <th>Roles</th>
              <th>Quorum</th>
              <th>Default</th>
              <th>Window</th>
              <th>Action</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {s.rules.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>{r.roles.join(", ")}</td>
                <td>{r.quorum}</td>
                <td className={r.default === "approve" ? "ok" : "bad"}>{r.default}</td>
                <td>{formatWindow(r.timeout_seconds)}</td>
                <td className="mono">{r.action ?? "—"}</td>
                <td>{r.risk_tier ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function formatWindow(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
