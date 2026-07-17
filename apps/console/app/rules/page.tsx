import { getState } from "../../lib/state";
import { VerifyBanner, Empty, table, th, td } from "../ui";
import { NewRuleForm } from "./new-rule";

export const dynamic = "force-dynamic";

export default function RulesPage() {
  const s = getState();
  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Rules{s.org && ` — ${s.org}`}</h1>
      <p style={{ color: "#555" }}>
        Named approval policies an agent references. A rule resolves to a signed Intent:
        which roles must approve, the quorum, the default on no-confirmation, and the review window.
      </p>
      <VerifyBanner state={s} />
      <NewRuleForm org={s.org || "acme"} roleIds={s.roles.map((r) => r.id)} />
      {s.rules.length === 0 ? (
        <Empty>No rules defined yet.</Empty>
      ) : (
        <table style={table}>
          <thead>
            <tr>
              <th style={th}>Name</th>
              <th style={th}>Roles</th>
              <th style={th}>Quorum</th>
              <th style={th}>Default</th>
              <th style={th}>Window</th>
              <th style={th}>Action</th>
              <th style={th}>Risk</th>
            </tr>
          </thead>
          <tbody>
            {s.rules.map((r) => (
              <tr key={r.id}>
                <td style={td}>{r.name}</td>
                <td style={td}>{r.roles.join(", ")}</td>
                <td style={td}>{r.quorum}</td>
                <td style={{ ...td, color: r.default === "approve" ? "#0a7d33" : "#b3261e" }}>{r.default}</td>
                <td style={td}>{formatWindow(r.timeout_seconds)}</td>
                <td style={td}>{r.action ?? "—"}</td>
                <td style={td}>{r.risk_tier ?? "—"}</td>
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
