"use client";
import { useState } from "react";
import { useSigner, AdminKeyField, Result } from "../sign";
import type { PolicyChange } from "../../lib/policy-entry";

export function NewRuleForm({ org, roleIds }: { org: string; roleIds: string[] }) {
  const [name, setName] = useState("");
  const [roles, setRoles] = useState<string[]>([]);
  const [quorum, setQuorum] = useState(1);
  const [def, setDef] = useState<"approve" | "reject">("reject");
  const [minutes, setMinutes] = useState(60);
  const [action, setAction] = useState("");
  const [risk, setRisk] = useState("high");
  const s = useSigner();

  const approveAllowed = quorum <= 1; // quorum > 1 must fail closed (reject)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const change: PolicyChange = {
      kind: "rule-set",
      rule: {
        id: name.trim().toLowerCase().replace(/\s+/g, "-"),
        org,
        name: name.trim(),
        roles,
        quorum,
        default: approveAllowed ? def : "reject",
        timeout_seconds: Math.max(1, Math.round(minutes * 60)),
        ...(action.trim() ? { action: action.trim() } : {}),
        ...(risk ? { risk_tier: risk } : {}),
      },
    };
    if (await s.sign(change, `Rule "${change.rule.name}" signed and recorded.`)) {
      setName("");
      setRoles([]);
      setAction("");
    }
  }

  return (
    <details style={{ margin: "1.5rem 0" }}>
      <summary>+ New rule</summary>
      <p className="muted" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>
        A rule an agent references by name. When triggered it produces a signed approval request for the chosen roles.
      </p>
      <form onSubmit={onSubmit}>
        <label style={label}>Rule name<input style={field} value={name} onChange={(e) => setName(e.target.value)} placeholder="large-refund" required /></label>

        <label style={label}>Who must approve (roles)</label>
        {roleIds.length === 0 && <p className="muted" style={{ fontSize: "0.85rem" }}>No roles yet — create one on the Roles page first.</p>}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
          {roleIds.map((id) => (
            <label key={id} style={{ fontSize: "0.9rem", color: "var(--ink)" }}>
              <input type="checkbox" checked={roles.includes(id)} onChange={(e) => setRoles((rs) => (e.target.checked ? [...rs, id] : rs.filter((r) => r !== id)))} /> {id}
            </label>
          ))}
        </div>

        <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap" }}>
          <label style={label}>How many must approve<input style={{ ...field, width: "8rem" }} type="number" min={1} value={quorum} onChange={(e) => setQuorum(Math.max(1, Number(e.target.value)))} /></label>
          <label style={label}>If nobody responds in time
            <select style={{ ...field, width: "13rem" }} value={approveAllowed ? def : "reject"} disabled={!approveAllowed} onChange={(e) => setDef(e.target.value as "approve" | "reject")}>
              <option value="reject">reject (fail closed)</option>
              <option value="approve">approve</option>
            </select>
          </label>
          <label style={label}>Review window (minutes)<input style={{ ...field, width: "8rem" }} type="number" min={1} value={minutes} onChange={(e) => setMinutes(Math.max(1, Number(e.target.value)))} /></label>
        </div>
        {!approveAllowed && <small className="bad">With more than one approver, a timeout must reject — you can&rsquo;t auto-approve a multi-person action.</small>}

        <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap" }}>
          <label style={label}>Action label (optional)<input style={field} value={action} onChange={(e) => setAction(e.target.value)} placeholder="billing.refund" /></label>
          <label style={label}>Risk tier
            <select style={{ ...field, width: "10rem" }} value={risk} onChange={(e) => setRisk(e.target.value)}>
              {["low", "medium", "high", "critical"].map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </label>
        </div>

        <AdminKeyField signer={s} />
        <button type="submit" disabled={s.busy || roles.length === 0 || !s.seed.trim()} style={{ marginTop: "0.9rem" }}>
          {s.busy ? "Signing…" : "Sign & record rule"}
        </button>
        <Result signer={s} />
      </form>
    </details>
  );
}

const field = { display: "block", margin: "0.3rem 0", width: "100%", maxWidth: "22rem" };
const label = { display: "block", fontSize: "0.85rem", marginTop: "0.9rem" };
