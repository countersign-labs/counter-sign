"use client";
import { useState } from "react";
import { useSigner, AdminKeyField, Result } from "../sign";
import type { PolicyChange } from "../../lib/policy-entry";

export function NewRoleForm({ org, approverActors }: { org: string; approverActors: string[] }) {
  const [name, setName] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const [custom, setCustom] = useState("");
  const s = useSigner();

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const extra = custom.split(",").map((x) => x.trim()).filter(Boolean);
    const allMembers = [...new Set([...members, ...extra])];
    const change: PolicyChange = {
      kind: "role-set",
      role: { id: name.trim().toLowerCase().replace(/\s+/g, "-"), org, name: name.trim(), members: allMembers },
    };
    if (await s.sign(change, `Role "${change.role.name}" signed and recorded.`)) {
      setName("");
      setMembers([]);
      setCustom("");
    }
  }

  return (
    <details style={{ margin: "1.5rem 0" }}>
      <summary>+ New role</summary>
      <p className="muted" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>A named group of approvers that rules can reference.</p>
      <form onSubmit={onSubmit}>
        <label style={label}>Role name<input style={field} value={name} onChange={(e) => setName(e.target.value)} placeholder="finance-approvers" required /></label>

        <label style={label}>Members (enrolled approvers)</label>
        {approverActors.length === 0 && <p className="muted" style={{ fontSize: "0.85rem" }}>No approvers enrolled yet.</p>}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
          {approverActors.map((a) => (
            <label key={a} style={{ fontSize: "0.9rem", color: "var(--ink)" }}>
              <input type="checkbox" checked={members.includes(a)} onChange={(e) => setMembers((ms) => (e.target.checked ? [...ms, a] : ms.filter((m) => m !== a)))} /> {a}
            </label>
          ))}
        </div>
        <label style={label}>Additional actor ids (comma-separated, optional)<input style={field} value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="m:cto, m:ceo" /></label>

        <AdminKeyField signer={s} />
        <button type="submit" disabled={s.busy || !name.trim() || !s.seed.trim()} style={{ marginTop: "0.9rem" }}>
          {s.busy ? "Signing…" : "Sign & record role"}
        </button>
        <Result signer={s} />
      </form>
    </details>
  );
}

const field = { display: "block", margin: "0.3rem 0", width: "100%", maxWidth: "22rem" };
const label = { display: "block", fontSize: "0.85rem", marginTop: "0.9rem" };
