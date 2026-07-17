"use client";
// Add-a-role form. Same client-side-signing path as New rule: the admin key stays in the
// browser, the role-set entry is signed here and the server only verifies + persists.
import { useState } from "react";
import { getHead, submitEntry } from "../actions";
import { signPolicyEntry, type PolicyChange } from "../../lib/policy-entry";

export function NewRoleForm({ org, approverActors }: { org: string; approverActors: string[] }) {
  const [name, setName] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const [custom, setCustom] = useState("");
  const [seed, setSeed] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const extra = custom.split(",").map((s) => s.trim()).filter(Boolean);
      const allMembers = [...new Set([...members, ...extra])];
      const change: PolicyChange = {
        kind: "role-set",
        role: { id: name.trim().toLowerCase().replace(/\s+/g, "-"), org, name: name.trim(), members: allMembers },
      };
      const entry = await signPolicyEntry(change, await getHead(), seed.trim());
      const res = await submitEntry(entry);
      if (res.ok) {
        setMsg({ ok: true, text: `Role "${change.role.name}" signed and recorded.` });
        setName("");
        setMembers([]);
        setCustom("");
      } else {
        setMsg({ ok: false, text: res.error });
      }
    } catch (err) {
      setMsg({ ok: false, text: `Signing failed: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setBusy(false);
    }
  }

  const field = { display: "block", margin: "0.4rem 0", width: "100%", maxWidth: "24rem", padding: "0.35rem" };
  const label = { display: "block", fontSize: "0.85rem", color: "#444", marginTop: "0.6rem" };

  return (
    <details style={{ margin: "1.5rem 0", border: "1px solid #e2e2e2", borderRadius: "0.5rem", padding: "1rem" }}>
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>+ New role</summary>
      <form onSubmit={onSubmit} style={{ marginTop: "0.75rem" }}>
        <label style={label}>Name<input style={field} value={name} onChange={(e) => setName(e.target.value)} required /></label>

        <label style={label}>Members (enrolled approvers)</label>
        <div>
          {approverActors.length === 0 && <em style={{ color: "#999" }}>No approvers enrolled yet.</em>}
          {approverActors.map((a) => (
            <label key={a} style={{ marginRight: "1rem", fontSize: "0.9rem" }}>
              <input
                type="checkbox"
                checked={members.includes(a)}
                onChange={(e) => setMembers((ms) => (e.target.checked ? [...ms, a] : ms.filter((m) => m !== a)))}
              />{" "}
              {a}
            </label>
          ))}
        </div>
        <label style={label}>Additional actor ids (comma-separated, optional)<input style={field} value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="m:cto, m:ceo" /></label>

        <label style={{ ...label, marginTop: "1rem" }}>Admin key (base64url ed25519 seed — stays in your browser, never sent)</label>
        <textarea style={{ ...field, fontFamily: "monospace", height: "3rem" }} value={seed} onChange={(e) => setSeed(e.target.value)} required />

        <button type="submit" disabled={busy || !name.trim() || !seed.trim()} style={{ marginTop: "0.75rem", padding: "0.5rem 1rem" }}>
          {busy ? "Signing…" : "Sign & record"}
        </button>
        {msg && <p style={{ color: msg.ok ? "#0a7d33" : "#b3261e", marginTop: "0.75rem" }}>{msg.text}</p>}
      </form>
    </details>
  );
}
