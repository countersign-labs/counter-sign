"use client";
// Add or revoke admin keys. Signed by an EXISTING admin key (client-side); the last
// remaining admin cannot be revoked (enforced by the library — the attempt is rejected).
import { useState } from "react";
import { useSigner, AdminKeyField, Result } from "../sign";
import type { PolicyChange } from "../../lib/policy-entry";

export function ManageAdmins({ org, admins }: { org: string; admins: { public_key: string; name?: string }[] }) {
  const [mode, setMode] = useState<"add" | "revoke">("add");
  const [newName, setNewName] = useState("");
  const [newKey, setNewKey] = useState("");
  const [revokeKey, setRevokeKey] = useState("");
  const s = useSigner();

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const change: PolicyChange =
      mode === "add"
        ? { kind: "admin-add", org, public_key: newKey.trim(), ...(newName.trim() ? { name: newName.trim() } : {}) }
        : { kind: "admin-revoke", org, public_key: revokeKey };
    const ok = await s.sign(change, mode === "add" ? `Admin "${newName || newKey.slice(0, 8)}" added.` : "Admin key revoked.");
    if (ok && mode === "add") {
      setNewName("");
      setNewKey("");
    }
  }

  return (
    <details style={{ margin: "1.5rem 0" }} open={admins.length <= 1}>
      <summary>Manage admins</summary>
      <p className="muted" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>
        An admin key can add or revoke other admin keys. You sign the change with an admin key you
        already hold — it never leaves your browser. The last remaining admin cannot be revoked.
      </p>
      <div style={{ display: "flex", gap: "1rem", margin: "0.5rem 0" }}>
        <label style={{ color: "var(--ink)" }}><input type="radio" checked={mode === "add"} onChange={() => setMode("add")} /> Add an admin</label>
        <label style={{ color: "var(--ink)" }}><input type="radio" checked={mode === "revoke"} onChange={() => setMode("revoke")} /> Revoke an admin</label>
      </div>

      <form onSubmit={onSubmit}>
        {mode === "add" ? (
          <>
            <label style={label}>New admin name (optional)<input style={field} value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="ops-lead" /></label>
            <label style={label}>New admin PUBLIC key<input style={field} value={newKey} onChange={(e) => setNewKey(e.target.value)} placeholder="base64url ed25519 public key" required /></label>
          </>
        ) : (
          <>
            <label style={label}>Admin to revoke</label>
            <select style={{ ...field, maxWidth: "30rem" }} value={revokeKey} onChange={(e) => setRevokeKey(e.target.value)} required>
              <option value="">— choose an admin —</option>
              {admins.map((a) => (
                <option key={a.public_key} value={a.public_key}>{a.name ? `${a.name} · ` : ""}{a.public_key.slice(0, 12)}…</option>
              ))}
            </select>
          </>
        )}

        <AdminKeyField signer={s} />
        <button type="submit" disabled={s.busy || !s.seed.trim() || (mode === "add" ? !newKey.trim() : !revokeKey)} style={{ marginTop: "0.9rem" }}>
          {s.busy ? "Signing…" : mode === "add" ? "Sign & add admin" : "Sign & revoke admin"}
        </button>
        <Result signer={s} />
      </form>
    </details>
  );
}

const field = { display: "block", margin: "0.3rem 0", width: "100%", maxWidth: "30rem", fontFamily: "var(--mono)" };
const label = { display: "block", fontSize: "0.85rem", marginTop: "0.9rem" };
