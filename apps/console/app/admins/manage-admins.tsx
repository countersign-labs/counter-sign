"use client";
// Add or revoke admin keys. Signed by an EXISTING admin key (client-side); the last
// remaining admin cannot be revoked (enforced by the library — the attempt is rejected).
import { useState } from "react";
import { useSigner, AdminKeyField, Result } from "../sign";
import { browserKeypair, type PolicyChange } from "../../lib/policy-entry";

export function ManageAdmins({ org, admins }: { org: string; admins: { public_key: string; name?: string }[] }) {
  const [mode, setMode] = useState<"add" | "revoke">("add");
  const [newName, setNewName] = useState("");
  const [newKey, setNewKey] = useState("");
  // The generated keypair, kept atomically: the secret is shown ONLY while the key field still
  // holds exactly this public key. Editing or replacing the key hides the now-mismatched secret,
  // so we never label pair A's private key as belonging to a submission that enrolls key B.
  const [gen, setGen] = useState<{ pub: string; secret: string } | null>(null);
  const [revokeKey, setRevokeKey] = useState("");
  const s = useSigner();

  async function generate() {
    const kp = await browserKeypair();
    setNewKey(kp.publicKey);
    setGen({ pub: kp.publicKey, secret: kp.secret });
  }

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
      setGen(null); // the freshly generated private key is "shown once" — clear it after use
    }
  }

  function switchMode(next: "add" | "revoke") {
    setMode(next);
    // Clear a GENERATED public key together with its secret (leaving it behind would let a key be
    // enrolled with no one holding the secret). A manually pasted key has no such coupling — keep
    // it so a mode toggle doesn't force the admin to re-paste.
    if (gen && newKey.trim() === gen.pub) setNewKey("");
    setGen(null);
  }

  return (
    <details style={{ margin: "1.5rem 0" }} open={admins.length <= 1}>
      <summary>Manage admins</summary>
      <p className="muted" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>
        An admin key can add or revoke other admin keys. You sign the change with an admin key you
        already hold — it never leaves your browser. The last remaining admin cannot be revoked.
      </p>
      <div style={{ display: "flex", gap: "1rem", margin: "0.5rem 0" }}>
        <label style={{ color: "var(--ink)" }}><input type="radio" checked={mode === "add"} onChange={() => switchMode("add")} /> Add an admin</label>
        <label style={{ color: "var(--ink)" }}><input type="radio" checked={mode === "revoke"} onChange={() => switchMode("revoke")} /> Revoke an admin</label>
      </div>

      <form onSubmit={onSubmit}>
        {mode === "add" ? (
          <>
            <label style={label}>New admin name (optional)<input style={field} value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="ops-lead" /></label>
            <label style={label}>
              New admin&rsquo;s PUBLIC key
              <span className="muted"> — paste the new admin&rsquo;s public key, or generate a fresh keypair here.</span>
            </label>
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-start", maxWidth: "34rem" }}>
              <input style={{ ...field, flex: 1, margin: 0 }} value={newKey} onChange={(e) => setNewKey(e.target.value)} placeholder="base64url ed25519 public key" required />
              <button type="button" onClick={generate} style={{ background: "transparent", color: "var(--sage)", border: "1px solid var(--line)", whiteSpace: "nowrap" }}>
                Generate keypair
              </button>
            </div>
            {gen && newKey.trim() === gen.pub && (
              <div style={{ marginTop: "0.6rem", padding: "0.75rem", border: "1px solid rgba(208,128,90,0.4)", borderRadius: "6px", background: "rgba(208,128,90,0.08)", maxWidth: "34rem" }}>
                <div className="bad" style={{ fontSize: "0.85rem", fontWeight: 600 }}>Save this now — it is shown once.</div>
                <div className="muted" style={{ fontSize: "0.82rem", margin: "0.25rem 0" }}>
                  This is the private key for the public key above. Give it to the new admin over a secure channel — they use it to sign. It is not stored anywhere.
                </div>
                <code className="mono" style={{ wordBreak: "break-all", color: "var(--ink)" }}>{gen.secret}</code>
              </div>
            )}
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
