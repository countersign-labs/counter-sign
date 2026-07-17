"use client";
// Add-a-rule form. The admin key (base64url ed25519 seed) is entered here, used to sign
// the entry IN THE BROWSER, and never sent to the server. On submit we fetch the current
// head, sign the rule-set entry client-side, and post the signed entry for validation.
import { useState } from "react";
import { getHead, submitEntry } from "../actions";
import { signPolicyEntry, type PolicyChange } from "../../lib/policy-entry";

export function NewRuleForm({ org, roleIds }: { org: string; roleIds: string[] }) {
  const [name, setName] = useState("");
  const [roles, setRoles] = useState<string[]>([]);
  const [quorum, setQuorum] = useState(1);
  const [def, setDef] = useState<"approve" | "reject">("reject");
  const [minutes, setMinutes] = useState(60);
  const [action, setAction] = useState("");
  const [risk, setRisk] = useState("high");
  const [seed, setSeed] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // quorum > 1 forces default reject (the library rejects otherwise); reflect it in the UI.
  const approveAllowed = quorum <= 1;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const effectiveDefault = approveAllowed ? def : "reject";
      const change: PolicyChange = {
        kind: "rule-set",
        rule: {
          id: name.trim().toLowerCase().replace(/\s+/g, "-"),
          org,
          name: name.trim(),
          roles,
          quorum,
          default: effectiveDefault,
          timeout_seconds: Math.max(1, Math.round(minutes * 60)),
          ...(action.trim() ? { action: action.trim() } : {}),
          ...(risk ? { risk_tier: risk } : {}),
        },
      };
      const head = await getHead();
      const entry = await signPolicyEntry(change, head, seed.trim());
      const res = await submitEntry(entry);
      if (res.ok) {
        setMsg({ ok: true, text: `Rule "${change.rule.name}" signed and recorded.` });
        setName("");
        setRoles([]);
        setAction("");
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
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>+ New rule</summary>
      <form onSubmit={onSubmit} style={{ marginTop: "0.75rem" }}>
        <label style={label}>Name<input style={field} value={name} onChange={(e) => setName(e.target.value)} required /></label>

        <label style={label}>Roles (must approve)</label>
        <div>
          {roleIds.length === 0 && <em style={{ color: "#999" }}>No roles yet — create one first.</em>}
          {roleIds.map((id) => (
            <label key={id} style={{ marginRight: "1rem", fontSize: "0.9rem" }}>
              <input
                type="checkbox"
                checked={roles.includes(id)}
                onChange={(e) => setRoles((rs) => (e.target.checked ? [...rs, id] : rs.filter((r) => r !== id)))}
              />{" "}
              {id}
            </label>
          ))}
        </div>

        <label style={label}>Quorum<input style={field} type="number" min={1} value={quorum} onChange={(e) => setQuorum(Math.max(1, Number(e.target.value)))} /></label>

        <label style={label}>Default on no-confirmation</label>
        <select style={field} value={approveAllowed ? def : "reject"} disabled={!approveAllowed} onChange={(e) => setDef(e.target.value as "approve" | "reject")}>
          <option value="reject">reject (fail closed)</option>
          <option value="approve">approve</option>
        </select>
        {!approveAllowed && <small style={{ color: "#b3261e" }}>quorum &gt; 1 must fail closed (reject).</small>}

        <label style={label}>Review window (minutes)<input style={field} type="number" min={1} value={minutes} onChange={(e) => setMinutes(Math.max(1, Number(e.target.value)))} /></label>
        <label style={label}>Action (optional)<input style={field} value={action} onChange={(e) => setAction(e.target.value)} placeholder="e.g. billing.refund" /></label>
        <label style={label}>Risk tier
          <select style={field} value={risk} onChange={(e) => setRisk(e.target.value)}>
            {["low", "medium", "high", "critical"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>

        <label style={{ ...label, marginTop: "1rem" }}>Admin key (base64url ed25519 seed — stays in your browser, never sent)</label>
        <textarea style={{ ...field, fontFamily: "monospace", height: "3rem" }} value={seed} onChange={(e) => setSeed(e.target.value)} required />

        <button type="submit" disabled={busy || roles.length === 0 || !seed.trim()} style={{ marginTop: "0.75rem", padding: "0.5rem 1rem" }}>
          {busy ? "Signing…" : "Sign & record"}
        </button>
        {msg && <p style={{ color: msg.ok ? "#0a7d33" : "#b3261e", marginTop: "0.75rem" }}>{msg.text}</p>}
      </form>
    </details>
  );
}
