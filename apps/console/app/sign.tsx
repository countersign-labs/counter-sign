"use client";
// Shared client-side signing helpers for the write forms. The admin key is entered
// masked (never shown by default, never sent to the server): the browser signs the
// policy entry locally and posts only the signed entry.
import { useState } from "react";
import { getHead, submitEntry } from "./actions";
import { signPolicyEntry, type PolicyChange } from "../lib/policy-entry";

export interface Signer {
  seed: string;
  setSeed: (s: string) => void;
  show: boolean;
  setShow: (b: boolean) => void;
  busy: boolean;
  msg: { ok: boolean; text: string } | null;
  sign: (change: PolicyChange, okText: string) => Promise<boolean>;
}

export function useSigner(): Signer {
  const [seed, setSeed] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function sign(change: PolicyChange, okText: string): Promise<boolean> {
    setBusy(true);
    setMsg(null);
    try {
      const entry = await signPolicyEntry(change, await getHead(), seed.trim());
      const res = await submitEntry(entry);
      if (res.ok) {
        setMsg({ ok: true, text: okText });
        setSeed(""); // clear the admin seed after a successful signature — don't leave the org root key resident in the page
      } else {
        setMsg({ ok: false, text: res.error });
      }
      return res.ok;
    } catch (err) {
      setMsg({ ok: false, text: `Signing failed: ${err instanceof Error ? err.message : String(err)}` });
      return false;
    } finally {
      setBusy(false);
    }
  }

  return { seed, setSeed, show, setShow, busy, msg, sign };
}

/** Masked admin-key entry with a show/hide toggle and a plain explanation. */
export function AdminKeyField({ signer }: { signer: Signer }) {
  return (
    <div style={{ marginTop: "1.1rem" }}>
      <label>
        Admin key to sign with{" "}
        <span className="muted">— your ed25519 private key. It stays in this browser and is never sent to the server.</span>
      </label>
      <div style={{ display: "flex", gap: "0.5rem", maxWidth: "30rem", marginTop: "0.3rem" }}>
        <input
          type={signer.show ? "text" : "password"}
          value={signer.seed}
          onChange={(e) => signer.setSeed(e.target.value)}
          placeholder="base64url ed25519 seed"
          autoComplete="off"
          spellCheck={false}
          style={{ flex: 1, fontFamily: "var(--mono)" }}
          required
        />
        <button type="button" onClick={() => signer.setShow(!signer.show)} style={{ background: "transparent", color: "var(--dim)", border: "1px solid var(--line)" }}>
          {signer.show ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}

export function Result({ signer }: { signer: Signer }) {
  if (!signer.msg) return null;
  return <p className={signer.msg.ok ? "ok" : "bad"} style={{ marginTop: "0.75rem" }}>{signer.msg.text}</p>;
}
