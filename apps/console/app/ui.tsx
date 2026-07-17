// Shared UI bits for the console pages.
import type { ReactNode } from "react";
import type { ConsoleState } from "../lib/store";

/** A prominent banner shown when chain verification failed — the console fails loud. */
export function VerifyBanner({ state }: { state: ConsoleState }) {
  if (state.verified) return null;
  return (
    <div
      role="alert"
      style={{
        background: "#fde8e6",
        border: "1px solid #f3b4ad",
        color: "#8a1c13",
        padding: "0.75rem 1rem",
        borderRadius: "0.5rem",
        margin: "0 0 1.25rem",
      }}
    >
      <strong>⚠ Verification failed.</strong> Do not trust the values below.
      <ul style={{ margin: "0.5rem 0 0" }}>
        {state.faults.map((f, i) => (
          <li key={i}>{f}</li>
        ))}
      </ul>
    </div>
  );
}

/** An empty-state note when a list has no rows yet. */
export function Empty({ children }: { children: ReactNode }) {
  return <p style={{ color: "#777" }}>{children}</p>;
}

export const table = { borderCollapse: "collapse" as const, width: "100%" };
export const th = { textAlign: "left" as const, padding: "0.5rem 0.75rem", borderBottom: "2px solid #e2e2e2", fontSize: "0.85rem", color: "#555" };
export const td = { padding: "0.5rem 0.75rem", borderBottom: "1px solid #eee", fontFamily: "inherit" };
export const mono = { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "0.8rem" };

/** Short, readable fingerprint of a key/descriptor for display. */
export function fingerprint(key: string): string {
  const body = key.includes(":") ? key.slice(key.indexOf(":") + 1) : key;
  return body.length <= 16 ? body : `${body.slice(0, 8)}…${body.slice(-6)}`;
}
