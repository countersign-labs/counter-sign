// Shared UI bits for the console pages (branded via globals.css).
import type { ReactNode } from "react";
import type { ConsoleState } from "../lib/store";

/** A prominent banner shown when chain verification failed — the console fails loud. */
export function VerifyBanner({ state }: { state: ConsoleState }) {
  if (state.verified) return null;
  return (
    <div role="alert" className="banner-fail">
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
  return <p className="muted">{children}</p>;
}

/** Short, readable fingerprint of a key/descriptor for display. */
export function fingerprint(key: string): string {
  const body = key.includes(":") ? key.slice(key.indexOf(":") + 1) : key;
  return body.length <= 16 ? body : `${body.slice(0, 8)}…${body.slice(-6)}`;
}
