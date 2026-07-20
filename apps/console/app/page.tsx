export default function Home() {
  return (
    <div>
      <p className="eyebrow">Admin console</p>
      <h1>Your organization&rsquo;s approval policy</h1>
      <p className="muted" style={{ maxWidth: "40rem" }}>
        Approvers are onboarded into <strong style={{ color: "var(--ink)" }}>roles</strong>;{" "}
        <strong style={{ color: "var(--ink)" }}>rules</strong> reference those roles and carry the
        quorum, the default on no-confirmation, and the review window. Every change is signed by an
        admin key and recorded in a verifiable, hash-chained policy log — the console holds no
        signing key.
      </p>
      <div className="card" style={{ marginTop: "1.5rem", maxWidth: "40rem" }}>
        <p className="eyebrow" style={{ marginBottom: "0.5rem" }}>Get started</p>
        <p className="muted" style={{ margin: 0 }}>
          Head to <a href="/rules">Rules</a> or <a href="/roles">Roles</a> to view and sign new
          policy, <a href="/approvers">Approvers</a> to see who can approve, or{" "}
          <a href="/audit">Audit</a> to check the log&rsquo;s integrity.
        </p>
      </div>
    </div>
  );
}
