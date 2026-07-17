export default function Home() {
  return (
    <div>
      <h1 style={{ marginTop: 0 }}>counter-sign admin console</h1>
      <p style={{ color: "#555", lineHeight: 1.6 }}>
        Configuration and read-only audit for your organization&rsquo;s approval policy.
        Approvers are onboarded into <strong>roles</strong>; <strong>rules</strong> reference
        those roles and carry the quorum, the default on no-confirmation, and the review
        window. Every change is signed by an admin key and recorded in a verifiable,
        hash-chained policy log — the console holds no signing key.
      </p>
      <p style={{ color: "#555" }}>Pick a section from the nav above to begin.</p>
    </div>
  );
}
