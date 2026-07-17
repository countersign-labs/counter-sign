import type { ReactNode } from "react";

export const metadata = { title: "counter-sign console" };

const linkStyle = { color: "#0a58ca", textDecoration: "none" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: 0, color: "#1a1a1a" }}>
        <nav
          style={{
            display: "flex",
            gap: "1.25rem",
            alignItems: "baseline",
            padding: "0.9rem 1.5rem",
            borderBottom: "1px solid #e2e2e2",
          }}
        >
          <a href="/" style={{ ...linkStyle, fontWeight: 700, color: "#111" }}>
            counter-sign
          </a>
          <a href="/approvers" style={linkStyle}>Approvers</a>
          <a href="/roles" style={linkStyle}>Roles</a>
          <a href="/rules" style={linkStyle}>Rules</a>
          <a href="/admins" style={linkStyle}>Admins</a>
          <a href="/audit" style={linkStyle}>Audit</a>
        </nav>
        <main style={{ padding: "1.75rem 1.5rem", maxWidth: "62rem" }}>{children}</main>
      </body>
    </html>
  );
}
