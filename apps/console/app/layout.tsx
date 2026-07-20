import type { ReactNode } from "react";
import { Inter, Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const space = Space_Grotesk({ subsets: ["latin"], variable: "--font-space", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata = {
  title: "counter-sign console",
  description: "Config and read-only audit for your organization's approval policy.",
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "any" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${space.variable} ${mono.variable}`}>
      <body>
        <nav className="nav">
          <a href="/" className="brand" aria-label="counter-sign">
            {/* the pixel two-tone wordmark from the landing site */}
            <img src="/wordmark.svg" alt="counter-sign" />
          </a>
          <span className="links">
            <a href="/approvers">Approvers</a>
            <a href="/roles">Roles</a>
            <a href="/rules">Rules</a>
            <a href="/admins">Admins</a>
            <a href="/audit">Audit</a>
          </span>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
