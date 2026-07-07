// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Email demo — runs FULLY OFFLINE. A debug SMTP inbox captures the mail, the
// approve link is extracted and printed, and the confirm-page flow (GET the
// page, then POST the form) is driven automatically. Set EMAIL_MANUAL=1 to
// click the link in your own browser instead.
//   npm run demo:email

import { EmailAdapter } from "../src/adapters/email.js";
import { demoFields, ensureAuthorityKey, runDemo } from "./_shared.js";
import { startDebugSmtp } from "./lib/debug-smtp.js";

// One authority key, shared by the adapter and the shim (see ensureAuthorityKey).
ensureAuthorityKey();

const SMTP_PORT = Number(process.env.DEBUG_SMTP_PORT ?? 2525);
const CALLBACK_PORT = Number(process.env.EMAIL_PORT ?? 8788);
const manual = process.env.EMAIL_MANUAL === "1";

const smtp = await startDebugSmtp(SMTP_PORT, (mail) => {
  // The email labels its links "Approve: <url>" / "Reject: <url>".
  const approve = mail.text.match(/Approve:\s+(\S+)/)?.[1];
  if (!approve) {
    console.error("Could not find the approve link in the captured email.");
    process.exitCode = 1;
    return;
  }
  console.log(`\n📬 Email captured by debug inbox. Approve link:\n   ${approve}`);
  if (manual) {
    console.log("\nEMAIL_MANUAL=1 — open the link in your browser and press Confirm.");
    return;
  }
  void (async () => {
    // What a mail scanner does — and why it must be harmless:
    const prefetch = await fetch(approve);
    console.log(`   GET (like a mail scanner would): ${prefetch.status} — nothing decided yet.`);
    // What a human does on the confirm page:
    const token = new URL(approve).searchParams.get("token")!;
    const post = await fetch(`http://127.0.0.1:${CALLBACK_PORT}/decide`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `token=${encodeURIComponent(token)}`,
    });
    console.log(`   POST (the human pressing Confirm): ${post.status} — decision recorded.`);
  })();
});

const adapter = new EmailAdapter({
  smtpUrl: process.env.SMTP_URL ?? `smtp://127.0.0.1:${SMTP_PORT}`,
  from: process.env.EMAIL_FROM ?? "approvals@countersign.local",
  to: process.env.EMAIL_TO ?? "you@countersign.local",
  callbackBaseUrl: process.env.EMAIL_CALLBACK_BASE_URL ?? `http://127.0.0.1:${CALLBACK_PORT}`,
  // authorityKey resolved from COUNTERSIGN_AUTHORITY_KEY — the same key the shim uses.
});
const callbackServer = adapter.createServer().listen(CALLBACK_PORT, "127.0.0.1");

try {
  await runDemo(adapter, demoFields({ approvers: ["email:you@countersign.local"], timeout: manual ? 300 : 60 }));
} finally {
  callbackServer.close();
  smtp.close();
}
