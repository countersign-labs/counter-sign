// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// WhatsApp demo (Meta WhatsApp Business Cloud API): sends the Intent as a
// pre-approved template with two quick-reply buttons; the decision arrives
// on the Meta webhook. Expose WHATSAPP_PORT publicly and register it as the
// webhook URL (Meta calls GET first to verify WHATSAPP_VERIFY_TOKEN).
// See adapters/README.md for the Meta app + free test-number setup.
//   npm run demo:whatsapp

import { createServer } from "node:http";
import { WhatsAppAdapter } from "../src/adapters/whatsapp.js";
import { demoFields, requireEnvOrExplain, runDemo } from "./_shared.js";

requireEnvOrExplain(
  [
    "WHATSAPP_ACCESS_TOKEN",
    "WHATSAPP_PHONE_NUMBER_ID",
    "WHATSAPP_APPROVER",
    "WHATSAPP_VERIFY_TOKEN",
    "WHATSAPP_APP_SECRET",
  ],
  "Set up a Meta app with the WhatsApp product and a test number; see adapters/README.md.",
);

const port = Number(process.env.WHATSAPP_PORT ?? 8792);
// The stricter settings a new deployment should use, all opt-in:
// - recipientMode "approvers": send to the whatsapp:<number> approvers the
//   Intent names (WHATSAPP_TO is not used). Without a mode, every request goes
//   to WHATSAPP_TO with no check on who the approvers are, as in 0.2.0.
// - requirePhoneNumberId: only believe webhook changes for this business number.
// - enforceLimits: refuse, before sending, a body Meta could cut or reject.
// - confirmDecisions: reply "Decision recorded: ..." after each press.
const adapter = new WhatsAppAdapter({
  recipientMode: "approvers",
  requirePhoneNumberId: true,
  enforceLimits: true,
  confirmDecisions: true,
});
const server = createServer(adapter.webhookHandler()).listen(port);
console.log(`Meta webhook listening on :${port} — make sure your public tunnel points here.`);

try {
  // The actor is the number that pressed the button, as the webhook reports it:
  // E.164 digits with no "+".
  await runDemo(adapter, demoFields({ approvers: [`whatsapp:${process.env.WHATSAPP_APPROVER}`] }));
} finally {
  server.close();
}
