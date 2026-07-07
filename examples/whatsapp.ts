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
  ["WHATSAPP_ACCESS_TOKEN", "WHATSAPP_PHONE_NUMBER_ID", "WHATSAPP_TO", "WHATSAPP_VERIFY_TOKEN"],
  "Set up a Meta app with the WhatsApp product and a test number; see adapters/README.md.",
);

const port = Number(process.env.WHATSAPP_PORT ?? 8792);
const adapter = new WhatsAppAdapter();
const server = createServer(adapter.webhookHandler()).listen(port);
console.log(`Meta webhook listening on :${port} — make sure your public tunnel points here.`);

try {
  await runDemo(adapter, demoFields({ approvers: [`whatsapp:${process.env.WHATSAPP_TO}`] }));
} finally {
  server.close();
}
