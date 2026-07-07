// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Slack demo: posts a Block Kit message with Approve/Reject buttons and
// receives the decision on the app's Interactivity Request URL. Expose
// SLACK_PORT publicly (e.g. `cloudflared tunnel --url http://localhost:8791`)
// and set the tunnel URL as the Request URL first. Request signatures are
// verified with SLACK_SIGNING_SECRET.
//   npm run demo:slack

import { createServer } from "node:http";
import { SlackAdapter } from "../src/adapters/slack.js";
import { demoFields, requireEnvOrExplain, runDemo } from "./_shared.js";

requireEnvOrExplain(
  ["SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID", "SLACK_SIGNING_SECRET"],
  "Create an app at https://api.slack.com/apps with chat:write; enable Interactivity.",
);

const port = Number(process.env.SLACK_PORT ?? 8791);
const adapter = new SlackAdapter();
const server = createServer(adapter.interactivityHandler()).listen(port);
console.log(`Interactivity endpoint listening on :${port} — make sure your public tunnel points here.`);

try {
  await runDemo(adapter, demoFields({ approvers: [`slack:${process.env.SLACK_CHANNEL_ID}`] }));
} finally {
  server.close();
}
