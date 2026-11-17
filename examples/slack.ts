// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Slack demo: posts a Block Kit message with Approve/Reject buttons and
// receives the decision on the app's Interactivity Request URL. Expose
// SLACK_PORT publicly (e.g. `cloudflared tunnel --url http://localhost:8791`)
// and set the tunnel URL as the Request URL first. Request signatures are
// verified with SLACK_SIGNING_SECRET; set SLACK_APP_ID (and SLACK_TEAM_ID) as
// well so presses from any other app or workspace are refused.
//   npm run demo:slack

import { createServer } from "node:http";
import { SlackAdapter } from "../src/adapters/slack.js";
import { demoFields, requireEnvOrExplain, runDemo } from "./_shared.js";

requireEnvOrExplain(
  ["SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID", "SLACK_SIGNING_SECRET"],
  "Create an app at https://api.slack.com/apps with chat:write; enable Interactivity.",
);

if (!process.env.SLACK_APP_ID)
  console.warn("SLACK_APP_ID is not set: any correctly signed request will be believed. Set it (Basic Information → App ID).");

const port = Number(process.env.SLACK_PORT ?? 8791);
// enforceLimits: count the message in UTF-16 code units, so nothing near the limit is cut.
const adapter = new SlackAdapter({ enforceLimits: true });
const server = createServer(adapter.interactivityHandler()).listen(port);
console.log(`Interactivity endpoint listening on :${port} — make sure your public tunnel points here.`);

try {
  // The actor is the user who clicks (`slack:<user id>`), not the channel — set
  // SLACK_APPROVER_ID to the approver's Slack user id (e.g. U024BE7LH).
  await runDemo(adapter, demoFields({ approvers: [`slack:${process.env.SLACK_APPROVER_ID ?? "UYOURUSERID"}`] }));
} finally {
  server.close();
}
