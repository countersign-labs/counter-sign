// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Discord demo: posts the Intent with Approve/Reject buttons and receives
// the decision on the app's Interactions Endpoint. Discord requires that
// endpoint to be public HTTPS — expose DISCORD_PORT with e.g.
// `cloudflared tunnel --url http://localhost:8790` and set the tunnel URL
// as the Interactions Endpoint URL in the developer portal first.
//   npm run demo:discord

import { createServer } from "node:http";
import { DiscordAdapter } from "../src/adapters/discord.js";
import { demoFields, requireEnvOrExplain, runDemo } from "./_shared.js";

requireEnvOrExplain(
  ["DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID", "DISCORD_PUBLIC_KEY"],
  "Create an app + bot at https://discord.com/developers; invite it with Send Messages.",
);

const port = Number(process.env.DISCORD_PORT ?? 8790);
const adapter = new DiscordAdapter();
const server = createServer(adapter.interactionHandler()).listen(port);
console.log(`Interactions endpoint listening on :${port} — make sure your public tunnel points here.`);

try {
  // The actor is the user who clicks (`discord:<user id>`), not the channel — set
  // DISCORD_APPROVER_ID to the approver's Discord user id.
  await runDemo(adapter, demoFields({ approvers: [`discord:${process.env.DISCORD_APPROVER_ID ?? "YOUR_DISCORD_USER_ID"}`] }));
} finally {
  server.close();
}
