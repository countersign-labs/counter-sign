// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Telegram demo: sends the Intent to your chat with Approve/Reject buttons
// and long-polls for the button press — works with no public URL.
//   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... npm run demo:telegram

import { TelegramAdapter } from "../src/adapters/telegram.js";
import { demoFields, requireEnvOrExplain, runDemo } from "./_shared.js";

requireEnvOrExplain(
  ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
  "Create a bot with @BotFather; get your chat id from @userinfobot or getUpdates.",
);

await runDemo(new TelegramAdapter(), demoFields({ approvers: [`telegram:${process.env.TELEGRAM_CHAT_ID}`] }));
