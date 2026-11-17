// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Telegram demo: sends the Intent to your chat with Approve/Reject buttons
// and long-polls for the button press — works with no public URL.
//   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... npm run demo:telegram
//
// The approver is the PERSON who presses the button, `telegram:<user id>`,
// not the chat the message lands in. In a private chat with the bot the two
// ids are the same number, so TELEGRAM_APPROVER_ID can be left unset. In a
// group, the chat id is the group's (negative) id: set TELEGRAM_APPROVER_ID
// to the approver's own user id, or their press will not count.

import { TelegramAdapter } from "../src/adapters/telegram.js";
import { demoFields, requireEnvOrExplain, runDemo } from "./_shared.js";

requireEnvOrExplain(
  ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
  "Create a bot with @BotFather; get your chat id from @userinfobot or getUpdates.",
);

const approverId = process.env.TELEGRAM_APPROVER_ID || process.env.TELEGRAM_CHAT_ID;
// enforceLimits: count the message in UTF-16 code units, so nothing near the limit is refused.
await runDemo(new TelegramAdapter({ enforceLimits: true }), demoFields({ approvers: [`telegram:${approverId}`] }));
