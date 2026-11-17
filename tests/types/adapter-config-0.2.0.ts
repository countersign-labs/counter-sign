// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Not a test file: tests/adapter-config-types.test.ts compiles it with tsc.
// Config objects written exactly as a 0.2.0 user would have written them must
// still type-check: every field added after 0.2.0 is optional, and no 0.2.0
// field changed its type.

import { SlackAdapter, slackConfigFromEnv, type SlackConfig } from "../../src/adapters/slack.js";
import { TelegramAdapter, telegramConfigFromEnv, type TelegramConfig } from "../../src/adapters/telegram.js";
import { WhatsAppAdapter, whatsappConfigFromEnv, type WhatsAppConfig } from "../../src/adapters/whatsapp.js";

const slack: SlackConfig = {
  botToken: "xoxb",
  channelId: "C1",
  signingSecret: "s",
  authorityKey: "k",
  apiBase: "https://slack.com/api",
};

const telegram: TelegramConfig = {
  botToken: "t",
  chatId: "1",
  authorityKey: "k",
  mode: "poll",
  webhookSecret: undefined,
  apiBase: "https://api.telegram.org",
};

const whatsapp: WhatsAppConfig = {
  accessToken: "t",
  phoneNumberId: "555",
  to: "6591234567",
  templateName: "countersign_approval",
  templateLang: "en",
  verifyToken: "v",
  appSecret: "s",
  authorityKey: "k",
  graphBase: "https://graph.facebook.com/v20.0",
};

// 0.2.0 read these as plain strings.
const to: string = whatsappConfigFromEnv(whatsapp).to;
const apiBase: string = slackConfigFromEnv(slack).apiBase;
const mode: "poll" | "webhook" = telegramConfigFromEnv(telegram).mode;

// A helper that takes a full config, the pattern the reviewer named.
function build(cfgs: { slack: SlackConfig; telegram: TelegramConfig; whatsapp: WhatsAppConfig }) {
  return [new SlackAdapter(cfgs.slack), new TelegramAdapter(cfgs.telegram), new WhatsAppAdapter(cfgs.whatsapp)];
}

export const used = [to, apiBase, mode, build({ slack, telegram, whatsapp })];
