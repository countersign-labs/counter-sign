# Adapter setup guides

Every adapter is configured through environment variables only — copy
[.env.example](../.env.example) to `.env` and fill in the block for your
channel. All adapters share `COUNTERSIGN_AUTHORITY_KEY` (generate with
`npm run keygen`), the ed25519 seed that signs Countersignatures.

**Quorum note.** An Intent's `quorum` (M-of-N / two-person approval) needs a
channel where distinct approvers can each respond: the chat adapters (Telegram,
Discord, Slack, WhatsApp) and the local approver accumulate distinct-actor
approvals and keep their buttons live until the quorum is met or someone vetoes.
The email adapter is single-recipient and supports `quorum: 1` only — it refuses
anything higher at delivery.

## Telegram (low effort — works with no public URL)

1. Message [@BotFather](https://t.me/BotFather), `/newbot`, copy the token
   into `TELEGRAM_BOT_TOKEN`.
2. Message your new bot once (bots can't start conversations), then get your
   chat id from `https://api.telegram.org/bot<token>/getUpdates` or
   [@userinfobot](https://t.me/userinfobot). Set `TELEGRAM_CHAT_ID`.
3. `npm run demo:telegram`. Default mode long-polls `getUpdates`, so no
   public URL is needed. For production webhooks set `TELEGRAM_MODE=webhook`,
   call `setWebhook` with a secret token, and serve
   `adapter.webhookHandler()`.

## Discord (medium effort — needs a public HTTPS endpoint)

1. Create an app at <https://discord.com/developers/applications>, add a
   Bot, copy the token to `DISCORD_BOT_TOKEN` and the app's **Public Key**
   to `DISCORD_PUBLIC_KEY`.
2. Invite the bot to your server with *Send Messages* permission; copy the
   target channel id to `DISCORD_CHANNEL_ID` (enable Developer Mode →
   right-click channel → Copy ID).
3. Discord delivers button presses to your app's **Interactions Endpoint
   URL**, which must be public HTTPS. Expose the demo port, e.g.
   `cloudflared tunnel --url http://localhost:8790`, paste the tunnel URL
   into the developer portal (Discord sends a signed PING to verify — the
   adapter answers it), then `npm run demo:discord`.

## Slack (medium effort — needs a public HTTPS endpoint)

1. Create an app at <https://api.slack.com/apps> → *From scratch*. Under
   **OAuth & Permissions** add the `chat:write` bot scope and install to
   your workspace; copy the Bot User OAuth Token to `SLACK_BOT_TOKEN`.
2. Copy the **Signing Secret** (Basic Information) to
   `SLACK_SIGNING_SECRET` — the adapter verifies every interactivity
   request against it and rejects the rest.
3. Invite the bot to a channel (`/invite @yourbot`) and put the channel id
   in `SLACK_CHANNEL_ID`.
4. Under **Interactivity & Shortcuts**, enable interactivity and set the
   Request URL to your public tunnel for port 8791, then
   `npm run demo:slack`.

## WhatsApp (high effort — Meta Business Cloud API only)

This adapter uses the **Meta WhatsApp Business Cloud API exclusively**;
unofficial web-client libraries are out of scope and against WhatsApp's
terms.

1. **Meta app**: at <https://developers.facebook.com> create an app of type
   *Business* and add the **WhatsApp** product. This provisions a **free
   test phone number** you can message from immediately — no business
   verification needed for testing.
2. From *WhatsApp → API Setup* copy the temporary access token to
   `WHATSAPP_ACCESS_TOKEN` and the test number's **Phone number ID** to
   `WHATSAPP_PHONE_NUMBER_ID`. Add your own phone as a recipient (test
   numbers may message up to 5 verified recipients) and put it in
   `WHATSAPP_TO` (E.164 digits, no `+`).
3. **Template**: business-initiated messages must use a pre-approved
   template. Under *WhatsApp → Message templates* create one named
   `countersign_approval` (category: UTILITY) with body
   `{{1}} — action: {{2}} ({{3}})` and **two quick-reply buttons** labelled
   `Approve` and `Reject`. Test-number templates are approved in minutes.
4. **Webhook**: expose port 8792 publicly, set the callback URL under
   *WhatsApp → Configuration*, choose any `WHATSAPP_VERIFY_TOKEN` (Meta
   sends a GET challenge the adapter answers), and subscribe to the
   `messages` field. Optionally set `WHATSAPP_APP_SECRET` so payload
   signatures (`X-Hub-Signature-256`) are verified.
5. `npm run demo:whatsapp`, then press a quick-reply button on your phone.

## Email (low effort — any SMTP server)

1. Point `SMTP_URL` at any SMTP server (`smtp://user:pass@host:587`), set
   `EMAIL_FROM`/`EMAIL_TO`.
2. Set `EMAIL_CALLBACK_BASE_URL` to wherever the adapter's confirm-page
   server (`adapter.createServer()`) is reachable by the approver.
3. The email carries signed **single-use** Approve/Reject links that expire
   exactly when the Intent times out. Opening a link never decides —
   the GET renders a confirm page and the decision executes only on the
   page's POST, so mail-scanner prefetch cannot approve anything.
4. Fully-offline demo (built-in debug SMTP inbox, auto-driven confirm):
   `npm run demo:email`. Set `EMAIL_MANUAL=1` to click the link yourself.
