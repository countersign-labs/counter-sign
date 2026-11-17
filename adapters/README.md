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

**How approvers are identified.** The receipt's actor is the person who
pressed the button, `telegram:<their numeric user id>`, never the chat and
never the `@username` (which they can change). Name approvers that way in the
Intent.

- *Private chat with the bot:* the chat id and the user id are the same
  number, so `telegram:<TELEGRAM_CHAT_ID>` names you.
- *Group or supergroup:* `TELEGRAM_CHAT_ID` is the group's id (negative,
  e.g. `-1001234567890`); each approver is named by their own user id. Find
  it in `callback_query.from.id` (or `message.from.id`) in `getUpdates`, or
  ask [@userinfobot](https://t.me/userinfobot). The demo reads it from
  `TELEGRAM_APPROVER_ID`. A press from a group member who is not named is
  ignored.

**One poller per bot.** Telegram serves a bot's updates to one `getUpdates`
consumer at a time; a second process polling the same token gets
`409 Conflict`, and presses would be split between them. When that happens
the adapter stops polling and fails every waiting request with
`TelegramPollingConflictError` ("another process is already polling this
bot") instead of retrying quietly. Run one poller per bot token, give each
process its own bot, or use webhook mode. A bot with a webhook set cannot be
polled either; the same error says so.

**Message limit.** Telegram rejects message text over 4,096 characters. The
adapter checks the full formatted request before sending and refuses to
deliver, with an error, text over that limit counted in characters (code
points), which Telegram rejects however it counts. Pass `enforceLimits: true`
to count UTF-16 code units instead (the unit Telegram uses for offsets), so
text with many emoji near the limit is refused too. The limit is
`TELEGRAM_MAX_MESSAGE_LENGTH`; override it with `maxMessageLength` if Telegram
changes it.

**After a decision** the message is edited to add
`Decision recorded: APPROVE by telegram:<id> at <time>` and the buttons are removed
(kept while a quorum is still open). If that line would push the message
past the limit, the buttons are removed and the line is sent as a reply.

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
5. Recommended: copy the **App ID** (Basic Information) to `SLACK_APP_ID`
   and your workspace's Team ID to `SLACK_TEAM_ID`. A correct signature only
   proves a request came from Slack; with these set, the adapter also refuses
   (403) any button press whose `api_app_id` or team is not yours.

**How approvers are identified.** The actor is the Slack user who pressed the
button, `slack:<user id>` (e.g. `slack:U024BE7LH`), not the channel. A press
from a channel member who is not named in the Intent is ignored.

**Message limit.** Slack rejects a section block over 3,000 characters. The
adapter checks the full formatted request before posting and refuses to
deliver, with an error, text over that limit counted in characters (code
points), which Slack rejects however it counts. Pass `enforceLimits: true` to
count UTF-16 code units instead, never fewer than Slack's characters. The
limit is `SLACK_MAX_SECTION_TEXT_LENGTH`; override it with
`maxSectionTextLength` if Slack changes it.

**After a decision** the message is replaced: the request stays visible, the
buttons go, and a line reads `Decision recorded: APPROVE by @person at
<time>` (a request too long to repeat in a section is replaced by that line
alone). While a quorum is still open, the presser gets a private note
instead and the buttons stay.

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
   `WHATSAPP_APPROVER` (E.164 digits, no `+`); the demo names
   `whatsapp:<that number>` as the approver.
3. **Template**: business-initiated messages must use a pre-approved
   template. Under *WhatsApp → Message templates* create one named
   `countersign_approval` (category: UTILITY) with body
   `{{1}} — action: {{2}} ({{3}})` and **two quick-reply buttons** labelled
   `Approve` and `Reject`. Test-number templates are approved in minutes.
   If your template's body reads differently, set `WHATSAPP_TEMPLATE_BODY`
   to it (with `{{1}}`, `{{2}}` and `{{3}}`) so the `enforceLimits` length
   check below counts the text the approver actually sees.
4. **Webhook**: expose port 8792 publicly, set the callback URL under
   *WhatsApp → Configuration*, choose any `WHATSAPP_VERIFY_TOKEN` (Meta
   sends a GET challenge the adapter answers), and subscribe to the
   `messages` field. Copy the **App secret** (*App settings → Basic*) to
   `WHATSAPP_APP_SECRET`. It is **required**: the adapter verifies the
   `X-Hub-Signature-256` signature on every webhook POST and will not start
   without it.
5. `npm run demo:whatsapp`, then press a quick-reply button on your phone.
   The demo turns on `confirmDecisions`, so a short reply tells you the
   decision was recorded, by whom and when (template messages cannot be
   edited after sending).

**Who gets asked.** Without a recipient mode the adapter behaves as in
0.2.0: every request goes to `WHATSAPP_TO` (`to`), whoever the Intent's
approvers are. Two stricter modes are opt-in (`recipientMode`, or
`WHATSAPP_RECIPIENT_MODE`):

- `"approvers"`: one template message to each `whatsapp:<number>` approver the
  Intent names; `WHATSAPP_TO` is not needed. An Intent that names none is
  refused. Write the number exactly as the webhook reports the sender: E.164
  digits with no `+` (`whatsapp:6591234567`); any other spelling is refused,
  because the press could never be counted. The demo uses this mode.
- `"single"`: every request goes to `WHATSAPP_TO`, and an Intent whose
  WhatsApp approvers are not exactly that number is refused rather than sent
  to someone whose answer would not count, or leaving another approver
  unasked.

All the checks run before the first send. In `"approvers"` mode the sends go
out one after another; if one fails after others went through, `deliver`
throws `DeliveryPartialError`, whose `reached` and `unreached` list the actors
who hold live buttons and those never asked. (If the first send fails, nobody was
reached and the plain send error is thrown.) What a reached approver's press
does then depends on the caller. With plain `wrapAction` the call rejects, the
action does not run and nobody waits on the Intent, so the press is ignored:
tell them the request was withdrawn. With `DurableDecisions` (or `wrapAction`
with a `pendingStore`) the Intent stays pending and marked delivered, so their
press counts, and `issue()` returns the record with the missed approvers in
`unreached` (`wrapAction` hands that record to its `onDelivered` option; the
list is also in the store). Nothing delivers to only the unreached; issue a new Intent to ask
them.

**Who is believed.** One Meta app can serve several business numbers. With
`requirePhoneNumberId: true` (`WHATSAPP_REQUIRE_PHONE_NUMBER_ID=1`) the
adapter ignores any webhook change whose `metadata.phone_number_id` is not
`WHATSAPP_PHONE_NUMBER_ID`, or that carries none. Real Meta payloads always
carry it; the demo turns this on.

**Message limits.** Meta rejects a template variable containing a newline or
a tab, so the adapter refuses such a summary before sending. With
`enforceLimits: true` it also refuses a variable with four or more spaces in
a row, and a template body over 1,024 characters once the variables are
filled in, so the approver never gets a cut or missing request. Write the
Intent's `summary` on one line. The limit is
`WHATSAPP_MAX_TEMPLATE_BODY_LENGTH`; override it with `maxTemplateBodyLength`
if Meta changes it.

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
