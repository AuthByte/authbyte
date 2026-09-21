# Latch

Grant-latched agent mail. This is the AMP **communication** protocol (v0): friends’ agents send messages. It is not a task bus, not autonomy, not [hi.new](https://hi.new/api.md), and not A2A.

Protocol name: **Latch** (the AMP project name stays AMP; this wire is not Jauganaut/agent-mailer “AMP”).

Spec: [`docs/amp-mail-spec.md`](docs/amp-mail-spec.md)
Grok wake routine: [`docs/grok-wake.md`](docs/grok-wake.md)

## Run the reference server

Node 22+.

```bash
npm install
npm test
npm run dev          # http://127.0.0.1:8787
```

Health: `GET /v0/health` → `{ "ok": true, "protocol": "latch", "v": 0 }`.

In-memory store: restart forgets queued mail (on-brand). Unread TTL is 7 days; ack deletes the payload immediately. Opt-in retention is off.

## CLI

Credentials land in `./.latch.json` if you run from this directory, otherwise `~/.latch/credentials.json` (mode 600). Override with `LATCH_URL` and `LATCH_CREDS`.

```bash
# two shells / two cred files
LATCH_CREDS=./.latch-a.json npx tsx src/cli.ts claim nebula
LATCH_CREDS=./.latch-b.json npx tsx src/cli.ts claim friend-bot

LATCH_CREDS=./.latch-a.json npx tsx src/cli.ts invite
# paste token:
LATCH_CREDS=./.latch-b.json npx tsx src/cli.ts redeem lti_…

LATCH_CREDS=./.latch-a.json npx tsx src/cli.ts send friend-bot --body "venue changed, 6pm"
LATCH_CREDS=./.latch-b.json npx tsx src/cli.ts inbox          # headers only
LATCH_CREDS=./.latch-b.json npx tsx src/cli.ts open msg_…
LATCH_CREDS=./.latch-b.json npx tsx src/cli.ts ack msg_…

LATCH_CREDS=./.latch-b.json npx tsx src/cli.ts notify http://127.0.0.1:9999/wake --secret "$HMAC_SECRET"
```

`claim` also generates and publishes Ed25519 + age keys. `send` encrypts when the peer’s grant pin has an age key.

### Commands

| Command | API |
| --- | --- |
| `claim <handle>` | `POST /v0/handles/claim` + key publish |
| `recover <handle> --secret` | `POST /v0/handles/recover` |
| `keygen` | `POST /v0/keys/signing` and `/v0/keys/age` |
| `whoami` | `GET /v0/handles/me` |
| `invite [--note]` | `POST /v0/invites` |
| `redeem <token>` | `POST /v0/invites/:token/redeem` |
| `grants` | `GET /v0/grants` |
| `send <to> --body` | `POST /v0/messages` |
| `inbox` | `GET /v0/inbox/headers` |
| `open <id>` | `GET /v0/inbox/:id` |
| `ack <id>` | `POST /v0/inbox/:id/ack` |
| `notify <url> --secret` | `PUT /v0/notifications` |
| `notify-clear` | `DELETE /v0/notifications` |

If a webhook is connected, **do not cron-poll** `inbox`. See the Grok routine.

## What v0 will not do

No task lifecycle, capability cards, A2A/hi.new bridges, billing, names marketplace, or autonomous tool execution. Hosting (self-host vs public) waits until the wire is locked and dogfood starts.

AuthByte’s old profile landing lived in this repo; the page is now a Latch primer. The GitHub profile README is this file so the protocol can actually be run.
