# Hermes Agent and WhatsApp alerts

Research date: 2026-08-19. Hermes source snapshot: [`13ce0c5`](https://github.com/NousResearch/hermes-agent/tree/13ce0c5c675e843af70d19c9e5144249cd51c8d1). Only first-party Hermes and Meta sources were used.

## Decision

For production `mise-en-plesk` alerts, prefer a narrow direct integration with the official Meta WhatsApp Cloud API and an approved utility message template. Hermes is reasonable for a temporary operator-only test, but its personal-account bridge is an unofficial WhatsApp Web client with account-ban and protocol-breakage risk. Hermes' current Cloud API adapter is not sufficient for unattended critical alerts because it does not implement template delivery outside Meta's 24-hour customer-service window.

Do not share Korneliusz's personal Hermes/Baileys session with a different service account. If Hermes is used at all, either run the scanner notification process as the same OS user and profile that owns the session, or pair a dedicated WhatsApp number under a dedicated unprivileged service account.

## Is the current command real?

Yes, with an important qualification. Hermes officially implements:

```sh
hermes send --to <platform[:chat-id]> "message"
```

The command is explicitly intended for shell scripts, cron jobs and monitoring daemons; it runs no LLM or agent loop and returns exit code `0` for success, `1` for delivery/backend failure and `2` for usage errors. It loads the selected Hermes profile's `.env` and `config.yaml` before dispatching. ([CLI docs](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/reference/cli-commands.md#hermes-send), [implementation](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/hermes_cli/send_cmd.py#L1-L24), [config loading](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/hermes_cli/send_cmd.py#L232-L325))

Therefore the current `src/hermes.ts` argv shape:

```ts
["send", "--to", "whatsapp:<chat-id>", message]
```

is real for the **Baileys** adapter, not invented. However, mise-en-plesk's validation is looser than Hermes' actual target grammar. A direct recipient should be an E.164 number such as `whatsapp:+48...`, a native WhatsApp JID such as `whatsapp:<digits>@s.whatsapp.net`, or an ID returned by `hermes send --list whatsapp`; a group uses its `@g.us` JID. Hermes parses these forms before normalizing the recipient for Baileys. ([target parser](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/tools/send_message_tool.py#L533-L624))

The official Cloud adapter is a different platform and target:

```sh
hermes send --to whatsapp_cloud:<wa_id> "message"
```

Here `<wa_id>` is the recipient number with country code. A bare `whatsapp:` target never selects Meta Cloud API.

## Install, authentication and session model

### Hermes installation

The official per-user installer is:

```sh
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
```

It places code under `~/.hermes/hermes-agent`, the launcher under `~/.local/bin/hermes`, and user data under `~/.hermes`. Hermes also supports installation as a dedicated non-root service user; `--skip-browser` avoids unrelated browser setup. ([installation guide](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/getting-started/installation.md#quick-install), [non-root service install](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/getting-started/installation.md#non-sudo--system-service-user-installs))

### Personal WhatsApp through Baileys

- `hermes whatsapp` installs/starts Hermes' Node/Baileys bridge and displays a QR code.
- The operator authorizes it in WhatsApp under **Linked Devices**. This is a WhatsApp Web session, not Meta Business authentication.
- Configuration lives in `$HERMES_HOME/.env` and `$HERMES_HOME/config.yaml`; the preferred auth state is `$HERMES_HOME/platforms/whatsapp/session`, with `$HERMES_HOME/whatsapp/session` retained for old installations.
- The session contains `creds.json`, encryption keys and mutable device state. Upstream explicitly says possession of this directory grants full access to the account. ([WhatsApp setup](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/whatsapp.md#step-1-run-the-setup-wizard), [session persistence](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/whatsapp.md#session-persistence), [path resolution](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/plugins/platforms/whatsapp/adapter.py#L420-L429))

`hermes send --to whatsapp:...` does not create an ephemeral WhatsApp connection. Its standalone sender POSTs to the already-running local bridge on `127.0.0.1:3000`; therefore the Hermes gateway/bridge must remain alive. ([standalone sender](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/plugins/platforms/whatsapp/adapter.py#L1695-L1743), [loopback binding](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/scripts/whatsapp-bridge/bridge.js#L781-L814))

### Official Meta Cloud API

`hermes whatsapp-cloud` configures a separate adapter using a WhatsApp Business phone-number ID and access token. Outbound delivery is a bearer-authenticated POST to `https://graph.facebook.com/<version>/<phone-number-id>/messages`; this matches Meta's official request contract. No Baileys session or QR code is involved. ([Hermes Cloud guide](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/whatsapp-cloud.md), [Hermes Graph sender](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/gateway/platforms/whatsapp_cloud.py#L513-L574), [Meta's official Postman collection](https://www.postman.com/meta/whatsapp-business-platform/documentation/wlk6lh4/whatsapp-cloud-api?entity=request-13382743-2e99d361-eef7-47be-948f-19d80a086f2e))

For outbound-only alerts, `hermes send` can call the Cloud API directly without a running gateway. A public webhook is needed only for inbound messages/status handling, not for the basic outbound POST. Hermes expects long-lived production credentials in its profile and recommends a Meta System User token rather than the 24-hour setup token. ([CLI transport distinction](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/hermes_cli/send_cmd.py#L10-L24), [Cloud credentials](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/whatsapp-cloud.md#configuration-reference))

## Headless/systemd operation and permissions

Hermes supports both a user unit (`hermes gateway install`) and a boot-time system unit (`sudo hermes gateway install --system`). A non-root service account is supported; a user unit needs `loginctl enable-linger <user>` to survive logout. Generated units pin `HERMES_HOME`, run as the selected user, use `Restart=always`, and restart after five seconds. ([gateway service docs](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/index.md#gateway-commands), [unit generation](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/hermes_cli/gateway.py#L3330-L3434))

An operator-owned Baileys session is **not safely reusable by a different service user by default**:

- the service resolves state from its own `HERMES_HOME`;
- Baileys continuously rewrites credentials on `creds.update`, so read-only sharing is impossible;
- granting another account access exposes full WhatsApp device credentials;
- two gateways must not concurrently own the same mutable session and bridge port;
- although the bridge is loopback-only, its local HTTP send endpoint has no per-caller authentication, so other users on a multi-user host may be able to submit sends to port 3000.

Use an OS-owned directory with mode `0700` and secret files at `0600`, owned exclusively by the gateway user. Hermes' installer explicitly applies `0600` to `.env`, but the upstream WhatsApp bridge creates its session directory and Baileys files under the process umask rather than documenting/enforcing every file mode. Set `UMask=0077` in the deployment unit and verify the resulting tree before production use. ([installer permissions](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/scripts/install.sh#L1958-L1986), [bridge auth-state creation](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/scripts/whatsapp-bridge/bridge.js#L22-L27))

## Delivery test and recovery semantics

Safe setup/test sequence, after checking the configured recipient manually:

```sh
hermes send --list whatsapp
hermes send --to 'whatsapp:+48...' --json 'mise-en-plesk delivery test'
```

For Cloud API, use `hermes send --list whatsapp_cloud` and `whatsapp_cloud:<wa_id>`. Treat exit code `0` plus a returned platform message ID as **submission evidence**, not proof that a person saw the alert. Delivery/read status requires platform status events/webhooks.

The Baileys bridge serializes sends, uses a 60-second send timeout, and returns one or more message IDs. It automatically reconnects after ordinary disconnects; an explicit logout exits and requires `hermes whatsapp` plus a new QR pairing. The systemd gateway restarts after process failure. ([bounded send queue](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/scripts/whatsapp-bridge/bridge.js#L120-L156), [reconnection](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/scripts/whatsapp-bridge/bridge.js#L422-L458))

The implementation reviewed after this research does not automatically retry
an ambiguous Meta network/timeout result or a failed Hermes command. It stores
that channel outcome as `unknown`, pauses automatic replay, includes a stable
event reference in the message, and persists accepted Meta `wamid` receipts.
Explicit retries can still produce duplicates, so the delivery contract remains
at-least-once and never claims exactly-once delivery.

## Security and production suitability

| Option | Benefits | Blocking risks/limitations | Verdict |
|---|---|---|---|
| Hermes + Baileys (`whatsapp:`) | Fast QR setup, personal/self-chat, no Meta app or public endpoint | Unofficial protocol, account-ban risk, protocol updates can break it, persistent privileged session, unauthenticated loopback send API, dedicated running gateway required | Operator-only pilot with a dedicated number; not the production alert channel |
| Hermes + Cloud (`whatsapp_cloud:`) | Official transport, no account-ban risk, one CLI surface, no gateway needed for outbound text | Full Hermes install/config for a simple POST; current Hermes lacks message-template sending, so proactive alerts fail outside the 24-hour window | Not reliable enough for always-on critical alerts today |
| Direct Meta Cloud API | Official, smallest runtime/credential surface, exact response/status control, templates can support proactive alerts | Requires Meta Business/WABA onboarding, dedicated number, token lifecycle, approved templates, webhook if delivery receipts are required | Recommended production path |

Hermes itself warns that Baileys is unofficial and recommends a dedicated number, no bulk messaging and no unsolicited automation. Its Cloud documentation states that free-form messages fail outside the 24-hour window and that template support is not implemented. That is incompatible with the requirement to alert Korneliusz before a client reports a critical incident: an alert must work after days of silence. ([Baileys warning](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/whatsapp.md#whatsapp-setup), [Cloud 24-hour limitation](https://github.com/NousResearch/hermes-agent/blob/13ce0c5c675e843af70d19c9e5144249cd51c8d1/website/docs/user-guide/messaging/whatsapp-cloud.md#known-limitations))

Recommended implementation boundary for `mise-en-plesk`:

1. Keep alert event generation and deduplication transport-independent.
2. Add a narrow Meta sender using Node's built-in `fetch`, with credentials loaded at runtime from the existing secret mechanism.
3. Send an approved utility template for newly opened P1 incidents; use free-form text only when a valid customer-service window is known.
4. Persist provider message IDs and consume Meta status webhooks if delivery confirmation is required.
5. Keep the existing Hermes adapter disabled or explicitly marked experimental until a dedicated Hermes number/session is provisioned and tested.
