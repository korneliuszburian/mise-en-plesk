import { sendFindingEventsViaHermes } from "./hermes";
import { notifyFindingEvents } from "./notifications";
import type { NotificationChannelAdapter } from "./notifier";
import { notifyFindingEventsToWhatsApp } from "./whatsapp";

export function createNotificationAdapters(
  env: NodeJS.ProcessEnv = process.env,
  debug: (message: string) => void = (message) => console.error(message),
): NotificationChannelAdapter[] {
  const whatsappConfigured = [
    env.MISE_PLESK_WHATSAPP_ACCESS_TOKEN,
    env.MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID,
    env.MISE_PLESK_WHATSAPP_RECIPIENT,
    env.MISE_PLESK_WHATSAPP_TEMPLATE_NAME,
    env.MISE_PLESK_WHATSAPP_GRAPH_VERSION,
  ].every((value) => Boolean(value?.trim()));

  return [
    {
      channel: "webhook",
      configured: Boolean(env.MISE_PLESK_ALERT_WEBHOOK_URL?.trim()),
      notifier: {
        send: async (events) => {
          const result = await notifyFindingEvents(events, { webhookUrl: env.MISE_PLESK_ALERT_WEBHOOK_URL, debug });
          return {
            outcome: result.outcome,
            acceptedEvents: result.outcome === "accepted" ? events : [],
          };
        },
      },
    },
    {
      channel: "whatsapp",
      configured: whatsappConfigured,
      notifier: {
        send: async (events) => {
          const result = await notifyFindingEventsToWhatsApp(events, {
            accessToken: env.MISE_PLESK_WHATSAPP_ACCESS_TOKEN,
            phoneNumberId: env.MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID,
            recipient: env.MISE_PLESK_WHATSAPP_RECIPIENT,
            templateName: env.MISE_PLESK_WHATSAPP_TEMPLATE_NAME,
            templateLanguage: env.MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE,
            graphVersion: env.MISE_PLESK_WHATSAPP_GRAPH_VERSION,
            debug,
          });
          return {
            outcome: result.outcome,
            acceptedEvents: result.acceptedEvents,
            providerReceipts: result.providerReceipts,
          };
        },
      },
    },
    {
      channel: "hermes",
      configured: Boolean(env.MISE_PLESK_HERMES_WHATSAPP_TARGET?.trim()),
      notifier: {
        send: async (events) => {
          const result = await sendFindingEventsViaHermes(events, {
            target: env.MISE_PLESK_HERMES_WHATSAPP_TARGET,
            binary: env.MISE_PLESK_HERMES_BIN,
            debug,
          });
          return { outcome: result.outcome, acceptedEvents: result.acceptedEvents };
        },
      },
    },
  ];
}
