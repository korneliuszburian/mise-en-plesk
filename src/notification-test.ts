import type { FindingEvent } from "./finding-state";

export function requireWhatsAppTestConfirmation(flags: string[], recipient: string | undefined): void {
  if (!recipient?.trim()) throw new Error("WhatsApp recipient is not configured.");
  if (flags.length !== 1 || flags[0] !== `--confirm=${recipient}`) {
    throw new Error("whatsapp-test sends one real test message; rerun with --confirm=<configured recipient> after checking the recipient.");
  }
}

export function createWhatsAppTestEvent(now = new Date()): FindingEvent {
  const occurredAt = now.toISOString();
  return {
    type: "opened",
    occurredAt,
    finding: {
      id: "notification-test",
      code: "monitor-stale",
      severity: "P1",
      host: "notification-test",
      installationPath: "__notification_test__",
      domain: "notification-test",
      message: "mise-en-plesk WhatsApp delivery test",
      status: "open",
      firstSeen: occurredAt,
      lastSeen: occurredAt,
    },
  };
}
