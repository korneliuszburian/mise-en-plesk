import type { AuditResult } from "./wp-audit";

export interface ScanOutputOptions {
  reportPath: string;
  json: boolean;
  alertAccepted?: boolean;
  whatsappAccepted?: boolean;
  hermesAccepted?: boolean;
}

export function formatScanOutput(result: AuditResult, options: ScanOutputOptions): string {
  if (options.json) return JSON.stringify(result, null, 2);

  const eventSummary = result.findingEvents?.length
    ? ` ${result.findingEvents.length} finding state change(s): ${result.findingEvents.map((event) => event.type).join(", ")}.`
    : " No finding state changes.";
  const lines = [
    `Read-only scan complete. Report written to ${options.reportPath}.`,
    `Open findings: ${result.findings?.length ?? 0}.${eventSummary}`,
  ];
  if (options.alertAccepted) lines.push("Provider accepted pending P1 alert(s).");
  if (options.whatsappAccepted) lines.push("Meta accepted pending P1 WhatsApp alert(s).");
  if (options.hermesAccepted) lines.push("Hermes accepted pending P1 alert(s).");
  return lines.join("\n");
}
