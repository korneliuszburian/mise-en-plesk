import type { AuditResult } from "./wp-audit";

export interface ScanOutputOptions {
  reportPath: string;
  json: boolean;
  alertSent?: boolean;
  whatsappSent?: boolean;
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
  if (options.alertSent) lines.push("Sent pending P1 alert(s).");
  if (options.whatsappSent) lines.push("Sent pending P1 WhatsApp alert(s).");
  return lines.join("\n");
}
