import type { FindingEvent } from "./finding-state";

export interface NotificationChunk {
  events: FindingEvent[];
  text: string;
}

function siteKey(event: FindingEvent): string {
  return `${event.finding.host}/${event.finding.domain ?? event.finding.installationPath}`;
}

function eventText(event: FindingEvent, maxLength: number): string {
  const label = event.type === "resolved" ? "recovered" : event.type;
  const text = `[${event.finding.severity}] ${label} on ${siteKey(event)}: ${event.finding.message}`;
  return text.length <= maxLength ? text : `${text.slice(0, Math.max(0, maxLength - 1))}…`;
}

function groupedItems(events: FindingEvent[], maxLength: number): NotificationChunk[] {
  const groups = new Map<string, FindingEvent[]>();
  for (const event of events) groups.set(siteKey(event), [...(groups.get(siteKey(event)) ?? []), event]);
  const items: NotificationChunk[] = [];
  for (const [site, group] of groups) {
    if (group.length === 1) {
      items.push({ events: group, text: eventText(group[0]!, maxLength) });
      continue;
    }
    const groupedText = `${site}:\n${group.map((event) => `- ${event.type === "resolved" ? "recovered" : event.type}: ${event.finding.message}`).join("\n")}`;
    if (groupedText.length <= maxLength) {
      items.push({ events: group, text: groupedText });
      continue;
    }
    for (const event of group) items.push({ events: [event], text: eventText(event, maxLength) });
  }
  return items;
}

export function chunkFindingEvents(events: FindingEvent[], maxLength: number): NotificationChunk[] {
  const boundedLength = Math.max(1, Math.floor(maxLength));
  const chunks: NotificationChunk[] = [];
  let current: NotificationChunk = { events: [], text: "" };
  for (const item of groupedItems(events, boundedLength)) {
    if (current.events.length && current.text.length + 1 + item.text.length > boundedLength) {
      chunks.push(current);
      current = { events: [], text: "" };
    }
    current.events.push(...item.events);
    current.text += `${current.text ? "\n" : ""}${item.text}`;
  }
  if (current.events.length) chunks.push(current);
  return chunks;
}
