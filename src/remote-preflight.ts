import type { HostConfig } from "./ssh-inventory";
import { renderReadOnlyCommand, type ReadOnlyCommand } from "./ssh-transport";

export interface RemoteCapabilities {
  uid: number | null;
  username: string | null;
  kernel: string | null;
  commands: Record<"bw" | "node" | "pnpm" | "sshpass" | "systemctl", string | null>;
}

export type RemoteCapabilityRunner = (host: HostConfig, command: ReadOnlyCommand) => Promise<string>;

const fields = ["uid", "username", "kernel", "bw", "node", "pnpm", "sshpass", "systemctl"] as const;
type CapabilityField = typeof fields[number];

function readField(output: string, field: CapabilityField): string | null {
  const markerName = field === "username" ? "USER" : field.toUpperCase();
  const marker = `__MISE_REMOTE_${markerName}__`;
  const index = output.indexOf(marker);
  if (index < 0) return null;
  const remainder = output.slice(index + marker.length).replace(/^\r?\n/, "");
  const nextMarker = remainder.search(/__MISE_REMOTE_[A-Z]+__/);
  return (nextMarker >= 0 ? remainder.slice(0, nextMarker) : remainder).trim() || null;
}

function parseUid(value: string | null): number | null {
  if (!value || !/^\d+$/.test(value)) return null;
  const uid = Number(value);
  return Number.isSafeInteger(uid) ? uid : null;
}

export async function readRemoteCapabilities(
  host: HostConfig,
  runner: RemoteCapabilityRunner,
): Promise<RemoteCapabilities> {
  const output = await runner(host, { kind: "remote-capabilities" });
  return {
    uid: parseUid(readField(output, "uid")),
    username: readField(output, "username"),
    kernel: readField(output, "kernel"),
    commands: {
      bw: readField(output, "bw"),
      node: readField(output, "node"),
      pnpm: readField(output, "pnpm"),
      sshpass: readField(output, "sshpass"),
      systemctl: readField(output, "systemctl"),
    },
  };
}

export function renderRemoteCapabilitiesProbe(): string {
  return renderReadOnlyCommand({ kind: "remote-capabilities" });
}
