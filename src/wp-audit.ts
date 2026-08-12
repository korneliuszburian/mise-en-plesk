import type { WordPressInstallation } from "./plesk-scan";

export interface PluginInfo {
  name: string;
  version: string;
  active: boolean;
}

export interface WordPressAudit {
  installation: WordPressInstallation;
  coreVersion: string;
  plugins: PluginInfo[];
  health: { reachable: boolean; lastUpdate?: string };
  priorities: string[];
}

export interface AuditResult {
  generatedAt: string;
  hosts: Array<{ host: string; wordpress: WordPressAudit[] }>;
}

export type WpCommandRunner = (installation: WordPressInstallation, command: string) => Promise<string>;

const defaultWpRunner: WpCommandRunner = async (installation, command) => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const result = await promisify(execFile)("wp", [
    ...command.split(/\s+/),
    `--path=${installation.path}`,
    "--allow-root",
  ]);
  return result.stdout;
};

export async function auditWordPressInstallation(
  installation: WordPressInstallation,
  runner: WpCommandRunner = defaultWpRunner,
): Promise<WordPressAudit> {
  const coreVersion = (await runner(installation, "core version")).trim();
  const pluginOutput = await runner(installation, "plugin list --format=json");
  const rawPlugins: unknown = JSON.parse(pluginOutput);
  if (!Array.isArray(rawPlugins)) throw new Error(`wp plugin list returned invalid JSON for ${installation.path}`);
  const plugins = rawPlugins.map((plugin) => {
    if (!plugin || typeof plugin !== "object") throw new Error("wp plugin list contained an invalid item");
    const value = plugin as Record<string, unknown>;
    return {
      name: String(value.name ?? ""),
      version: String(value.version ?? ""),
      active: value.status === "active",
    };
  });
  await runner(installation, "core verify-checksums");
  return applyHeuristics({ installation, coreVersion, plugins, health: { reachable: true } });
}

export function applyHeuristics(audit: Omit<WordPressAudit, "priorities">): WordPressAudit {
  const priorities: string[] = [];
  if (/^(4|5)\./.test(audit.coreVersion)) priorities.push("core is very old");
  if (!audit.health.reachable) priorities.push("installation is unreachable");
  return { ...audit, priorities };
}
