import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readInventory } from "./ssh-inventory";

const execFileAsync = promisify(execFile);

export interface PreflightCheck {
  name: string;
  ok: boolean;
  blocking: boolean;
  detail: string;
}

export interface PreflightResult {
  ok: boolean;
  checks: PreflightCheck[];
}

export interface PreflightOptions {
  inventoryPath?: string;
  configPath?: string;
  env?: NodeJS.ProcessEnv;
  commandRunner?: (command: string) => Promise<string>;
}

export function versionArguments(command: string): string[] {
  return command === "ssh" ? ["-V"] : ["--version"];
}

async function defaultCommandRunner(command: string): Promise<string> {
  const result = await execFileAsync(command, versionArguments(command));
  return (result.stdout || result.stderr).trim();
}

function check(name: string, ok: boolean, detail: string, blocking = true): PreflightCheck {
  return { name, ok, blocking, detail };
}

export async function runPreflight(options: PreflightOptions = {}): Promise<PreflightResult> {
  const env = options.env ?? process.env;
  const commandRunner = options.commandRunner ?? defaultCommandRunner;
  const checks: PreflightCheck[] = [];
  const majorNode = Number(process.versions.node.split(".")[0]);
  checks.push(check("node", majorNode >= 20, `Node.js ${process.versions.node}; requires >= 20`));

  for (const command of ["bw", "ssh", "sshpass"]) {
    const blocking = command !== "sshpass";
    try {
      const version = await commandRunner(command);
      checks.push(check(command, true, version || "available", blocking));
    } catch {
      checks.push(check(command, false, command === "sshpass" ? "optional; required for password-authenticated Secure Notes" : `${command} is not available on PATH`, blocking));
    }
  }

  checks.push(check(
    "BW_SESSION",
    Boolean(env.BW_SESSION?.trim()),
    env.BW_SESSION?.trim() ? "present for this process" : "missing; source scripts/setup-bw-session.sh",
  ));

  const inventoryPath = options.inventoryPath ?? "inventory.json";
  try {
    await readInventory(inventoryPath);
    checks.push(check("inventory", true, `${inventoryPath} is readable`));
  } catch (error: unknown) {
    checks.push(check("inventory", false, error instanceof Error ? error.message : `cannot read ${inventoryPath}`));
  }

  const configPath = options.configPath ?? "config.mise-en-plesk.json";
  try {
    const config = JSON.parse(await readFile(configPath, "utf8")) as unknown;
    checks.push(check("config", Boolean(config && typeof config === "object" && !Array.isArray(config)), `${configPath} is readable`));
  } catch {
    checks.push(check("config", false, `${configPath} is missing or invalid`));
  }

  checks.push(check(
    "alerting",
    Boolean(env.MISE_PLESK_ALERT_WEBHOOK_URL?.trim()),
    env.MISE_PLESK_ALERT_WEBHOOK_URL?.trim() ? "webhook configured" : "disabled; set MISE_PLESK_ALERT_WEBHOOK_URL to enable",
    false,
  ));
  const whatsappVariables = [
    "MISE_PLESK_WHATSAPP_ACCESS_TOKEN",
    "MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID",
    "MISE_PLESK_WHATSAPP_RECIPIENT",
    "MISE_PLESK_WHATSAPP_TEMPLATE_NAME",
    "MISE_PLESK_WHATSAPP_GRAPH_VERSION",
  ];
  const missingWhatsApp = whatsappVariables.filter((name) => !env[name]?.trim());
  const configuredWhatsApp = missingWhatsApp.length < whatsappVariables.length;
  checks.push(check(
    "whatsapp",
    !configuredWhatsApp || missingWhatsApp.length === 0,
    !configuredWhatsApp
      ? "disabled; set the WhatsApp environment variables to enable"
      : missingWhatsApp.length === 0
        ? "configuration complete"
        : `incomplete; missing ${missingWhatsApp.join(", ")}`,
    false,
  ));
  return { ok: checks.filter((item) => item.blocking).every((item) => item.ok), checks };
}
