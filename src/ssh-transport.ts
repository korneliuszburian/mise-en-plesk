import { randomBytes } from "node:crypto";

export type ReadOnlyCommand =
  | { kind: "ssh-handshake" }
  | { kind: "remote-capabilities" }
  | { kind: "plesk-subscriptions"; useSudo?: boolean }
  | { kind: "plesk-wp-toolkit-inventory"; useSudo?: boolean }
  | { kind: "wp-cli-capability"; useSudo?: boolean }
  | { kind: "wordpress-candidates"; useSudo?: boolean; includeAlternateDetection?: boolean; offset?: number; limit?: number }
  | { kind: "plesk-version"; useSudo?: boolean }
  | { kind: "php-version"; useSudo?: boolean }
  | { kind: "disk-usage"; useSudo?: boolean }
  | { kind: "suspicious-uploads"; installationPath: string; useSudo?: boolean }
  | { kind: "wp-audit-batch"; installationPath: string; useSudo?: boolean; runtime?: WpCliRuntime; markerNonce?: string };

export type WpCliRuntime =
  | { kind: "host" }
  | { kind: "plesk-wp-toolkit"; instanceId: number };

export interface WpExecutionContext {
  useSudo?: boolean;
  runtime?: WpCliRuntime;
}

export const READ_ONLY_WP_COMMANDS = [
  "core version",
  "core check-update --format=json",
  "core verify-checksums",
  "plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated",
  "plugin verify-checksums --all --strict",
  "theme list --format=json --fields=name,status,version,update,update_version,auto_update",
] as const;

export type ReadOnlyWpCommand = typeof READ_ONLY_WP_COMMANDS[number];

export const WP_AUDIT_COMMAND_SECTIONS = [
  { section: "core", command: READ_ONLY_WP_COMMANDS[0] },
  { section: "core_update", command: READ_ONLY_WP_COMMANDS[1] },
  { section: "plugins", command: READ_ONLY_WP_COMMANDS[3] },
  { section: "plugin_checksums", command: READ_ONLY_WP_COMMANDS[4] },
  { section: "themes", command: READ_ONLY_WP_COMMANDS[5] },
  { section: "checksums", command: READ_ONLY_WP_COMMANDS[2] },
] as const;

export type WpAuditSection = typeof WP_AUDIT_COMMAND_SECTIONS[number]["section"] | "uploads";

export function isReadOnlyWpCommand(value: string): value is ReadOnlyWpCommand {
  return (READ_ONLY_WP_COMMANDS as readonly string[]).includes(value);
}

function shellQuote(value: string): string {
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error("unsafe installation path: control character");
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function sudoPrefix(useSudo = false, requireCachedCredential = false): string {
  return useSudo ? requireCachedCredential ? "sudo -n -- " : "sudo -S -p '' -- " : "";
}

function boundedRange(offset = 0, limit?: number): { offset: number; limit?: number } {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("wordpress offset must be a non-negative safe integer");
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1)) throw new Error("wordpress limit must be a positive safe integer");
  if (limit !== undefined && offset > Number.MAX_SAFE_INTEGER - limit - 1) {
    throw new Error("wordpress offset and limit exceed safe integer range");
  }
  return { offset, limit };
}

function renderWordPressCandidates(command: Extract<ReadOnlyCommand, { kind: "wordpress-candidates" }>): string {
  const { offset, limit } = boundedRange(command.offset, command.limit);
  const prefix = sudoPrefix(command.useSudo);
  const find = `${prefix}find /var/www/vhosts -xdev -maxdepth 4 -type f ${command.includeAlternateDetection ? "\\( -name wp-config.php -o -path '*/wp-includes/version.php' \\)" : "-name wp-config.php"} -print`;
  if (limit === undefined) return find;
  const end = offset + limit + 1;
  return `${find} | ${String.raw`awk '{ candidate=$0; sub(/\/wp-config\.php$/, "", candidate); sub(/\/wp-includes\/version\.php$/, "", candidate); if (seen[candidate]++) next; position++; if (position > ${offset} && position <= ${end}) { print; if (position >= ${end}) exit } }'`}`;
}

function renderWpAuditBatch(command: Extract<ReadOnlyCommand, { kind: "wp-audit-batch" }>): string {
  const markerNonce = command.markerNonce ?? randomBytes(16).toString("hex");
  if (!/^[a-f0-9]{32}$/.test(markerNonce)) throw new Error("WP audit marker nonce must be 32 lowercase hexadecimal characters");
  const prefix = sudoPrefix(command.useSudo, true);
  const wp = (value: ReadOnlyWpCommand): string => renderWpCliCommand(command.installationPath, value, command.useSudo, command.runtime, true);
  const commands: Array<{ section: WpAuditSection; rendered: string }> = [
    ...WP_AUDIT_COMMAND_SECTIONS.map(({ section, command: wpCommand }) => ({ section, rendered: wp(wpCommand) })),
    { section: "uploads", rendered: `${prefix}find ${shellQuote(`${command.installationPath}/wp-content/uploads`)} -type f -name '*.php' -print` },
  ];
  const batch = commands.map(({ section, rendered }) => [
    `printf '%s\\n' '__MISE_${markerNonce}_${section.toUpperCase()}_BEGIN__'`,
    `${rendered} 2>&1`,
    "status=$?",
    `printf '\\n%s\\n' "__MISE_${markerNonce}_${section.toUpperCase()}_STATUS_\${status}__"`,
    `printf '%s\\n' '__MISE_${markerNonce}_${section.toUpperCase()}_END__'`,
  ].join("; ")).join("; ");
  return command.useSudo ? `sudo -S -p '' -v; ${batch}` : batch;
}

export function renderWpCliCommand(installationPath: string, command: ReadOnlyWpCommand, useSudo = false, runtime: WpCliRuntime = { kind: "host" }, cachedSudo = false): string {
  if (runtime.kind === "plesk-wp-toolkit") {
    if (!Number.isSafeInteger(runtime.instanceId) || runtime.instanceId < 1) {
      throw new Error("WP Toolkit instance ID must be a positive safe integer");
    }
    return `${sudoPrefix(useSudo, cachedSudo)}plesk ext wp-toolkit --wp-cli -instance-id ${runtime.instanceId} -- ${command}`;
  }
  return `${sudoPrefix(useSudo, cachedSudo)}wp ${command} --path=${shellQuote(installationPath)} --allow-root`;
}

export function renderReadOnlyCommand(command: ReadOnlyCommand): string {
  switch (command.kind) {
    case "ssh-handshake": return ":";
    case "remote-capabilities": return [
      "printf '%s\\n' '__MISE_REMOTE_UID__'; id -u 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_USER__'; id -un 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_KERNEL__'; uname -srm 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_BW__'; command -v bw 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_NODE__'; command -v node 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_PNPM__'; command -v pnpm 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_SSHPASS__'; command -v sshpass 2>&1;",
      "printf '%s\\n' '__MISE_REMOTE_SYSTEMCTL__'; command -v systemctl 2>&1; :",
    ].join(" ");
    case "plesk-subscriptions": return `${sudoPrefix(command.useSudo)}plesk bin subscription --list`;
    case "plesk-wp-toolkit-inventory": return `${sudoPrefix(command.useSudo)}plesk ext wp-toolkit --list -plugins -themes -format json`;
    case "wp-cli-capability": return [
      "printf '%s\\n' '__MISE_WP_CLI_BEGIN__'",
      `value=$(${sudoPrefix(command.useSudo)}wp cli version --allow-root 2>&1)`,
      "status=$?",
      "printf '%s\\n' \"$value\"",
      "printf '%s\\n' \"__MISE_WP_CLI_STATUS_${status}__\"",
      "printf '%s\\n' '__MISE_WP_CLI_END__'",
      ":",
    ].join("; ");
    case "wordpress-candidates": return renderWordPressCandidates(command);
    case "plesk-version": return `${sudoPrefix(command.useSudo)}plesk version`;
    case "php-version": return `${sudoPrefix(command.useSudo)}php -v`;
    case "disk-usage": return `${sudoPrefix(command.useSudo)}df -P -k /var/www/vhosts`;
    case "suspicious-uploads": return `${sudoPrefix(command.useSudo)}find ${shellQuote(`${command.installationPath}/wp-content/uploads`)} -type f -name '*.php' -print`;
    case "wp-audit-batch": return renderWpAuditBatch(command);
  }
}

const forbiddenRemoteMutation = [
  /\b(?:rm|rmdir|mv|cp|chmod|chown|truncate|mkfs|reboot|shutdown|poweroff)\b/i,
  /\bwp\s+(?!(?:cli\s+version|core\s+(?:version|check-update|verify-checksums)|plugin\s+(?:list|verify-checksums)|theme\s+list)\b)/i,
  /\bwp\s+.*(?:--exec|--require|--eval)(?:=|\s)/i,
  /\bplesk\s+(?!(?:bin\s+subscription\s+--list|ext\s+wp-toolkit\s+--list\s+-plugins\s+-themes\s+-format\s+json|version)\b)/i,
  /\bplesk\s+bin\s+subscription\s+--list\s+\S|\bplesk\s+version\s+\S|\bplesk\s+ext\s+wp-toolkit\s+--list\s+-plugins\s+-themes\s+-format\s+json\s+\S/i,
  /(?:^|[;&|]\s*|\$\(\s*)php\s+-[rce]\b/i,
  /(?:^|[;&|]\s*|\$\(\s*)php\s+(?!-v(?:\s|$))/i,
  /(?:^|[;&|]\s*|\$\(\s*)php\s+-v\s+\S/i,
  /\b(?:sh|bash|dash|zsh|ksh)\s+-c\b/i,
  /\bfind\b.*\s-(?:exec|execdir|delete|fls|fprint|fprintf|ok|okdir)\b/i,
  />>\s*\S|>\s*(?:[~/.]|["'])|<\s*(?:[~/.]|["'])|<\(/i,
];
const allowedRemoteExecutables = new Set(["printf", "wp", "plesk", "php", "df", "find", "awk", "id", "uname", ":"]);
const allowedAwkPrefix = "awk '{ candidate=$0; sub(/\\/wp-config\\.php$/, \"\", candidate); sub(/\\/wp-includes\\/version\\.php$/, \"\", candidate); if (seen[candidate]++) next; position++; if (position > ";
const allowedAwkRemainder = /^\d+ && position <= \d+\) \{ print; if \(position >= \d+\) exit \} \}'$/;

export function assertReadOnlyRenderedCommand(command: string): void {
  let invalidToolkitBridge = false;
  const normalizedCommand = command
    .replace(/^sudo\s+-S\s+-p\s+(?:''|"")\s+-v;\s*/i, "")
    .replace(/sudo\s+-S\s+-p\s+(?:''|"")\s+--\s+/gi, "")
    .replace(/sudo\s+-n\s+--\s+/gi, "")
    .replace(/plesk\s+ext\s+wp-toolkit\s+--wp-cli\s+-instance-id\s+\d+\s+--\s+([^;\n]+?)(?=\s+2>&1|;|$)/gi, (_match, subcommand: string) => {
      const candidate = subcommand.trim();
      if (!isReadOnlyWpCommand(candidate)) invalidToolkitBridge = true;
      return `wp ${candidate}`;
    });
  const commandForExecutableScan = normalizedCommand
    .replace(/\d*>&\d+/g, "")
    .replace(/'[^']*'/g, "''")
    .replace(/\bcommand\s+-v\s+(?:bw|node|pnpm|sshpass|systemctl)\b/gi, "");
  const shellOnlyCommand = normalizedCommand.replace(/'[^']*'/g, "''");
  const executableNames = [...commandForExecutableScan.matchAll(/(?:^|[;&|]\s*|\$\(\s*)(?![A-Za-z_][A-Za-z0-9_]*=)([A-Za-z0-9_./-]+)/gm)].map((match) => match[1]);
  const awkIndex = normalizedCommand.indexOf("awk ");
  const containsAwk = awkIndex >= 0;
  const allowedAwk = containsAwk
    && normalizedCommand.slice(awkIndex).startsWith(allowedAwkPrefix)
    && allowedAwkRemainder.test(normalizedCommand.slice(awkIndex + allowedAwkPrefix.length));
  if (
    invalidToolkitBridge
    || /\bsudo\b/i.test(normalizedCommand)
    || executableNames.some((name) => !allowedRemoteExecutables.has(name))
    || /`/.test(normalizedCommand)
    || (containsAwk && !allowedAwk)
    || />>|>(?!&1)|</i.test(shellOnlyCommand)
    || forbiddenRemoteMutation.some((pattern) => pattern.test(normalizedCommand))
  ) {
    throw new Error("Refusing remote command: mutation detected in read-only SSH policy.");
  }
}
