import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const script = "scripts/install-systemd.sh";
const runtimeBootstrapScript = "scripts/bootstrap-systemd-bw-runtime.sh";
const sshTrustScript = "scripts/install-systemd-ssh-trust.sh";
const prepareSshTrustScript = "scripts/prepare-verified-ssh-trust.sh";
const whatsappBootstrapScript = "scripts/bootstrap-systemd-whatsapp-runtime.sh";
const whatsappTestScript = "scripts/run-systemd-whatsapp-test.sh";

async function runSandboxedWhatsAppBootstrap(failureMode: "daemon" | "term") {
  const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-whatsapp-bootstrap-"));
  const runtimeRoot = join(root, "run", "mise-en-plesk");
  const systemdRoot = join(root, "etc", "systemd", "system");
  const dropinDirectory = join(systemdRoot, "mise-en-plesk.service.d");
  const fakeBin = join(root, "bin");
  await mkdir(runtimeRoot, { recursive: true });
  await mkdir(dropinDirectory, { recursive: true });
  await mkdir(fakeBin, { recursive: true });
  await writeFile(join(systemdRoot, "mise-en-plesk.service"), "[Service]\n");
  await writeFile(join(runtimeRoot, "scan.lock"), "");
  await writeFile(join(runtimeRoot, "WHATSAPP_ACCESS_TOKEN"), "old-token");
  await writeFile(join(dropinDirectory, "whatsapp.conf"), "old-dropin\n");
  await writeFile(join(root, "timer-state"), "active\n");

  const source = (await readFile(whatsappBootstrapScript, "utf8"))
    .replaceAll("/run/mise-en-plesk", runtimeRoot)
    .replaceAll("/etc/systemd/system", systemdRoot)
    .replaceAll("-o root -g root ", "");
  const sandboxScript = join(root, "bootstrap.sh");
  await writeFile(sandboxScript, source, { mode: 0o700 });
  await writeFile(join(root, "payload.json"), JSON.stringify({
    accessToken: "new-runtime-token-value",
    phoneNumberId: "123456789",
    recipient: "48123123123",
    templateName: "plesk_security_alert",
    templateLanguage: "pl_PL",
    graphVersion: "v25.0",
  }));

  await writeFile(join(fakeBin, "id"), "#!/usr/bin/env bash\n[[ \"${1:-}\" == '-u' ]] && { echo 0; exit 0; }\nexec /usr/bin/id \"$@\"\n", { mode: 0o700 });
  await writeFile(join(fakeBin, "flock"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o700 });
  await writeFile(join(fakeBin, "systemctl"), `#!/usr/bin/env bash
set -euo pipefail
command="\${1:-}"
case "$command" in
  is-active)
    [[ "\${3:-\${2:-}}" == "mise-en-plesk.timer" ]] && grep -qx active "$TEST_TIMER_STATE" && exit 0
    exit 1
    ;;
  stop) printf 'inactive\n' > "$TEST_TIMER_STATE" ;;
  start) printf 'active\n' > "$TEST_TIMER_STATE" ;;
  daemon-reload)
    if [[ "$TEST_FAILURE_MODE" == daemon && ! -e "$TEST_FAILURE_MARKER" ]]; then
      : > "$TEST_FAILURE_MARKER"
      exit 1
    fi
    ;;
esac
`, { mode: 0o700 });
  await writeFile(join(fakeBin, "install"), `#!/usr/bin/env bash
set -euo pipefail
target="\${@: -1}"
if [[ "$TEST_FAILURE_MODE" == term && "$target" == */whatsapp.conf && ! -e "$TEST_FAILURE_MARKER" ]]; then
  : > "$TEST_FAILURE_MARKER"
  kill -TERM "$PPID"
  exit 0
fi
exec /usr/bin/install "$@"
`, { mode: 0o700 });

  const execution = execFileAsync("bash", ["-c", 'exec bash "$1" --apply --confirm=bootstrap-whatsapp-runtime < "$2"', "bash", sandboxScript, join(root, "payload.json")], {
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      TEST_TIMER_STATE: join(root, "timer-state"),
      TEST_FAILURE_MODE: failureMode,
      TEST_FAILURE_MARKER: join(root, "failure-marker"),
    },
  });
  await expect(execution).rejects.toBeDefined();
  return {
    token: await readFile(join(runtimeRoot, "WHATSAPP_ACCESS_TOKEN"), "utf8"),
    dropin: await readFile(join(dropinDirectory, "whatsapp.conf"), "utf8"),
    timer: await readFile(join(root, "timer-state"), "utf8"),
  };
}

describe("systemd installer safety gate", () => {
  it("defaults to a fixed, non-mutating plan", async () => {
    const { stdout } = await execFileAsync("bash", [script]);
    expect(stdout).toContain("DRY RUN");
    expect(stdout).toContain("/opt/mise-en-plesk");
    expect(stdout).toContain("/var/lib/mise-en-plesk");
    expect(stdout).toContain("--apply --confirm=install-systemd");
  });

  it("refuses apply without exact confirmation before preflight", async () => {
    await expect(execFileAsync("bash", [script, "--apply"])).rejects.toMatchObject({
      code: 78,
      stderr: expect.stringContaining("refusing mutation"),
    });
  });

  it.each([
    "--checkout=/tmp/repo",
    "--unit-dir=/tmp/units",
    "--state-dir=/tmp/state",
    "--credential-path=/tmp/credential",
    "--credential-mode=runtime",
  ])("rejects path or credential override %s", async (argument) => {
    await expect(execFileAsync("bash", [script, argument])).rejects.toMatchObject({ code: 78 });
  });

  it("creates the service HOME before probing Bitwarden as the service account", async () => {
    const source = await readFile(script, "utf8");
    expect(source.indexOf('install -d -o mise-en-plesk -g mise-en-plesk -m 0750 "$state_directory"'))
      .toBeLessThan(source.indexOf('bw --version'));
  });

  it("probes tsx without asking pnpm to write a temporary shim in the checkout", async () => {
    const source = await readFile(script, "utf8");
    expect(source).toContain('"$checkout/node_modules/.bin/tsx" --version');
    expect(source).not.toContain('pnpm --dir "$checkout" exec tsx');
  });

  it("quarantines failed state instead of deleting it", async () => {
    const source = await readFile(script, "utf8");
    expect(source).toContain('mv --no-clobber "$state_directory" "$quarantine_path"');
    expect(source).not.toContain('rmdir "$state_directory/reports"');
  });

  it("requires the compiled CLI and keeps pnpm out of the systemd runtime", async () => {
    const installer = await readFile(script, "utf8");
    const unit = await readFile("deploy/systemd/mise-en-plesk.service.example", "utf8");
    expect(installer).toContain('dist/bin/mise-plesk-audit.js');
    expect(unit).toContain("Environment=MISE_PLESK_RUNNER_BIN=/usr/local/bin/node");
    expect(unit).not.toContain("Environment=MISE_PLESK_RUNNER_BIN=/usr/local/bin/pnpm");
  });
});

describe("systemd runtime bootstrap safety gates", () => {
  it.each([
    [runtimeBootstrapScript, "bootstrap-bw-runtime"],
    [sshTrustScript, "install-ssh-trust"],
    [prepareSshTrustScript, "prepare-ssh-trust"],
    [whatsappBootstrapScript, "bootstrap-whatsapp-runtime"],
  ])("keeps %s non-mutating by default", async (bootstrapScript, confirmation) => {
    const { stdout } = await execFileAsync("bash", [bootstrapScript]);
    expect(stdout).toContain("DRY RUN");
    expect(stdout).toContain(`--confirm=${confirmation}`);
  });

  it.each([runtimeBootstrapScript, sshTrustScript, whatsappBootstrapScript])(
    "rejects apply without exact confirmation for %s",
    async (bootstrapScript) => {
      await expect(execFileAsync("bash", [bootstrapScript, "--apply"])).rejects.toMatchObject({ code: 78 });
    },
  );

  it("keeps the WhatsApp token on stdin and in the ephemeral runtime directory", async () => {
    const source = await readFile(whatsappBootstrapScript, "utf8");
    expect(source).toContain('readonly credential_path="/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN"');
    expect(source).toContain('JSON.parse(fs.readFileSync(0, "utf8"))');
    expect(source).toContain("LoadCredential=WHATSAPP_ACCESS_TOKEN:/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN");
    expect(source).not.toContain("echo $MISE_PLESK_WHATSAPP_ACCESS_TOKEN");
    expect(source).toContain("rollback_whatsapp_runtime");
    expect(source).toContain('flock -n 9');
    expect(source).toContain('timer_was_active');
    expect(source).toContain("trap 'exit 130' INT");
    expect(source).toContain("trap 'exit 143' TERM");
    expect(source).toContain("transaction_complete=1");
  });

  it("verifies an installed WhatsApp drop-in without reading or printing its token", async () => {
    const verifier = await readFile("scripts/verify-systemd-install.sh", "utf8");
    expect(verifier).toContain('whatsapp_dropin="/etc/systemd/system/mise-en-plesk.service.d/whatsapp.conf"');
    expect(verifier).toContain('whatsapp_credential="/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN"');
    expect(verifier).toContain("LoadCredential=WHATSAPP_ACCESS_TOKEN:/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN");
    expect(verifier).toContain("--require-whatsapp");
    expect(verifier).toContain("production WhatsApp routing is required but not configured");
    expect(verifier).not.toContain("cat \"$whatsapp_credential\"");
  });

  it("runs the guarded WhatsApp test in a transient hardened unit with the runtime credential", async () => {
    const source = await readFile(whatsappTestScript, "utf8");
    expect(source).toContain("--confirm=<exact configured recipient>");
    expect(source).toContain("LoadCredential=WHATSAPP_ACCESS_TOKEN:$credential_path");
    expect(source).toContain('$CREDENTIALS_DIRECTORY/WHATSAPP_ACCESS_TOKEN');
    expect(source).toContain("ProtectSystem=strict");
    expect(source).not.toContain("cat \"$credential_path\"");
  });

  it.each(["daemon", "term"] as const)("rolls back credential, drop-in, and timer after %s interruption", async (failureMode) => {
    await expect(runSandboxedWhatsAppBootstrap(failureMode)).resolves.toEqual({
      token: "old-token",
      dropin: "old-dropin\n",
      timer: "active\n",
    });
  });

  it("keeps Bitwarden authentication state ephemeral and out of argv", async () => {
    const source = await readFile(runtimeBootstrapScript, "utf8");
    expect(source).toContain('readonly runtime_root="/run/mise-en-plesk"');
    expect(source).toContain('JSON.parse(fs.readFileSync(0, "utf8"))');
    expect(source).not.toContain("echo $BW_SESSION");
    expect(source).toContain("systemctl stop mise-en-plesk.timer");
    expect(source).toContain("scanner service is active");
    expect(source).toContain("rollback_pair");
  });

  it("pins systemd to the ephemeral Bitwarden appdata directory", async () => {
    const unit = await readFile("deploy/systemd/mise-en-plesk.service.example", "utf8");
    expect(unit).toContain("Environment=BITWARDENCLI_APPDATA_DIR=/run/mise-en-plesk/bw-data");
    expect(unit).toContain("ReadWritePaths=/run/mise-en-plesk/bw-data");
    expect(unit).toContain("Environment=MISE_PLESK_SCHEDULE_LOCK_FILE=/run/mise-en-plesk/scan.lock");
    expect(unit).toContain("ReadWritePaths=/run/mise-en-plesk/scan.lock");
  });

  it("installs verified SSH trust before the service unit", async () => {
    const installer = await readFile(script, "utf8");
    expect(installer.indexOf('install-systemd-ssh-trust.sh'))
      .toBeLessThan(installer.indexOf('install -o root -g root -m 0644 "$temporary_unit"'));
    expect(installer).toContain('verified-known-hosts is missing or a symlink');
  });
});
