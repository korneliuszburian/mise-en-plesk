import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const script = "scripts/install-systemd.sh";
const runtimeBootstrapScript = "scripts/bootstrap-systemd-bw-runtime.sh";
const sshTrustScript = "scripts/install-systemd-ssh-trust.sh";
const prepareSshTrustScript = "scripts/prepare-verified-ssh-trust.sh";

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
  ])("keeps %s non-mutating by default", async (bootstrapScript, confirmation) => {
    const { stdout } = await execFileAsync("bash", [bootstrapScript]);
    expect(stdout).toContain("DRY RUN");
    expect(stdout).toContain(`--confirm=${confirmation}`);
  });

  it.each([runtimeBootstrapScript, sshTrustScript])(
    "rejects apply without exact confirmation for %s",
    async (bootstrapScript) => {
      await expect(execFileAsync("bash", [bootstrapScript, "--apply"])).rejects.toMatchObject({ code: 78 });
    },
  );

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
