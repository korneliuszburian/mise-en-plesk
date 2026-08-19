import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const script = "scripts/install-systemd.sh";
const credentialScript = "scripts/update-systemd-bw-credential.sh";

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
});

describe("systemd credential updater safety gate", () => {
  it("defaults to a non-mutating plan", async () => {
    const { stdout } = await execFileAsync("bash", [credentialScript]);
    expect(stdout).toContain("DRY RUN");
    expect(stdout).toContain("--apply --confirm=update-bw-session");
  });

  it("rejects override arguments", async () => {
    await expect(execFileAsync("bash", [credentialScript, "--credential-path=/tmp/session"]))
      .rejects.toMatchObject({ code: 78 });
  });
});
