import { describe, expect, it } from "vitest";
import { readRemoteCapabilities, renderRemoteCapabilitiesProbe } from "../src/remote-preflight";
import { assertReadOnlyRenderedCommand } from "../src/ssh-transport";

const host = {
  alias: "dev-ssh",
  id: "dev",
  name: "dev ssh",
  host: "dev.example.test",
  port: 6022,
  user: "szymon",
  identitySource: "bitwarden:dev",
};

describe("remote capability preflight", () => {
  it("renders and guards a fixed read-only capability probe", () => {
    const command = renderRemoteCapabilitiesProbe();
    expect(command).toContain("command -v pnpm");
    expect(() => assertReadOnlyRenderedCommand(command)).not.toThrow();
    expect(() => assertReadOnlyRenderedCommand("command python3 -c \"open('/tmp/x','w').write('x')\"")).toThrow("mutation detected");
  });

  it("parses account identity and tool paths without requiring any mutation", async () => {
    const output = [
      "__MISE_REMOTE_UID__", "1001",
      "__MISE_REMOTE_USER__", "szymon",
      "__MISE_REMOTE_KERNEL__", "Linux 6.8.0 x86_64",
      "__MISE_REMOTE_BW__", "",
      "__MISE_REMOTE_NODE__", "/usr/bin/node",
      "__MISE_REMOTE_PNPM__", "/usr/local/bin/pnpm",
      "__MISE_REMOTE_SSHPASS__", "",
      "__MISE_REMOTE_SYSTEMCTL__", "/usr/bin/systemctl",
    ].join("\n");
    await expect(readRemoteCapabilities(host, async () => output)).resolves.toEqual({
      uid: 1001,
      username: "szymon",
      kernel: "Linux 6.8.0 x86_64",
      commands: {
        bw: null,
        node: "/usr/bin/node",
        pnpm: "/usr/local/bin/pnpm",
        sshpass: null,
        systemctl: "/usr/bin/systemctl",
      },
    });
  });
});
