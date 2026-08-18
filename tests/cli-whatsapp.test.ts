import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("WhatsApp CLI safety gate", () => {
  it("rejects a non-recipient-bound confirmation before provider delivery", async () => {
    await expect(execFileAsync("pnpm", ["run", "mise-plesk-audit", "whatsapp-test", "--confirm"], {
      cwd: process.cwd(),
      env: { ...process.env, MISE_PLESK_WHATSAPP_RECIPIENT: "48123123123" },
      timeout: 5_000,
    })).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("--confirm=<configured recipient>"),
    });
  });
});
