import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("Hermes CLI safety gate", () => {
  it("refuses a test send without exact target confirmation", async () => {
    await expect(execFileAsync("pnpm", ["run", "mise-plesk-audit", "hermes-test", "--confirm=wrong"], {
      env: { ...process.env, MISE_PLESK_HERMES_WHATSAPP_TARGET: "whatsapp:123@s.whatsapp.net" },
    })).rejects.toMatchObject({ stderr: expect.stringContaining("exact configured target") });
  });
});
