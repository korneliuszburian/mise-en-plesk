import { describe, expect, it } from "vitest";
import { parseCliArguments } from "../src/cli-args";

describe("CLI argument parsing", () => {
  it("keeps flags as flags for commands without a target", () => {
    expect(parseCliArguments(["doctor", "--json"])).toEqual({ command: "doctor", flags: ["--json"] });
    expect(parseCliArguments(["monitor-health", "--json", "--max-age-hours=4"])).toEqual({
      command: "monitor-health",
      flags: ["--json", "--max-age-hours=4"],
    });
  });

  it("parses scan target separately from scan flags", () => {
    expect(parseCliArguments(["scan", "dev-ssh", "--json", "--max-sites=2"])).toEqual({
      command: "scan",
      target: "dev-ssh",
      flags: ["--json", "--max-sites=2"],
    });
  });

  it("parses remote preflight target separately from flags", () => {
    expect(parseCliArguments(["remote-preflight", "dev-ssh", "--json"])).toEqual({
      command: "remote-preflight",
      target: "dev-ssh",
      flags: ["--json"],
    });
  });
});
