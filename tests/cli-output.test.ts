import { describe, expect, it } from "vitest";
import { formatScanOutput } from "../src/cli-output";
import type { AuditResult } from "../src/wp-audit";

const result: AuditResult = {
  generatedAt: "2026-08-18T00:00:00.000Z",
  hosts: [],
  findings: [],
  findingEvents: [],
};

describe("formatScanOutput", () => {
  it("writes only the machine-readable audit result in JSON mode", () => {
    const output = formatScanOutput(result, { json: true, reportPath: "reports/audit.json" });

    expect(JSON.parse(output)).toEqual(result);
    expect(output).not.toContain("Read-only scan complete");
  });

  it("keeps human completion details in the default mode", () => {
    expect(formatScanOutput(result, {
      json: false,
      reportPath: "reports/audit.md",
      alertSent: true,
      whatsappSent: true,
    })).toContain("Sent pending P1 WhatsApp alert(s).");
  });
});
