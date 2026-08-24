import { attachPublicSiteHealth, type PublicSiteProbeOptions } from "./public-site-health";
import { parsePleskSiteInfo } from "./plesk-site-info";
import type { ReadOnlyCommand } from "./ssh-transport";
import type { WordPressAudit } from "./wp-audit";

export type SiteDiagnosticRunner = (command: ReadOnlyCommand) => Promise<string>;

export interface SiteDiagnosticOptions extends PublicSiteProbeOptions {
  enabled?: boolean;
  useSudo?: boolean;
  pleskCliAvailable?: boolean;
}

function failedPublicProbe(audit: WordPressAudit): boolean {
  const health = audit.publicSiteHealth;
  return Boolean(health
    && (health.tls.status !== "valid"
      || !health.http.reachable
      || (health.http.status ?? 0) >= 500));
}

function shortError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").trim().slice(0, 200) || "unknown error";
}

export async function enrichAuditWithSiteDiagnostics(
  audit: WordPressAudit,
  runner: SiteDiagnosticRunner,
  options: SiteDiagnosticOptions = {},
): Promise<WordPressAudit> {
  let result = await attachPublicSiteHealth(audit, options);
  if (!failedPublicProbe(result) || !result.installation.domain || options.pleskCliAvailable === false) return result;
  try {
    result = {
      ...result,
      pleskSiteInfo: parsePleskSiteInfo(await runner({
        kind: "plesk-site-info",
        domain: result.installation.domain,
        useSudo: options.useSudo,
      })),
    };
  } catch (error: unknown) {
    result = {
      ...result,
      limitations: [...(result.limitations ?? []), `Plesk site diagnostics unavailable: ${shortError(error)}`],
    };
  }
  return result;
}
