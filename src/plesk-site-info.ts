export interface PleskSiteInfo {
  domain: string;
  status: string;
  suspended: boolean;
  certificate?: string;
  tlsEnabled?: boolean;
  documentRoot?: string;
}

function field(output: string, name: string): string | undefined {
  const expression = new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\s*(.+)$`, "mi");
  return expression.exec(output)?.[1]?.trim();
}

export function parsePleskSiteInfo(output: string): PleskSiteInfo {
  const domain = field(output, "Domain name");
  const status = field(output, "Domain status");
  if (!domain || !status) throw new Error("Plesk site info omitted domain or status");
  const tls = field(output, "SSL/TLS support");
  const documentRoot = /^--WWW-Root--:\s*(.+)$/mi.exec(output)?.[1]?.trim();
  return {
    domain,
    status,
    suspended: /suspended/i.test(status),
    ...(field(output, "Certificate") ? { certificate: field(output, "Certificate") } : {}),
    ...(tls ? { tlsEnabled: /^on$/i.test(tls) } : {}),
    ...(documentRoot ? { documentRoot } : {}),
  };
}
