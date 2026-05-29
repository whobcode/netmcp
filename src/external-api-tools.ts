// External API Tools for MCP Server
// Integrates security research, OSINT, and vulnerability intelligence APIs.
//
// Each tool follows the project's shared conventions (see tool-helpers.ts):
//   - registered via the modern registerTool(name, config, handler) API
//   - title + annotations (all read-only, open-world)
//   - a `response_format` param ('markdown' default | 'json')
//   - structuredContent for machine consumption
//   - CHARACTER_LIMIT truncation and status-mapped error messages

import { z } from "zod";
import type { ToolHost } from "./tool-registry";
import {
  HttpError,
  READONLY_OPENWORLD,
  ResponseFormat,
  describeError,
  formatToolResult,
  responseFormatField,
  toolError,
} from "./tool-helpers";

// ─── HTTP helper ───────────────────────────────────────────────────────────
// Retries transient (5xx / network) failures, but fails fast on 4xx and
// throws an HttpError carrying the status so describeError can map it.
async function fetchWithRetry(url: string, options: RequestInit = {}, maxRetries = 3): Promise<any> {
  let lastError: unknown;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        headers: { "User-Agent": "netmcp/1.0", ...options.headers },
      });

      if (!response.ok) {
        throw new HttpError(response.status, `HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;
      // Don't retry client errors (4xx) — they won't change on retry.
      if (error instanceof HttpError && error.status < 500) throw error;
      if (attempt < maxRetries - 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

// ─── Structured parsers + markdown renderers ────────────────────────────────
// Structured object is the single source of truth; markdown is rendered from it.

function parseNVD(data: any) {
  const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities.slice(0, 10) : [];
  return {
    total: data?.totalResults ?? vulns.length,
    count: vulns.length,
    cves: vulns.map((item: any) => {
      const cve = item.cve ?? {};
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
      const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
      return {
        id: cve.id ?? "UNKNOWN",
        score: cvssV3?.baseScore ?? cvssV2?.baseScore ?? null,
        severity: cvssV3?.baseSeverity ?? cvssV2?.baseSeverity ?? "N/A",
        published: cve.published ? new Date(cve.published).toISOString().slice(0, 10) : "N/A",
        description: cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "No description",
      };
    }),
  };
}

function renderNVD(s: ReturnType<typeof parseNVD>): string {
  if (!s.count) return "### NVD CVE Lookup\n\nNo CVEs found matching your search.";
  const body = s.cves
    .map(
      (c: any, i: number) =>
        `${i + 1}. **${c.id}** (Score: ${c.score ?? "N/A"}, Severity: ${c.severity})\n   Published: ${c.published}\n   ${c.description.slice(0, 200)}${c.description.length > 200 ? "..." : ""}`,
    )
    .join("\n\n");
  return `### NVD CVE Lookup Results\n\nFound ${s.total} CVEs (showing ${s.count}):\n\n${body}`;
}

function parseOSV(data: any, params: { packageName: string; version?: string }) {
  const vulns = Array.isArray(data?.vulns) ? data.vulns : [];
  return {
    package: params.packageName,
    version: params.version ?? null,
    count: vulns.length,
    vulns: vulns.map((v: any) => ({
      id: v.id,
      severity: v.database_specific?.severity ?? "UNKNOWN",
      aliases: v.aliases ?? [],
      summary: v.summary ?? "No summary available",
    })),
  };
}

function renderOSV(s: ReturnType<typeof parseOSV>): string {
  if (!s.count) {
    return `### OSV Vulnerability Scan\n\n✓ No vulnerabilities found for ${s.package}${s.version ? ` v${s.version}` : ""}`;
  }
  const body = s.vulns
    .map(
      (v: any, i: number) =>
        `${i + 1}. **${v.id}** (Severity: ${v.severity})\n   Aliases: ${v.aliases.join(", ") || "None"}\n   ${v.summary}`,
    )
    .join("\n\n");
  return `### OSV Vulnerability Scan Results\n\nFound ${s.count} vulnerabilities for ${s.package}:\n\n${body}`;
}

function parseGitHub(data: any) {
  const items = Array.isArray(data?.items) ? data.items : [];
  return {
    total: data?.total_count ?? items.length,
    count: items.length,
    items: items.map((item: any) => ({
      repo: item.repository?.full_name ?? "unknown",
      path: item.path ?? "",
      url: item.html_url ?? "",
    })),
  };
}

function renderGitHub(s: ReturnType<typeof parseGitHub>): string {
  if (!s.count) return "### GitHub Exploit Search\n\nNo code found matching your search.";
  const body = s.items
    .map((it: any, i: number) => `${i + 1}. **${it.repo}** - \`${it.path}\`\n   URL: ${it.url}`)
    .join("\n\n");
  return `### GitHub Exploit Search Results\n\nFound ${s.total} results (showing ${s.count}):\n\n${body}`;
}

function parseGitLab(data: any) {
  const arr = Array.isArray(data) ? data : [];
  return {
    count: arr.length,
    results: arr.map((item: any) =>
      item.path
        ? { type: "blob", project_id: item.project_id, path: item.path, snippet: (item.data ?? "").slice(0, 100) }
        : { type: "project", name: item.name, description: item.description ?? "", url: item.web_url ?? "" },
    ),
  };
}

function renderGitLab(s: ReturnType<typeof parseGitLab>): string {
  if (!s.count) return "### GitLab Code Search\n\nNo results found matching your search.";
  const body = s.results
    .map((r: any, i: number) =>
      r.type === "blob"
        ? `${i + 1}. **${r.project_id}** - \`${r.path}\`\n   ${r.snippet}...`
        : `${i + 1}. **${r.name}**\n   ${r.description || "No description"}\n   URL: ${r.url}`,
    )
    .join("\n\n");
  return `### GitLab Code Search Results\n\nFound ${s.count} results:\n\n${body}`;
}

function parseShodan(data: any, limit: number) {
  const matches = Array.isArray(data?.matches) ? data.matches.slice(0, limit) : [];
  return {
    total: data?.total ?? matches.length,
    count: matches.length,
    matches: matches.map((m: any) => ({
      ip: m.ip_str,
      port: m.port,
      product: m.product ?? "Unknown",
      org: m.org ?? "Unknown",
      location: `${m.location?.city ?? "Unknown"}, ${m.location?.country_name ?? "Unknown"}`,
      vulns: m.vulns ? Object.keys(m.vulns) : [],
    })),
  };
}

function renderShodan(s: ReturnType<typeof parseShodan>): string {
  if (!s.count) return "### Shodan Search\n\nNo devices found matching your search.";
  const body = s.matches
    .map(
      (m: any, i: number) =>
        `${i + 1}. **${m.ip}:${m.port}** (${m.product})\n   Org: ${m.org}\n   Location: ${m.location}\n   Vulnerabilities: ${m.vulns.join(", ") || "None detected"}`,
    )
    .join("\n\n");
  return `### Shodan Search Results\n\nFound ${s.total} devices (showing ${s.count}):\n\n${body}`;
}

function parseCensys(data: any) {
  const hits = Array.isArray(data?.result?.hits) ? data.result.hits : [];
  return {
    total: data?.result?.total ?? hits.length,
    count: hits.length,
    hosts: hits.map((h: any) => ({
      ip: h.ip,
      name: h.name ?? "No hostname",
      asn: h.autonomous_system?.asn ?? "Unknown",
      location: `${h.location?.city ?? "Unknown"}, ${h.location?.country ?? "Unknown"}`,
      services: (h.services ?? []).map((sv: any) => `${sv.port}/${sv.service_name}`),
    })),
  };
}

function renderCensys(s: ReturnType<typeof parseCensys>): string {
  if (!s.count) return "### Censys Host Search\n\nNo hosts found matching your search.";
  const body = s.hosts
    .map(
      (h: any, i: number) =>
        `${i + 1}. **${h.ip}** (${h.name})\n   ASN: ${h.asn}\n   Location: ${h.location}\n   Services: ${h.services.join(", ") || "No services"}`,
    )
    .join("\n\n");
  return `### Censys Host Search Results\n\nFound ${s.total} hosts (showing ${s.count}):\n\n${body}`;
}

function parseSecurityTrails(data: any, params: { domain: string; type: string }) {
  const records = Array.isArray(data?.records) ? data.records.slice(0, 10) : [];
  return {
    domain: params.domain,
    type: params.type.toUpperCase(),
    count: records.length,
    records: records.map((r: any) => ({
      values: r.values ?? [],
      first_seen: r.first_seen ?? "Unknown",
      last_seen: r.last_seen ?? "Unknown",
    })),
  };
}

function renderSecurityTrails(s: ReturnType<typeof parseSecurityTrails>): string {
  if (!s.count) return `### SecurityTrails DNS History\n\nNo ${s.type} record history found for ${s.domain}`;
  const body = s.records
    .map(
      (r: any, i: number) =>
        `${i + 1}. **${(r.values ?? []).join(", ") || "N/A"}**\n   First seen: ${r.first_seen}\n   Last seen: ${r.last_seen}`,
    )
    .join("\n\n");
  return `### SecurityTrails DNS History\n\nDNS ${s.type} history for **${s.domain}** (${s.count} records):\n\n${body}`;
}

function parseIPWhois(data: any) {
  return {
    ip: data?.ip ?? null,
    type: data?.type ?? "N/A",
    country: data?.country ?? null,
    country_code: data?.country_code ?? null,
    region: data?.region ?? null,
    city: data?.city ?? null,
    isp: data?.isp ?? "Unknown",
    asn: data?.asn ?? "Unknown",
    org: data?.org ?? "Unknown",
    timezone: data?.timezone ?? "Unknown",
    latitude: data?.latitude ?? null,
    longitude: data?.longitude ?? null,
  };
}

function renderIPWhois(s: ReturnType<typeof parseIPWhois>): string {
  return `### IP WHOIS Lookup

**IP:** ${s.ip}
**Type:** ${s.type}
**Country:** ${s.country} (${s.country_code})
**Region:** ${s.region}
**City:** ${s.city}
**ISP:** ${s.isp}
**ASN:** ${s.asn}
**Organization:** ${s.org}
**Timezone:** ${s.timezone}
**Latitude:** ${s.latitude}
**Longitude:** ${s.longitude}`;
}

function parseWayback(result: any) {
  const closest = result?.archived_snapshots?.closest ?? result?.closest ?? null;
  const rawSnapshots = Array.isArray(result?.snapshots) ? result.snapshots : [];
  // CDX returns a header row first; drop it for the snapshot list.
  const rows = rawSnapshots.slice(1, 11).map((snap: any[]) => {
    const [, timestamp, , mimetype, statuscode] = snap;
    return { timestamp, status: statuscode, mimetype };
  });
  return {
    available: Boolean(closest),
    closest: closest ? { timestamp: closest.timestamp, status: closest.status, url: closest.url } : null,
    snapshot_count: Math.max(0, rawSnapshots.length - 1),
    snapshots: rows,
  };
}

function renderWayback(s: ReturnType<typeof parseWayback>): string {
  if (!s.available) return "### Wayback Machine\n\nNo archived snapshots found for this URL.";
  let out = `### Wayback Machine Results\n\n**Latest Snapshot:**\n- Timestamp: ${s.closest?.timestamp}\n- Status: ${s.closest?.status}\n- URL: ${s.closest?.url}\n`;
  if (s.snapshot_count > 0) {
    out += `\n**Available Snapshots:** ${s.snapshot_count} found\n\n`;
    out += s.snapshots
      .map((snap: any, i: number) => `${i + 1}. ${snap.timestamp} - Status ${snap.status} - ${snap.mimetype}`)
      .join("\n");
  }
  return out;
}

// ─── Tool registrations ──────────────────────────────────────────────────────
export function registerExternalApiTools(server: ToolHost, env: Env) {
  // 1. NVD CVE Lookup
  server.registerTool(
    "nvd_cve_lookup",
    {
      title: "NVD CVE Lookup",
      description:
        "Search the NIST National Vulnerability Database for CVE details, CVSS scores, and remediation info. Read-only; does not modify anything. Provide either cveId or keyword.",
      inputSchema: {
        cveId: z.string().optional().describe("Specific CVE ID to look up (e.g., CVE-2024-1234)"),
        keyword: z.string().optional().describe("Keyword search across CVE descriptions"),
        resultsPerPage: z.number().int().min(1).max(100).optional().default(10).describe("Results per page (1-100)"),
        startIndex: z.number().int().min(0).optional().default(0).describe("Starting index for pagination"),
        ...responseFormatField,
      },
      annotations: { title: "NVD CVE Lookup", ...READONLY_OPENWORLD },
    },
    async ({ cveId, keyword, resultsPerPage, startIndex, response_format }) => {
      if (!cveId && !keyword) return toolError("Error: provide either 'cveId' or 'keyword'.");

      const params = new URLSearchParams();
      if (cveId) params.set("cveId", cveId);
      if (keyword) params.set("keywordSearch", keyword);
      params.set("resultsPerPage", String(resultsPerPage ?? 10));
      params.set("startIndex", String(startIndex ?? 0));

      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (env.NVD_API_KEY) headers["apiKey"] = env.NVD_API_KEY;

      try {
        const data = await fetchWithRetry(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`, { headers });
        const structured = parseNVD(data);
        return formatToolResult(response_format as ResponseFormat, { markdown: renderNVD(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying NVD", "Without an API key, limits are 5 requests / 30s."));
      }
    },
  );

  // 2. OSV Vulnerability Scan
  server.registerTool(
    "osv_vulnerability_scan",
    {
      title: "OSV Vulnerability Scan",
      description:
        "Scan an open-source package (or git commit) for known vulnerabilities via the OSV database. No API key required. Read-only.",
      inputSchema: {
        packageName: z.string().describe("Package name to check"),
        version: z.string().optional().describe("Specific version (e.g., 1.2.3)"),
        ecosystem: z
          .enum(["npm", "PyPI", "Go", "Maven", "Cargo", "RubyGems", "NuGet", "Packagist", "Debian", "Alpine"])
          .describe("Package ecosystem"),
        commit: z.string().optional().describe("Git commit hash (alternative to version)"),
        ...responseFormatField,
      },
      annotations: { title: "OSV Vulnerability Scan", ...READONLY_OPENWORLD },
    },
    async ({ packageName, version, ecosystem, commit, response_format }) => {
      const body = commit ? { commit } : { version, package: { name: packageName, ecosystem } };
      try {
        const data = await fetchWithRetry("https://api.osv.dev/v1/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const structured = parseOSV(data, { packageName, version });
        return formatToolResult(response_format as ResponseFormat, { markdown: renderOSV(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying OSV"));
      }
    },
  );

  // 3. GitHub Exploit Search
  server.registerTool(
    "github_exploit_search",
    {
      title: "GitHub Exploit Search",
      description:
        "Search GitHub code for exploits, proof-of-concepts, and security tools. Requires GITHUB_TOKEN. Read-only.",
      inputSchema: {
        query: z.string().describe("Search query (CVE ID, exploit name, or keywords)"),
        language: z.string().optional().describe("Filter by programming language (e.g., python)"),
        limit: z.number().int().min(1).max(100).optional().default(10).describe("Maximum results (1-100)"),
        ...responseFormatField,
      },
      annotations: { title: "GitHub Exploit Search", ...READONLY_OPENWORLD },
    },
    async ({ query, language, limit, response_format }) => {
      if (!env.GITHUB_TOKEN) return toolError("Error: GITHUB_TOKEN not configured. This tool requires a GitHub API token.");
      const q = language ? `${query} language:${language}` : query;
      try {
        const data = await fetchWithRetry(
          `https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=${limit ?? 10}`,
          {
            headers: {
              Authorization: `Bearer ${env.GITHUB_TOKEN}`,
              Accept: "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28",
            },
          },
        );
        const structured = parseGitHub(data);
        return formatToolResult(response_format as ResponseFormat, { markdown: renderGitHub(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying GitHub", "Authenticated limit is 5,000 requests/hour."));
      }
    },
  );

  // 4. GitLab Code Search
  server.registerTool(
    "gitlab_code_search",
    {
      title: "GitLab Code Search",
      description:
        "Search GitLab for code in public projects. Works without auth; GITLAB_TOKEN raises limits. Read-only.",
      inputSchema: {
        query: z.string().describe("Search query for code content"),
        scope: z.enum(["blobs", "projects"]).optional().default("blobs").describe("Search scope"),
        limit: z.number().int().min(1).max(100).optional().default(10).describe("Maximum results (1-100)"),
        ...responseFormatField,
      },
      annotations: { title: "GitLab Code Search", ...READONLY_OPENWORLD },
    },
    async ({ query, scope, limit, response_format }) => {
      const params = new URLSearchParams({ scope: scope ?? "blobs", search: query, per_page: String(limit ?? 10) });
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (env.GITLAB_TOKEN) headers["PRIVATE-TOKEN"] = env.GITLAB_TOKEN;
      try {
        const data = await fetchWithRetry(`https://gitlab.com/api/v4/search?${params}`, { headers });
        const structured = parseGitLab(data);
        return formatToolResult(response_format as ResponseFormat, { markdown: renderGitLab(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying GitLab", "Limited to public projects without a token."));
      }
    },
  );

  // 5. Shodan Device Search
  server.registerTool(
    "shodan_device_search",
    {
      title: "Shodan Device Search",
      description:
        "Search Shodan for Internet-connected devices, exposed services, and vulnerabilities. Requires SHODAN_API_KEY. Read-only.",
      inputSchema: {
        query: z.string().describe("Shodan query (IP, hostname, service, or filters)"),
        facets: z.string().optional().describe("Comma-separated facets (e.g., country,port,org)"),
        limit: z.number().int().min(1).max(100).optional().default(10).describe("Maximum results (1-100)"),
        ...responseFormatField,
      },
      annotations: { title: "Shodan Device Search", ...READONLY_OPENWORLD },
    },
    async ({ query, facets, limit, response_format }) => {
      if (!env.SHODAN_API_KEY)
        return toolError("Error: SHODAN_API_KEY not configured. Get one at https://account.shodan.io (100 free queries/month).");
      const params = new URLSearchParams({ key: env.SHODAN_API_KEY, query });
      if (facets) params.set("facets", facets);
      try {
        const data = await fetchWithRetry(`https://api.shodan.io/shodan/host/search?${params}`, {});
        const structured = parseShodan(data, limit ?? 10);
        return formatToolResult(response_format as ResponseFormat, { markdown: renderShodan(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying Shodan", "Free tier is 100 queries/month."));
      }
    },
  );

  // 6. Censys Host Search
  server.registerTool(
    "censys_host_search",
    {
      title: "Censys Host Search",
      description:
        "Search Censys for host information, certificates, and exposed services. Requires CENSYS_API_ID + CENSYS_API_SECRET. Read-only.",
      inputSchema: {
        query: z.string().describe("Censys query (IP, domain, or search syntax)"),
        perPage: z.number().int().min(1).max(100).optional().default(10).describe("Results per page (1-100)"),
        ...responseFormatField,
      },
      annotations: { title: "Censys Host Search", ...READONLY_OPENWORLD },
    },
    async ({ query, perPage, response_format }) => {
      if (!env.CENSYS_API_ID || !env.CENSYS_API_SECRET)
        return toolError("Error: CENSYS_API_ID and CENSYS_API_SECRET not configured. Register at https://search.censys.io/register");
      const auth = btoa(`${env.CENSYS_API_ID}:${env.CENSYS_API_SECRET}`);
      try {
        const data = await fetchWithRetry("https://search.censys.io/api/v2/hosts/search", {
          method: "POST",
          headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
          body: JSON.stringify({ q: query, per_page: perPage ?? 10 }),
        });
        const structured = parseCensys(data);
        return formatToolResult(response_format as ResponseFormat, { markdown: renderCensys(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying Censys"));
      }
    },
  );

  // 7. SecurityTrails DNS History
  server.registerTool(
    "securitytrails_dns_history",
    {
      title: "SecurityTrails DNS History",
      description:
        "Query historical DNS records and domain intelligence from SecurityTrails. Requires SECURITYTRAILS_API_KEY. Read-only.",
      inputSchema: {
        domain: z.string().describe("Domain to look up DNS history for"),
        type: z.enum(["a", "aaaa", "mx", "ns", "soa", "txt"]).optional().default("a").describe("DNS record type"),
        ...responseFormatField,
      },
      annotations: { title: "SecurityTrails DNS History", ...READONLY_OPENWORLD },
    },
    async ({ domain, type, response_format }) => {
      if (!env.SECURITYTRAILS_API_KEY)
        return toolError("Error: SECURITYTRAILS_API_KEY not configured. Free tier: 50 queries/month at https://securitytrails.com");
      const recordType = type ?? "a";
      try {
        const data = await fetchWithRetry(
          `https://api.securitytrails.com/v1/history/${domain}/dns/${recordType}`,
          { headers: { APIKEY: env.SECURITYTRAILS_API_KEY, "Content-Type": "application/json" } },
        );
        const structured = parseSecurityTrails(data, { domain, type: recordType });
        return formatToolResult(response_format as ResponseFormat, {
          markdown: renderSecurityTrails(structured),
          structured,
        });
      } catch (error) {
        return toolError(describeError(error, "querying SecurityTrails", "Free tier is 50 queries/month."));
      }
    },
  );

  // 8. IP WHOIS Enrichment (no key)
  server.registerTool(
    "ipwhois_enrichment",
    {
      title: "IP WHOIS Enrichment",
      description:
        "Get geolocation, ASN, and WHOIS data for an IP address. No authentication required. Read-only.",
      inputSchema: {
        ip: z.string().describe("IP address to look up"),
        ...responseFormatField,
      },
      annotations: { title: "IP WHOIS Enrichment", ...READONLY_OPENWORLD },
    },
    async ({ ip, response_format }) => {
      try {
        const data = await fetchWithRetry(`https://ipwhois.app/json/${ip}`, {});
        if (data?.success === false) return toolError(`Error: ${data.message ?? "Invalid IP address"}`);
        const structured = parseIPWhois(data);
        return formatToolResult(response_format as ResponseFormat, { markdown: renderIPWhois(structured), structured });
      } catch (error) {
        return toolError(describeError(error, "querying IPWHOIS"));
      }
    },
  );

  // 9. Wayback Machine Lookup (no key)
  server.registerTool(
    "wayback_machine_lookup",
    {
      title: "Wayback Machine Lookup",
      description:
        "Search the Internet Archive Wayback Machine for historical website snapshots. No authentication required. Read-only.",
      inputSchema: {
        url: z.string().describe("URL to look up in the Wayback Machine"),
        timestamp: z.string().optional().describe("Timestamp YYYYMMDDHHMMSS (optional)"),
        limit: z.number().int().min(1).max(100).optional().default(10).describe("Number of snapshots (1-100)"),
        ...responseFormatField,
      },
      annotations: { title: "Wayback Machine Lookup", ...READONLY_OPENWORLD },
    },
    async ({ url, timestamp, limit, response_format }) => {
      try {
        const availData = await fetchWithRetry(
          `https://archive.org/wayback/available?url=${encodeURIComponent(url)}${timestamp ? `&timestamp=${timestamp}` : ""}`,
          {},
        );
        const snapshotsData = await fetchWithRetry(
          `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}&limit=${limit ?? 10}&output=json`,
          {},
        );
        const structured = parseWayback({ ...availData, snapshots: snapshotsData });
        return formatToolResult(response_format as ResponseFormat, {
          markdown: renderWayback(structured),
          structured,
        });
      } catch (error) {
        return toolError(describeError(error, "querying Wayback Machine"));
      }
    },
  );
}
