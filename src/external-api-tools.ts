// External API Tools for MCP Server
// Integrates security research, OSINT, and vulnerability intelligence APIs

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Helper function for HTTP requests with retry logic
async function fetchWithRetry(url: string, options: RequestInit = {}, maxRetries = 3): Promise<any> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          "User-Agent": "MCP-Server/1.0",
          ...options.headers,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error: any) {
      lastError = error;
      if (attempt < maxRetries - 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
      }
    }
  }

  throw new Error(`Failed after ${maxRetries} attempts: ${lastError?.message}`);
}

// Format functions
function formatNVDResults(data: any): string {
  if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
    return "No CVEs found matching your search.";
  }

  const results = data.vulnerabilities.slice(0, 10).map((item: any, idx: number) => {
    const cve = item.cve;
    const cveId = cve.id;
    const description = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "No description";
    const published = cve.published ? new Date(cve.published).toLocaleDateString() : "N/A";

    const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const score = cvssV3?.baseScore || cvssV2?.baseScore || "N/A";
    const severity = cvssV3?.baseSeverity || cvssV2?.baseSeverity || "N/A";

    return `${idx + 1}. **${cveId}** (Score: ${score}, Severity: ${severity})\n   Published: ${published}\n   ${description.substring(0, 200)}${description.length > 200 ? "..." : ""}`;
  }).join("\n\n");

  return `Found ${data.totalResults} CVEs (showing ${data.vulnerabilities.length}):\n\n${results}`;
}

function formatOSVResults(data: any, params: { packageName: string; version?: string }): string {
  if (!data.vulns || data.vulns.length === 0) {
    return `✓ No vulnerabilities found for ${params.packageName}${params.version ? ` v${params.version}` : ""}`;
  }

  const results = data.vulns.map((vuln: any, idx: number) => {
    const severity = vuln.database_specific?.severity || "UNKNOWN";
    const summary = vuln.summary || "No summary available";
    const aliases = vuln.aliases?.join(", ") || "None";

    return `${idx + 1}. **${vuln.id}** (Severity: ${severity})\n   Aliases: ${aliases}\n   ${summary}`;
  }).join("\n\n");

  return `Found ${data.vulns.length} vulnerabilities for ${params.packageName}:\n\n${results}`;
}

function formatGitHubResults(data: any): string {
  if (!data.items || data.items.length === 0) {
    return "No code found matching your search.";
  }

  const results = data.items.map((item: any, idx: number) => {
    const repoName = item.repository.full_name;
    const filePath = item.path;
    const htmlUrl = item.html_url;

    return `${idx + 1}. **${repoName}** - \`${filePath}\`\n   URL: ${htmlUrl}`;
  }).join("\n\n");

  return `Found ${data.total_count} results (showing ${data.items.length}):\n\n${results}`;
}

function formatGitLabResults(data: any): string {
  if (!Array.isArray(data) || data.length === 0) {
    return "No results found matching your search.";
  }

  const results = data.map((item: any, idx: number) => {
    if (item.path) {
      return `${idx + 1}. **${item.project_id}** - \`${item.path}\`\n   ${item.data?.substring(0, 100) || ""}...`;
    } else {
      return `${idx + 1}. **${item.name}**\n   ${item.description || "No description"}\n   URL: ${item.web_url}`;
    }
  }).join("\n\n");

  return `Found ${data.length} results:\n\n${results}`;
}

function formatShodanResults(data: any, limit: number): string {
  if (!data.matches || data.matches.length === 0) {
    return "No devices found matching your search.";
  }

  const results = data.matches.slice(0, limit).map((match: any, idx: number) => {
    const ip = match.ip_str;
    const port = match.port;
    const org = match.org || "Unknown";
    const location = `${match.location?.city || "Unknown"}, ${match.location?.country_name || "Unknown"}`;
    const product = match.product || "Unknown";
    const vulns = match.vulns ? Object.keys(match.vulns).join(", ") : "None detected";

    return `${idx + 1}. **${ip}:${port}** (${product})\n   Org: ${org}\n   Location: ${location}\n   Vulnerabilities: ${vulns}`;
  }).join("\n\n");

  return `Found ${data.total} devices (showing ${Math.min(limit, data.matches.length)}):\n\n${results}`;
}

function formatCensysResults(data: any): string {
  if (!data.result?.hits || data.result.hits.length === 0) {
    return "No hosts found matching your search.";
  }

  const results = data.result.hits.map((hit: any, idx: number) => {
    const ip = hit.ip;
    const name = hit.name || "No hostname";
    const services = hit.services?.map((s: any) => `${s.port}/${s.service_name}`).join(", ") || "No services";
    const asn = hit.autonomous_system?.asn || "Unknown";
    const location = `${hit.location?.city || "Unknown"}, ${hit.location?.country || "Unknown"}`;

    return `${idx + 1}. **${ip}** (${name})\n   ASN: ${asn}\n   Location: ${location}\n   Services: ${services}`;
  }).join("\n\n");

  return `Found ${data.result.total} hosts (showing ${data.result.hits.length}):\n\n${results}`;
}

function formatSecurityTrailsResults(data: any, params: { domain: string; type: string }): string {
  if (!data.records || data.records.length === 0) {
    return `No ${params.type.toUpperCase()} record history found for ${params.domain}`;
  }

  const results = data.records.slice(0, 10).map((record: any, idx: number) => {
    const values = record.values?.join(", ") || "N/A";
    const firstSeen = record.first_seen || "Unknown";
    const lastSeen = record.last_seen || "Unknown";

    return `${idx + 1}. **${values}**\n   First seen: ${firstSeen}\n   Last seen: ${lastSeen}`;
  }).join("\n\n");

  return `DNS ${params.type.toUpperCase()} history for **${params.domain}** (${data.records.length} records):\n\n${results}`;
}

function formatIPWhoisResults(data: any): string {
  if (data.success === false) {
    return `Error: ${data.message || "Invalid IP address"}`;
  }

  return `**IP:** ${data.ip}
**Type:** ${data.type || "N/A"}
**Country:** ${data.country} (${data.country_code})
**Region:** ${data.region}
**City:** ${data.city}
**ISP:** ${data.isp || "Unknown"}
**ASN:** ${data.asn || "Unknown"}
**Organization:** ${data.org || "Unknown"}
**Timezone:** ${data.timezone || "Unknown"}
**Latitude:** ${data.latitude}
**Longitude:** ${data.longitude}`;
}

function formatWaybackResults(data: any): string {
  if (!data.available) {
    return "No archived snapshots found for this URL.";
  }

  let output = `**Latest Snapshot:**\n`;
  output += `- Timestamp: ${data.closest.timestamp}\n`;
  output += `- Status: ${data.closest.status}\n`;
  output += `- URL: ${data.closest.url}\n\n`;

  if (data.snapshots && Array.isArray(data.snapshots) && data.snapshots.length > 1) {
    output += `**Available Snapshots:** ${data.snapshots.length - 1} found\n\n`;
    const snapshots = data.snapshots.slice(1, 11);
    output += snapshots.map((snap: any, idx: number) => {
      const [urlkey, timestamp, original, mimetype, statuscode, digest, length] = snap;
      return `${idx + 1}. ${timestamp} - Status ${statuscode} - ${mimetype}`;
    }).join("\n");
  }

  return output;
}

// Register all external API tools
export function registerExternalApiTools(server: McpServer, env: Env) {
  // 1. NVD CVE Lookup
  server.tool(
    "nvd_cve_lookup",
    "Search the NIST National Vulnerability Database for CVE details, CVSS scores, and remediation information.",
    {
      cveId: z.string().optional().describe("Specific CVE ID to lookup (e.g., CVE-2024-1234)"),
      keyword: z.string().optional().describe("Keyword search across CVE descriptions"),
      resultsPerPage: z.number().int().min(1).max(100).optional().default(10).describe("Number of results (1-100)"),
      startIndex: z.number().int().min(0).optional().default(0).describe("Starting index for pagination"),
    },
    async ({ cveId, keyword, resultsPerPage, startIndex }) => {
      if (!cveId && !keyword) {
        return {
          content: [{ type: "text", text: "Error: Either cveId or keyword must be provided" }],
          isError: true,
        };
      }

      const baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
      const searchParams = new URLSearchParams();

      if (cveId) searchParams.set("cveId", cveId);
      if (keyword) searchParams.set("keywordSearch", keyword);
      searchParams.set("resultsPerPage", String(resultsPerPage || 10));
      searchParams.set("startIndex", String(startIndex || 0));

      const url = `${baseUrl}?${searchParams}`;
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (env.NVD_API_KEY) headers["apiKey"] = env.NVD_API_KEY;

      try {
        const data = await fetchWithRetry(url, { headers });
        return {
          content: [{ type: "text", text: `### NVD CVE Lookup Results\n\n${formatNVDResults(data)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying NVD API: ${error.message}\n\nNote: Without an API key, rate limits are 5 requests per 30 seconds.` }],
          isError: true,
        };
      }
    }
  );

  // 2. OSV Vulnerability Scan
  server.tool(
    "osv_vulnerability_scan",
    "Scan open source packages for known vulnerabilities using the OSV database.",
    {
      packageName: z.string().describe("Package name to check for vulnerabilities"),
      version: z.string().optional().describe("Specific version to check (e.g., 1.2.3)"),
      ecosystem: z.enum(["npm", "PyPI", "Go", "Maven", "Cargo", "RubyGems", "NuGet", "Packagist", "Debian", "Alpine"]).describe("Package ecosystem"),
      commit: z.string().optional().describe("Git commit hash (alternative to version)"),
    },
    async ({ packageName, version, ecosystem, commit }) => {
      const url = "https://api.osv.dev/v1/query";

      const requestBody = commit
        ? { commit }
        : {
            version,
            package: { name: packageName, ecosystem },
          };

      try {
        const data = await fetchWithRetry(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestBody),
        });

        return {
          content: [{ type: "text", text: `### OSV Vulnerability Scan Results\n\n${formatOSVResults(data, { packageName, version })}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying OSV API: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  // 3. GitHub Exploit Search
  server.tool(
    "github_exploit_search",
    "Search GitHub for exploit code, proof-of-concepts, and security tools.",
    {
      query: z.string().describe("Search query (CVE ID, exploit name, or keywords)"),
      language: z.string().optional().describe("Filter by programming language (e.g., python, javascript)"),
      limit: z.number().int().min(1).max(100).optional().default(10).describe("Maximum results (1-100)"),
    },
    async ({ query, language, limit }) => {
      if (!env.GITHUB_TOKEN) {
        return {
          content: [{ type: "text", text: "Error: GITHUB_TOKEN not configured. This tool requires a GitHub API token." }],
          isError: true,
        };
      }

      let searchQuery = query;
      if (language) searchQuery += ` language:${language}`;

      const url = `https://api.github.com/search/code?q=${encodeURIComponent(searchQuery)}&per_page=${limit || 10}`;

      try {
        const data = await fetchWithRetry(url, {
          headers: {
            Authorization: `Bearer ${env.GITHUB_TOKEN}`,
            Accept: "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
          },
        });

        return {
          content: [{ type: "text", text: `### GitHub Exploit Search Results\n\n${formatGitHubResults(data)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying GitHub API: ${error.message}\n\nNote: Rate limit is 5,000 requests/hour with authentication.` }],
          isError: true,
        };
      }
    }
  );

  // 4. GitLab Code Search
  server.tool(
    "gitlab_code_search",
    "Search GitLab for code, focusing on public projects and exploits.",
    {
      query: z.string().describe("Search query for code content"),
      scope: z.enum(["blobs", "projects"]).optional().default("blobs").describe("Search scope"),
      limit: z.number().int().min(1).max(100).optional().default(10).describe("Maximum results"),
    },
    async ({ query, scope, limit }) => {
      const baseUrl = "https://gitlab.com/api/v4/search";
      const searchParams = new URLSearchParams({
        scope: scope || "blobs",
        search: query,
        per_page: String(limit || 10),
      });

      const url = `${baseUrl}?${searchParams}`;
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (env.GITLAB_TOKEN) headers["PRIVATE-TOKEN"] = env.GITLAB_TOKEN;

      try {
        const data = await fetchWithRetry(url, { headers });
        return {
          content: [{ type: "text", text: `### GitLab Code Search Results\n\n${formatGitLabResults(data)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying GitLab API: ${error.message}\n\nNote: Limited to public projects without authentication.` }],
          isError: true,
        };
      }
    }
  );

  // 5. Shodan Device Search
  server.tool(
    "shodan_device_search",
    "Search Shodan for Internet-connected devices, exposed services, and vulnerabilities.",
    {
      query: z.string().describe("Shodan search query (IP, hostname, service, or advanced filters)"),
      facets: z.string().optional().describe("Comma-separated facets to return (e.g., country,port,org)"),
      limit: z.number().int().min(1).max(100).optional().default(10).describe("Maximum results"),
    },
    async ({ query, facets, limit }) => {
      if (!env.SHODAN_API_KEY) {
        return {
          content: [{ type: "text", text: "Error: SHODAN_API_KEY not configured. Get one at https://shodan.io (100 free queries/month)." }],
          isError: true,
        };
      }

      const searchParams = new URLSearchParams({
        key: env.SHODAN_API_KEY,
        query,
      });
      if (facets) searchParams.set("facets", facets);

      const url = `https://api.shodan.io/shodan/host/search?${searchParams}`;

      try {
        const data = await fetchWithRetry(url, {});
        return {
          content: [{ type: "text", text: `### Shodan Search Results\n\n${formatShodanResults(data, limit || 10)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying Shodan API: ${error.message}\n\nNote: Free tier provides 100 queries/month.` }],
          isError: true,
        };
      }
    }
  );

  // 6. Censys Host Search
  server.tool(
    "censys_host_search",
    "Search Censys for host information, certificates, and exposed services.",
    {
      query: z.string().describe("Censys search query (IP, domain, or search syntax)"),
      perPage: z.number().int().min(1).max(100).optional().default(10).describe("Results per page"),
    },
    async ({ query, perPage }) => {
      if (!env.CENSYS_API_ID || !env.CENSYS_API_SECRET) {
        return {
          content: [{ type: "text", text: "Error: CENSYS_API_ID and CENSYS_API_SECRET not configured. Register at https://search.censys.io/register" }],
          isError: true,
        };
      }

      const url = "https://search.censys.io/api/v2/hosts/search";
      const auth = btoa(`${env.CENSYS_API_ID}:${env.CENSYS_API_SECRET}`);

      try {
        const data = await fetchWithRetry(url, {
          method: "POST",
          headers: {
            Authorization: `Basic ${auth}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ q: query, per_page: perPage || 10 }),
        });

        return {
          content: [{ type: "text", text: `### Censys Host Search Results\n\n${formatCensysResults(data)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying Censys API: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  // 7. SecurityTrails DNS History
  server.tool(
    "securitytrails_dns_history",
    "Query SecurityTrails for historical DNS records and domain intelligence.",
    {
      domain: z.string().describe("Domain to lookup DNS history for"),
      type: z.enum(["a", "aaaa", "mx", "ns", "soa", "txt"]).optional().default("a").describe("DNS record type"),
    },
    async ({ domain, type }) => {
      if (!env.SECURITYTRAILS_API_KEY) {
        return {
          content: [{ type: "text", text: "Error: SECURITYTRAILS_API_KEY not configured. Free tier: 50 queries/month at https://securitytrails.com" }],
          isError: true,
        };
      }

      const url = `https://api.securitytrails.com/v1/history/${domain}/dns/${type || "a"}`;

      try {
        const data = await fetchWithRetry(url, {
          headers: {
            APIKEY: env.SECURITYTRAILS_API_KEY,
            "Content-Type": "application/json",
          },
        });

        return {
          content: [{ type: "text", text: `### SecurityTrails DNS History\n\n${formatSecurityTrailsResults(data, { domain, type: type || "a" })}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying SecurityTrails API: ${error.message}\n\nNote: Free tier limited to 50 queries per month.` }],
          isError: true,
        };
      }
    }
  );

  // 8. IP WHOIS Enrichment (No API key required)
  server.tool(
    "ipwhois_enrichment",
    "Get geolocation, ASN, and WHOIS data for an IP address. No authentication required.",
    {
      ip: z.string().describe("IP address to lookup"),
    },
    async ({ ip }) => {
      const url = `https://ipwhois.app/json/${ip}`;

      try {
        const data = await fetchWithRetry(url, {});
        return {
          content: [{ type: "text", text: `### IP WHOIS Lookup\n\n${formatIPWhoisResults(data)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying IPWHOIS API: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  // 9. Wayback Machine Lookup (No API key required)
  server.tool(
    "wayback_machine_lookup",
    "Search the Internet Archive Wayback Machine for historical website snapshots.",
    {
      url: z.string().describe("URL to lookup in the Wayback Machine"),
      timestamp: z.string().optional().describe("Timestamp in format YYYYMMDDHHMMSS (optional)"),
      limit: z.number().int().min(1).max(100).optional().default(10).describe("Number of snapshots to return"),
    },
    async ({ url, timestamp, limit }) => {
      const availUrl = `https://archive.org/wayback/available?url=${encodeURIComponent(url)}${timestamp ? `&timestamp=${timestamp}` : ""}`;

      try {
        const availData = await fetchWithRetry(availUrl, {});

        // Get snapshots from CDX API
        const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}&limit=${limit || 10}&output=json`;
        const snapshotsData = await fetchWithRetry(cdxUrl, {});

        const result = {
          available: availData.archived_snapshots?.closest ? true : false,
          closest: availData.archived_snapshots?.closest,
          snapshots: snapshotsData,
        };

        return {
          content: [{ type: "text", text: `### Wayback Machine Results\n\n${formatWaybackResults(result)}` }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error querying Wayback Machine: ${error.message}` }],
          isError: true,
        };
      }
    }
  );
}
