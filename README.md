# Security Research MCP Server

A Model Context Protocol (MCP) server providing security research, OSINT, and vulnerability intelligence tools. Authenticated via GitHub OAuth.

**Server URL:** `https://my-mcp-server-github-auth.tru-bone.workers.dev`

## Tools

### Vulnerability Intelligence

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `nvd_cve_lookup` | Search NIST National Vulnerability Database for CVE details, CVSS scores, and remediation info | Optional (increases rate limit) |
| `osv_vulnerability_scan` | Scan open source packages for known vulnerabilities using the OSV database | None |

### Exploit Database

| Tool | Description |
|------|-------------|
| `exploitdb_search` | Search 47,987 exploits by keyword, CVE, platform, or type |
| `exploitdb_get` | Get detailed exploit information by ExploitDB ID |
| `exploitdb_info` | Get dataset metadata and statistics |

### Code Search

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `github_exploit_search` | Search GitHub for exploit code, PoCs, and security tools | GITHUB_TOKEN |
| `gitlab_code_search` | Search GitLab for code in public projects | Optional |

### Internet Intelligence

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `shodan_device_search` | Search Shodan for Internet-connected devices and exposed services | SHODAN_API_KEY |
| `censys_host_search` | Search Censys for host information, certificates, and services | CENSYS_API_ID + SECRET |
| `securitytrails_dns_history` | Query historical DNS records and domain intelligence | SECURITYTRAILS_API_KEY |
| `ipwhois_enrichment` | Get geolocation, ASN, and WHOIS data for any IP address | None |
| `wayback_machine_lookup` | Search Internet Archive for historical website snapshots | None |

### Utility

| Tool | Description |
|------|-------------|
| `add` | Add two numbers |
| `userInfoOctokit` | Get authenticated GitHub user info |
| `generateImage` | Generate images with Flux AI (restricted access) |

## Connecting to the Server

### Claude Desktop

Open **Settings → Developer → Edit Config** and add:

```json
{
  "mcpServers": {
    "security-research": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://my-mcp-server-github-auth.tru-bone.workers.dev/sse"
      ]
    }
  }
}
```

Restart Claude Desktop. A browser window will open for GitHub OAuth authentication.

### Cursor

Choose **Type**: "Command" and enter:

```
npx mcp-remote https://my-mcp-server-github-auth.tru-bone.workers.dev/sse
```

### Other MCP Clients

Add the same JSON configuration to your client's config file and restart.

### MCP Inspector

Test the server directly:

```bash
npx @modelcontextprotocol/inspector@latest
```

Enter `https://my-mcp-server-github-auth.tru-bone.workers.dev/sse` and connect.

## Example Usage

Once connected, you can ask your AI assistant:

- "Search for CVE-2024-1234 in the NVD database"
- "Check if lodash 4.17.20 has any known vulnerabilities"
- "Search ExploitDB for Apache Struts exploits"
- "Look up the IP 8.8.8.8"
- "Find historical DNS records for example.com"
- "Search GitHub for Log4j proof of concept code"
- "Check Wayback Machine for archived versions of example.com"
