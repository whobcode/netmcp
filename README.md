# NETMCP — Security Research MCP Server

A Model Context Protocol (MCP) server providing security research, OSINT, and vulnerability intelligence tools. Authenticated via GitHub OAuth.

**Server URL:** `https://netmcp.hwmnbn.me`

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

## Response formats, structured output & annotations

Every data tool follows a few shared conventions (implemented once in
`src/tool-helpers.ts`):

- **Dual output via `response_format`.** Pass `response_format: "markdown"`
  (default, human-readable) or `"json"` (machine-readable). Over MCP the
  structured object is *also* returned in the `structuredContent` field
  regardless of `response_format`.
- **Truncation.** Text output is capped at `CHARACTER_LIMIT` (25,000 chars) with
  a note telling you to narrow the query or use `limit`/`offset`.
- **Annotations.** Each tool carries MCP annotations so clients can reason about
  it: the searches/lookups are `readOnlyHint: true, openWorldHint: true`; the
  bundled ExploitDB tools are read-only with `openWorldHint: false`;
  `browser_fill_form`, `browser_click`, and `browser_execute_script` are **not**
  read-only; `generateImage` is a non-destructive open-world write.
- **Errors** are reported in-band (`isError: true`) with status-mapped, actionable
  messages (401/403/404/429 each map to a specific hint) — never thrown as
  protocol-level errors.

Tools are registered with the modern `registerTool(name, config, handler)` API
(title + description + `inputSchema` + annotations). Browser tools that return
images/PDFs (`browser_screenshot`, `browser_pdf`) emit binary content instead of
`response_format` text.

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
        "https://netmcp.hwmnbn.me/sse"
      ]
    }
  }
}
```

Restart Claude Desktop. A browser window will open for GitHub OAuth authentication.

### Cursor

Choose **Type**: "Command" and enter:

```
npx mcp-remote https://netmcp.hwmnbn.me/sse
```

### Other MCP Clients

Add the same JSON configuration to your client's config file and restart.

### MCP Inspector

Test the server directly:

```bash
npx @modelcontextprotocol/inspector@latest
```

Enter `https://netmcp.hwmnbn.me/sse` and connect.

## REST shim for iOS Shortcuts / curl (`/run`)

For clients that can't speak the MCP protocol (iOS Shortcuts, simple webhooks,
quick `curl` testing), this server exposes a thin REST endpoint at `/run` that
wraps the same tool handlers. It lives outside the OAuth-protected MCP paths
(`/sse`, `/mcp`), which are unchanged.

**Auth:** Single shared-secret bearer token. Set it once:

```bash
npx wrangler secret put SHORTCUT_SECRET
# paste a random string — e.g. `openssl rand -hex 32`
```

**Endpoints**

- `GET /run` — list available tools
- `POST /run` — run a tool. Body: `{ "tool": "<name>", "args": { ... } }`

The args are validated against the tool's Zod `inputSchema` with `.strict()` —
unknown fields are rejected, so a typo returns a `400` instead of being silently
dropped. Most data tools also accept an optional `"response_format"` arg
(`"markdown"` default, or `"json"`). The OAuth-gated tools (`userInfoOctokit`,
`generateImage`) are intentionally **not** exposed here.

**Example: Shodan search via curl**

```bash
curl -X POST https://netmcp.hwmnbn.me/run \
  -H "Authorization: Bearer $SHORTCUT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"tool":"shodan_device_search","args":{"query":"port:22 country:US","limit":5}}'
```

Response:

```json
{
  "ok": true,
  "tool": "shodan_device_search",
  "text": "### Shodan Search Results\n\nFound ...",
  "raw": { "content": [], "isError": false, "structuredContent": {} }
}
```

**Machine-readable JSON instead of Markdown** — add `response_format: "json"`:

```bash
curl -X POST https://netmcp.hwmnbn.me/run \
  -H "Authorization: Bearer $SHORTCUT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"tool":"nvd_cve_lookup","args":{"cveId":"CVE-2024-3094","response_format":"json"}}'
```

**iOS Shortcuts wiring**

One "Get Contents of URL" action is enough:

- **URL:** `https://netmcp.hwmnbn.me/run`
- **Method:** POST
- **Headers:**
  - `Authorization: Bearer <your SHORTCUT_SECRET>`
  - `Content-Type: application/json`
- **Request Body** (JSON):

  ```json
  {"tool":"ipwhois_enrichment","args":{"ip":"Shortcut Input"}}
  ```

Pipe it into a "Get Dictionary Value" → key `text` → "Show Result".

## Example Usage

Once connected, you can ask your AI assistant:

- "Search for CVE-2024-1234 in the NVD database"
- "Check if lodash 4.17.20 has any known vulnerabilities"
- "Search ExploitDB for Apache Struts exploits"
- "Look up the IP 8.8.8.8"
- "Find historical DNS records for example.com"
- "Search GitHub for Log4j proof of concept code"
- "Check Wayback Machine for archived versions of example.com"
