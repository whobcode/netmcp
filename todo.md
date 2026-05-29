# netmcp — Setup & Completion Checklist

This is the punch list to get the server from "builds clean" to "mostly functional,"
plus a full tool reference and an Apple Shortcuts wiring guide for the `/run` REST shim.

Server URL: `https://netmcp.hwmnbn.me`
MCP endpoints: `/mcp` (Streamable-HTTP, current) and `/sse` (deprecated)
REST shim: `/run` (no OAuth — bearer token only)

---

## 1. Required secrets — set these or core features break

The MCP OAuth flow (`/sse`, `/mcp`) will not work without the three GitHub/cookie
secrets. The `/run` shim will not work without `SHORTCUT_SECRET`.

```bash
# GitHub OAuth app credentials (see step 1a below to create the app)
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET

# Cookie encryption key — any long random string
openssl rand -hex 32   # copy the output, then:
npx wrangler secret put COOKIE_ENCRYPTION_KEY

# Bearer token for the /run REST shim (iOS Shortcuts / curl)
openssl rand -hex 32   # copy the output, then:
npx wrangler secret put SHORTCUT_SECRET
```

### 1a. Create the GitHub OAuth app

GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.

- **Homepage URL:** `https://netmcp.hwmnbn.me`
- **Authorization callback URL:** `https://netmcp.hwmnbn.me/callback`

Copy the Client ID and generate a Client Secret; feed both into the
`wrangler secret put` commands above. For local dev, also put them in `.dev.vars`
(copy `.dev.vars.example` → `.dev.vars`).

---

## 2. Optional API keys — each unlocks one tool

Every external-API tool returns a clear "missing key" error if its secret is unset,
so the server runs fine without them — those specific tools just won't return data.

| Secret | Unlocks tool | Get a key at |
|--------|-------------|--------------|
| `NVD_API_KEY` | `nvd_cve_lookup` (works without; key raises rate limit) | https://nvd.nist.gov/developers/request-an-api-key |
| `GITHUB_TOKEN` | `github_exploit_search` | GitHub → Settings → Developer settings → Personal access tokens |
| `GITLAB_TOKEN` | `gitlab_code_search` (works without; key raises limits) | GitLab → Preferences → Access tokens |
| `SHODAN_API_KEY` | `shodan_device_search` | https://account.shodan.io |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | `censys_host_search` | https://search.censys.io/account/api |
| `SECURITYTRAILS_API_KEY` | `securitytrails_dns_history` | https://securitytrails.com/app/account/credentials |

```bash
npx wrangler secret put NVD_API_KEY
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put GITLAB_TOKEN
npx wrangler secret put SHODAN_API_KEY
npx wrangler secret put CENSYS_API_ID
npx wrangler secret put CENSYS_API_SECRET
npx wrangler secret put SECURITYTRAILS_API_KEY
```

No-key tools (always work): `osv_vulnerability_scan`, `ipwhois_enrichment`,
`wayback_machine_lookup`, all `exploitdb_*`, all `browser_*`, `add`.

---

## 3. Build, run, deploy

```bash
npm install           # if you haven't already
npm run cf-typegen    # regenerate Env types (REQUIRED before type-check — see note)
npm run type-check    # tsc --noEmit
npm run dev           # local dev on http://localhost:8788
npm run deploy        # wrangler deploy to production
```

> **Heads-up — `type-check` currently fails until you do step 4a.** The generated
> `worker-configuration.d.ts` only knows about the bindings in `wrangler.jsonc`
> (`AI`, `BROWSER`, `OAUTH_KV`, `MCP_OBJECT`). It does **not** declare the secret
> env vars the code reads (`GITHUB_CLIENT_ID`, `COOKIE_ENCRYPTION_KEY`,
> `NVD_API_KEY`, `SHODAN_API_KEY`, etc.), so `tsc` reports ~18
> "Property 'X' does not exist on type 'Env'" errors. Fix it once via step 4a.

After `wrangler secret put`, redeploy isn't required for secrets to take effect on
the live worker, but a deploy is required for any code/binding change.

---

## 4. Code issues to clean up

### 4a. (Blocker) `type-check` fails — `Env` type is missing all secrets

The code reads secrets off `env` (e.g. `env.GITHUB_CLIENT_ID`, `env.NVD_API_KEY`),
but `worker-configuration.d.ts` doesn't declare them, so `tsc --noEmit` errors out.
Wrangler generates secret types from a local `.dev.vars` file — which doesn't exist
yet. Create it, then regenerate the types:

```bash
cp .dev.vars.example .dev.vars      # then fill in real values (or leave blanks)
# add the optional-API keys you plan to use as empty lines too, e.g.:
#   NVD_API_KEY=
#   GITHUB_TOKEN=
#   SHODAN_API_KEY=
#   CENSYS_API_ID=
#   CENSYS_API_SECRET=
#   SECURITYTRAILS_API_KEY=
#   GITLAB_TOKEN=
npm run cf-typegen                  # wrangler types — rewrites worker-configuration.d.ts
npm run type-check                  # should now be clean
```

`.dev.vars` is gitignored, so this stays local. Re-run `npm run cf-typegen` any time
you add a new secret or change a binding.

### 4b. Cosmetic / boilerplate cleanup

These are cosmetic/boilerplate items found in a scan — none block the build, but
they leak "demo template" identity and a stale URL. Fix when convenient.

- [x] **wrangler.jsonc — AI/BROWSER remote warning.** Added `"remote": true` to both
  the `ai` and `browser` bindings. Resolves the
  `▲ AI bindings always access remote resources` warning. *(Done.)*

- [x] **README.md — stale server URL (4 places).** All four now point to
  `https://netmcp.hwmnbn.me`. *(Done.)*

- [x] **.dev.vars.example — typo.** Line 3 fixed to
  `COOKIE_ENCRYPTION_KEY=<your cookie encryption key>`. *(Done.)*

- [x] **src/index.ts — MCP server name.** Renamed `"Github OAuth Proxy Demo"` →
  `"NETMCP"` (line ~71). *(Done.)*

- [x] **src/github-handler.ts — approval-dialog text.** OAuth consent screen now shows
  `name: "NETMCP"` and a non-"demo" description. *(Done.)*

- [ ] **src/index.ts — hardcoded allow-list.** `ALLOWED_USERNAMES` contains only
  `'whobcode'`; the `generateImage` tool is gated to that GitHub login. **Intentionally
  left as-is** — add other logins here later if you want to widen image-gen access.

- [ ] **(Optional) Refresh ExploitDB dataset.** The bundled dataset is baked into
  `src/exploitdb-dataset.ts`. To rebuild it: `npm run sync:exploitdb`
  (runs `scripts/build_exploitdb.py`). README claims 47,987 exploits — re-verify the
  count after a rebuild and update README/`exploitdb_info` expectations if it changes.

---

## 5. Tool reference

All tools below are callable over `/run` **except** `userInfoOctokit` and
`generateImage`, which require GitHub OAuth context and are only available over
`/sse` and `/mcp`. `?` marks optional args.

### Vulnerability intelligence
| Tool | Args | Notes |
|------|------|-------|
| `nvd_cve_lookup` | `cveId?`, `keyword?`, `resultsPerPage?`, `startIndex?` | Pass either a CVE id or a keyword. |
| `osv_vulnerability_scan` | `packageName`, `ecosystem`, `version?`, `commit?` | No key needed. `ecosystem` e.g. `npm`, `PyPI`. |

### Exploit database (bundled, no key)
| Tool | Args | Notes |
|------|------|-------|
| `exploitdb_search` | `query?`, `platform?`, `type?`, `verified?`, `kind?`, `limit?` | `kind` = `exploit`\|`shellcode`; `limit` 1–200 (default 10). |
| `exploitdb_get` | `id` | Numeric ExploitDB ID. |
| `exploitdb_info` | *(none)* | Dataset metadata/stats. |

### Code search
| Tool | Args | Notes |
|------|------|-------|
| `github_exploit_search` | `query`, `language?`, `limit?` | Needs `GITHUB_TOKEN`. |
| `gitlab_code_search` | `query`, `scope?`, `limit?` | Works without key; token raises limits. |

### Internet intelligence
| Tool | Args | Notes |
|------|------|-------|
| `shodan_device_search` | `query`, `facets?`, `limit?` | Needs `SHODAN_API_KEY`. |
| `censys_host_search` | `query`, `perPage?` | Needs `CENSYS_API_ID` + `CENSYS_API_SECRET`. |
| `securitytrails_dns_history` | `domain`, `type?` | Needs `SECURITYTRAILS_API_KEY`. |
| `ipwhois_enrichment` | `ip` | No key. Geo/ASN/WHOIS. |
| `wayback_machine_lookup` | `url`, `timestamp?`, `limit?` | No key. |

### Browser automation (Cloudflare Playwright, no key)
| Tool | Args |
|------|------|
| `browser_screenshot` | `url`, `fullPage?`, `width?`, `height?`, `format?`, `quality?`, `waitUntil?`, `selector?` |
| `browser_get_content` | `url`, `contentType?`, `waitUntil?`, `selector?`, `waitForSelector?`, `timeout?` |
| `browser_get_markdown` | `url`, `waitUntil?`, `selector?`, `includeLinks?` |
| `browser_pdf` | `url`, `format?`, `landscape?`, `printBackground?`, `scale?`, `waitUntil?` |
| `browser_scrape` | `url`, `selectors`, `multiple?`, `attributes?`, `waitUntil?`, `waitForSelector?` |
| `browser_execute_script` | `url`, `script`, `waitUntil?`, `waitForSelector?` |
| `browser_get_links` | `url`, `selector?`, `includeExternal?`, `waitUntil?` |
| `browser_fill_form` | `url`, `fields`, `submitSelector?`, `waitAfterSubmit?`, `screenshotAfter?`, `waitUntil?` |
| `browser_click` | `url`, `selector`, `waitForNavigation?`, `waitForSelector?`, `screenshot?`, `waitUntil?` |

### Utility / OAuth-gated
| Tool | Args | Availability |
|------|------|--------------|
| `add` | `a`, `b` | `/run` + MCP. Smoke test. |
| `userInfoOctokit` | *(none)* | **MCP only** (needs OAuth). |
| `generateImage` | `prompt`, `steps?` | **MCP only**, restricted to `ALLOWED_USERNAMES`. |

---

## 6. `/run` REST shim — Apple Shortcuts guide

The `/run` endpoint lets iOS Shortcuts (or `curl`, or any plain HTTP client) call
the tools without speaking MCP. Auth is a single bearer token (`SHORTCUT_SECRET`).

- `GET /run` → lists available tools (handy while wiring a Shortcut).
- `POST /run` → body `{ "tool": "<name>", "args": { ... } }`. Args are validated
  against the tool's Zod schema. Response: `{ ok, tool, text, raw }` — `text` is the
  concatenated text output (use this in Shortcuts); `raw` is the full MCP result.

### Minimal Shortcut (one action)

Use a single **Get Contents of URL** action:

- **URL:** `https://netmcp.hwmnbn.me/run`
- **Method:** POST
- **Headers:**
  - `Authorization` → `Bearer YOUR_SHORTCUT_SECRET`
  - `Content-Type` → `application/json`
- **Request Body:** JSON (see per-tool examples below)

Then add **Get Dictionary Value** → key `text` → **Show Result** (or **Quick Look**).

To make it interactive, drop an **Ask for Input** action first and reference its
result inside the JSON body (Shortcuts lets you insert the variable into a text field).

### Ready-to-use request bodies

```jsonc
// Look up an IP (no key needed)
{ "tool": "ipwhois_enrichment", "args": { "ip": "8.8.8.8" } }

// CVE lookup
{ "tool": "nvd_cve_lookup", "args": { "cveId": "CVE-2024-3094" } }

// Check a package for known vulns (no key)
{ "tool": "osv_vulnerability_scan",
  "args": { "packageName": "lodash", "version": "4.17.20", "ecosystem": "npm" } }

// Search the bundled ExploitDB (no key)
{ "tool": "exploitdb_search", "args": { "query": "apache struts", "limit": 5 } }

// Shodan (needs SHODAN_API_KEY)
{ "tool": "shodan_device_search",
  "args": { "query": "port:22 country:US", "limit": 5 } }

// Wayback snapshot (no key)
{ "tool": "wayback_machine_lookup", "args": { "url": "example.com", "limit": 3 } }

// Page → markdown (no key)
{ "tool": "browser_get_markdown", "args": { "url": "https://example.com" } }
```

### curl equivalents (for testing before building the Shortcut)

```bash
# List tools
curl https://netmcp.hwmnbn.me/run \
  -H "Authorization: Bearer $SHORTCUT_SECRET"

# Run a tool
curl -X POST https://netmcp.hwmnbn.me/run \
  -H "Authorization: Bearer $SHORTCUT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"tool":"ipwhois_enrichment","args":{"ip":"8.8.8.8"}}'
```

Tip: for tools that return images/PDFs (`browser_screenshot`, `browser_pdf`,
`generateImage` via MCP), read the `raw.content` array instead of `text` — the
base64 payload lives there.
