import { env } from "cloudflare:workers";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { Octokit } from "octokit";
import { z } from "zod";
import { fetchUpstreamAuthToken, getUpstreamAuthorizeUrl, type Props } from "./utils";
import {
	addApprovedClient,
	bindStateToSession,
	createOAuthState,
	generateCSRFProtection,
	isClientApproved,
	OAuthError,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";
import { ensureToolsBootstrapped, toolRegistry } from "./index";
import UI from "./ui.html";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

// ─── Public landing page + read-only tool catalog ──────────────────────────
// GET / falls through to this defaultHandler (it isn't an OAuth/MCP route).
// The catalog exposes only tool metadata (names/descriptions) — no execution.
app.get("/", (c) => c.html(UI));
app.get("/api/tools", async (c) => {
	await ensureToolsBootstrapped(c.env);
	const tools = toolRegistry.list();
	return c.json({ endpoint: "/mcp", count: tools.length, tools });
});

// ─── Shared-secret auth for the /run REST shim ─────────────────────────────
// Constant-time string compare so the bearer check doesn't leak length/prefix
// information via timing.
function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let mismatch = 0;
	for (let i = 0; i < a.length; i++) {
		mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return mismatch === 0;
}

function requireShortcutAuth(c: { req: { header(name: string): string | undefined }; env: Env }):
	{ ok: true } | { ok: false; status: 401 | 503; body: { error: string } } {
	const expected = (c.env as { SHORTCUT_SECRET?: string }).SHORTCUT_SECRET;
	if (!expected) {
		return { ok: false, status: 503, body: { error: "Server not configured: SHORTCUT_SECRET unset" } };
	}
	const header = c.req.header("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	if (!m || !timingSafeEqual(m[1], expected)) {
		return { ok: false, status: 401, body: { error: "Unauthorized" } };
	}
	return { ok: true };
}

// ─── REST shim for iOS Shortcuts / curl / any plain HTTP client ────────────
// GET  /run         → list available tools (handy when wiring a Shortcut)
// POST /run         → { "tool": "<name>", "args": { ... } }
//
// Auth: Bearer <SHORTCUT_SECRET>. Set with:
//   npx wrangler secret put SHORTCUT_SECRET
//
// This intentionally lives OUTSIDE the OAuthProvider's apiHandlers so it
// bypasses the MCP/OAuth flow. The MCP endpoints (/sse, /mcp) remain fully
// OAuth-protected and untouched.
app.get("/run", async (c) => {
	const auth = requireShortcutAuth(c);
	if (!auth.ok) return c.json(auth.body, auth.status);

	await ensureToolsBootstrapped(c.env);
	return c.json({ tools: toolRegistry.list() });
});

app.post("/run", async (c) => {
	const auth = requireShortcutAuth(c);
	if (!auth.ok) return c.json(auth.body, auth.status);

	await ensureToolsBootstrapped(c.env);

	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		return c.json({ error: "Body must be JSON" }, 400);
	}

	const { tool, args } = (body ?? {}) as { tool?: unknown; args?: unknown };
	if (typeof tool !== "string") {
		return c.json({ error: "Missing 'tool' (string) in body" }, 400);
	}
	const argObj = (args && typeof args === "object") ? (args as Record<string, unknown>) : {};

	const entry = toolRegistry.get(tool);
	if (!entry) {
		return c.json(
			{ error: `Unknown tool: ${tool}`, available: toolRegistry.list().map((t) => t.name) },
			404,
		);
	}

	// Validate against the tool's Zod inputSchema. .strict() rejects unknown
	// fields so typos surface as errors instead of being silently dropped.
	const shape = entry.config.inputSchema ?? {};
	const parsed = z.object(shape).strict().safeParse(argObj);
	if (!parsed.success) {
		return c.json({ error: "Invalid args", issues: parsed.error.issues }, 400);
	}

	try {
		const result = await entry.handler(parsed.data as Record<string, unknown>);
		// Convenience field: concatenate any text content blocks so a Shortcut
		// can do `Get Dictionary Value: text` and be done. `raw` carries the
		// full MCP-shaped result for clients that want images/PDFs/etc.
		const text = result.content
			.filter((b): b is { type: "text"; text: string } =>
				b.type === "text" && typeof (b as { text?: unknown }).text === "string")
			.map((b) => b.text)
			.join("\n");

		return c.json({
			ok: !result.isError,
			tool,
			text,
			raw: result,
		});
	} catch (err) {
		return c.json({ error: (err as Error).message ?? String(err) }, 500);
	}
});

app.get("/authorize", async (c) => {
	// parseAuthRequest throws (an OAuthError, or something else on malformed
	// input) when required OAuth params are missing. Without this guard the
	// throw bubbles out as an opaque HTTP 500. Catch it: OAuthError knows its
	// own spec-compliant response, anything else is a 400.
	let oauthReqInfo: AuthRequest;
	try {
		oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	} catch (error) {
		if (error instanceof OAuthError) {
			return error.toResponse();
		}
		console.error("GET /authorize parseAuthRequest failed:", error);
		return c.text("Invalid request", 400);
	}

	const { clientId } = oauthReqInfo;
	if (!clientId) {
		return c.text("Invalid request", 400);
	}

	// Check if client is already approved
	if (await isClientApproved(c.req.raw, clientId, env.COOKIE_ENCRYPTION_KEY)) {
		// Skip approval dialog but still create secure state and bind to session
		const { stateToken } = await createOAuthState(oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie: sessionBindingCookie } = await bindStateToSession(stateToken);
		return redirectToGithub(c.req.raw, stateToken, { "Set-Cookie": sessionBindingCookie });
	}

	// Generate CSRF protection for the approval form
	const { token: csrfToken, setCookie } = generateCSRFProtection();

	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		csrfToken,
		server: {
			description: "NETMCP — security research MCP server, authenticated via GitHub OAuth.",
			logo: "https://avatars.githubusercontent.com/u/314135?s=200&v=4",
			name: "NETMCP",
		},
		setCookie,
		state: { oauthReqInfo },
	});
});

app.post("/authorize", async (c) => {
	try {
		// Read form data once
		const formData = await c.req.raw.formData();

		// Validate CSRF token (returns cookie to clear for one-time use)
		const { clearCookie: csrfClearCookie } = validateCSRFToken(formData, c.req.raw);

		// Extract state from form data
		const encodedState = formData.get("state");
		if (!encodedState || typeof encodedState !== "string") {
			return c.text("Missing state in form data", 400);
		}

		let state: { oauthReqInfo?: AuthRequest };
		try {
			state = JSON.parse(atob(encodedState));
		} catch (_e) {
			return c.text("Invalid state data", 400);
		}

		if (!state.oauthReqInfo || !state.oauthReqInfo.clientId) {
			return c.text("Invalid request", 400);
		}

		// Add client to approved list
		const approvedClientCookie = await addApprovedClient(
			c.req.raw,
			state.oauthReqInfo.clientId,
			c.env.COOKIE_ENCRYPTION_KEY,
		);

		// Create OAuth state and bind it to this user's session
		const { stateToken } = await createOAuthState(state.oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie: sessionBindingCookie } = await bindStateToSession(stateToken);

		// Set all cookies: CSRF clear + approved client list + session binding
		const headers = new Headers();
		headers.append("Set-Cookie", csrfClearCookie);
		headers.append("Set-Cookie", approvedClientCookie);
		headers.append("Set-Cookie", sessionBindingCookie);

		// Build headers object for redirect - using Array.from for DOM/Workers Headers compatibility
		const headerEntries: [string, string][] = [];
		headers.forEach((value, key) => headerEntries.push([key, value]));
		return redirectToGithub(c.req.raw, stateToken, Object.fromEntries(headerEntries));
	} catch (error: any) {
		console.error("POST /authorize error:", error);
		if (error instanceof OAuthError) {
			return error.toResponse();
		}
		// Unexpected non-OAuth error - don't leak internal details
		return c.text("Internal server error", 500);
	}
});

async function redirectToGithub(
	request: Request,
	stateToken: string,
	headers: Record<string, string> = {},
) {
	return new Response(null, {
		headers: {
			...headers,
			location: getUpstreamAuthorizeUrl({
				client_id: env.GITHUB_CLIENT_ID,
				redirect_uri: new URL("/callback", request.url).href,
				scope: "read:user",
				state: stateToken,
				upstream_url: "https://github.com/login/oauth/authorize",
			}),
		},
		status: 302,
	});
}

/**
 * OAuth Callback Endpoint
 *
 * This route handles the callback from GitHub after user authentication.
 * It exchanges the temporary code for an access token, then stores some
 * user metadata & the auth token as part of the 'props' on the token passed
 * down to the client. It ends by redirecting the client back to _its_ callback URL
 *
 * SECURITY: This endpoint validates that the state parameter from GitHub
 * matches both:
 * 1. A valid state token in KV (proves it was created by our server)
 * 2. The __Host-CONSENTED_STATE cookie (proves THIS browser consented to it)
 *
 * This prevents CSRF attacks where an attacker's state token is injected
 * into a victim's OAuth flow.
 */
app.get("/callback", async (c) => {
	// Validate OAuth state with session binding
	// This checks both KV storage AND the session cookie
	let oauthReqInfo: AuthRequest;
	let clearSessionCookie: string;

	try {
		const result = await validateOAuthState(c.req.raw, c.env.OAUTH_KV);
		oauthReqInfo = result.oauthReqInfo;
		clearSessionCookie = result.clearCookie;
	} catch (error: any) {
		if (error instanceof OAuthError) {
			return error.toResponse();
		}
		// Unexpected non-OAuth error
		return c.text("Internal server error", 500);
	}

	if (!oauthReqInfo.clientId) {
		return c.text("Invalid OAuth request data", 400);
	}

	// Exchange the code for an access token
	const [accessToken, errResponse] = await fetchUpstreamAuthToken({
		client_id: c.env.GITHUB_CLIENT_ID,
		client_secret: c.env.GITHUB_CLIENT_SECRET,
		code: c.req.query("code"),
		redirect_uri: new URL("/callback", c.req.url).href,
		upstream_url: "https://github.com/login/oauth/access_token",
	});
	if (errResponse) return errResponse;

	// Fetch the user info from GitHub
	const user = await new Octokit({ auth: accessToken }).rest.users.getAuthenticated();
	const { login, name, email } = user.data;

	// Validate required fields (email can be null if user has private email settings)
	if (!login) {
		return c.text("Failed to retrieve GitHub user login", 500);
	}

	// Return back to the MCP client a new token
	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		metadata: {
			label: name ?? login,
		},
		// This will be available on this.props inside MyMCP
		// Note: email and name can be null if user has private settings
		props: {
			accessToken,
			email: email ?? "",
			login,
			name: name ?? login,
		} as Props,
		request: oauthReqInfo,
		scope: oauthReqInfo.scope,
		userId: login,
	});

	// Clear the session binding cookie (one-time use) by creating response with headers
	const headers = new Headers({ Location: redirectTo });
	if (clearSessionCookie) {
		headers.set("Set-Cookie", clearSessionCookie);
	}

	return new Response(null, {
		status: 302,
		headers,
	});
});

export { app as GitHubHandler };
