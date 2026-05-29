import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { Octokit } from "octokit";
import { z } from "zod";
import { GitHubHandler } from "./github-handler";
import type { Props } from "./utils";
import { registerExternalApiTools } from "./external-api-tools";
import { registerExploitDbTools, loadDataset, isDatasetLoaded } from "./exploitdb-toolkit";
import { EXPLOITDB_DATASET_BASE64 } from "./exploitdb-dataset";
import { registerBrowserTools } from "./browser-tools";
import { ToolRegistry } from "./tool-registry";
import { WRITE_OPENWORLD } from "./tool-helpers";

const ALLOWED_USERNAMES = new Set<string>([
	// Add GitHub usernames of users who should have access to the image generation tool
	// For example: 'yourusername', 'coworkerusername'
	'whobcode'
]);

// Shared per-isolate registry. Both MyMCP (Durable Object isolate) and the
// Hono `app` (Worker isolate) construct their own copy at module load,
// populated lazily on first use. This lets the REST `/run` shim dispatch to
// the same tool handlers the MCP server uses, even though the two run in
// different isolates with different module state.
export const toolRegistry = new ToolRegistry();
let bootstrapped = false;

/**
 * Idempotent: registers every plain (non-OAuth) tool into the module-scope
 * registry. Safe to call from MyMCP.init() and from the /run REST handler.
 *
 * ToolRegistry implements .tool() with the same signature McpServer uses, so
 * the existing register*Tools functions work unchanged. The `as any` casts
 * just satisfy TS — those functions are typed against McpServer.
 */
export async function ensureToolsBootstrapped(env: Env): Promise<void> {
	if (bootstrapped) return;
	bootstrapped = true;

	if (EXPLOITDB_DATASET_BASE64 && !isDatasetLoaded()) {
		try {
			await loadDataset(EXPLOITDB_DATASET_BASE64);
			console.log("ExploitDB dataset loaded successfully");
		} catch (e) {
			console.error("Failed to load ExploitDB dataset:", e);
		}
	}

	// Register external API tools (security research, OSINT, vulnerability intelligence)
	registerExternalApiTools(toolRegistry as any, env);

	// Register ExploitDB tools
	registerExploitDbTools(toolRegistry as any);

	// Register browser automation tools (Playwright)
	registerBrowserTools(toolRegistry as any, env.BROWSER);

	// `add` is trivial enough to also expose via /run for smoke-testing.
	toolRegistry.registerTool(
		"add",
		{
			title: "Add",
			description: "Add two numbers (smoke-test tool).",
			inputSchema: { a: z.number().describe("First addend"), b: z.number().describe("Second addend") },
			annotations: {
				title: "Add",
				readOnlyHint: true,
				destructiveHint: false,
				idempotentHint: true,
				openWorldHint: false,
			},
		},
		async ({ a, b }) => ({
			content: [{ text: String((a as number) + (b as number)), type: "text" }],
		}),
	);
}

export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "NETMCP",
		version: "1.0.0",
	});

	async init() {
		// Populate the shared registry (idempotent).
		await ensureToolsBootstrapped(this.env);

		// Mirror every registered tool onto the actual MCP server so /mcp and
		// /sse clients still see them. The cast keeps the registry's looser
		// ToolResult/ZodRawShape types compatible with McpServer's stricter
		// ToolCallback typing — behavior is identical.
		for (const meta of toolRegistry.list()) {
			const full = toolRegistry.get(meta.name)!;
			(this.server.registerTool as any)(full.name, full.config, full.handler);
		}

		// OAuth-gated tools stay here — they close over this.props and can't
		// run through /run (which has no GitHub OAuth context).
		this.server.registerTool(
			"userInfoOctokit",
			{
				title: "GitHub User Info",
				description:
					"Get the authenticated GitHub user's info via Octokit. Requires GitHub OAuth (available on /mcp and /sse only).",
				inputSchema: {},
				annotations: {
					title: "GitHub User Info",
					readOnlyHint: true,
					destructiveHint: false,
					idempotentHint: true,
					openWorldHint: true,
				},
			},
			async () => {
				if (!this.props?.accessToken) {
					return {
						content: [{ text: "Error: Not authenticated. Please authenticate with GitHub first.", type: "text" }],
						isError: true,
					};
				}
				try {
					const octokit = new Octokit({ auth: this.props.accessToken });
					return {
						content: [
							{
								text: JSON.stringify(await octokit.rest.users.getAuthenticated()),
								type: "text",
							},
						],
					};
				} catch (error: any) {
					return {
						content: [{ text: `Error fetching user info: ${error.message}`, type: "text" }],
						isError: true,
					};
				}
			},
		);

		// Dynamically add tools based on the user's login. In this case, I want to limit
		// access to my Image Generation tool to just me
		if (this.props?.login && ALLOWED_USERNAMES.has(this.props.login)) {
			this.server.registerTool(
				"generateImage",
				{
					title: "Generate Image (Flux)",
					description:
						"Generate an image using the flux-1-schnell model. Works best with 8 steps. Restricted to allowed GitHub users.",
					inputSchema: {
						prompt: z
							.string()
							.describe("A text description of the image you want to generate."),
						steps: z
							.number()
							.min(4)
							.max(8)
							.default(4)
							.describe(
								"The number of diffusion steps; higher values can improve quality but take longer. Must be between 4 and 8, inclusive.",
							),
					},
					annotations: { title: "Generate Image (Flux)", ...WRITE_OPENWORLD },
				},
				async ({ prompt, steps }) => {
					try {
						const response = await this.env.AI.run("@cf/black-forest-labs/flux-1-schnell", {
							prompt,
							steps,
						});

						if (!response.image) {
							return {
								content: [{ text: "Error: AI model failed to generate an image.", type: "text" }],
								isError: true,
							};
						}

						return {
							content: [{ data: response.image, mimeType: "image/jpeg", type: "image" }],
						};
					} catch (error: any) {
						return {
							content: [{ text: `Error generating image: ${error.message}`, type: "text" }],
							isError: true,
						};
					}
				},
			);
		}
	}
}

export default new OAuthProvider({
	// NOTE - during the summer 2025, the SSE protocol was deprecated and replaced by the Streamable-HTTP protocol
	// https://developers.cloudflare.com/agents/model-context-protocol/transport/#mcp-server-with-authentication
	apiHandlers: {
		"/sse": MyMCP.serveSSE("/sse"), // deprecated SSE protocol - use /mcp instead
		"/mcp": MyMCP.serve("/mcp"), // Streamable-HTTP protocol
	},
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: GitHubHandler as any,
	tokenEndpoint: "/token",
});
