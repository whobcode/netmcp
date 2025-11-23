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

const ALLOWED_USERNAMES = new Set<string>([
	// Add GitHub usernames of users who should have access to the image generation tool
	// For example: 'yourusername', 'coworkerusername'
	'whobcode'
]);

export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "Github OAuth Proxy Demo",
		version: "1.0.0",
	});

	async init() {
		// Load ExploitDB dataset if available
		if (EXPLOITDB_DATASET_BASE64 && !isDatasetLoaded()) {
			try {
				await loadDataset(EXPLOITDB_DATASET_BASE64);
				console.log("ExploitDB dataset loaded successfully");
			} catch (error) {
				console.error("Failed to load ExploitDB dataset:", error);
			}
		}

		// Register external API tools (security research, OSINT, vulnerability intelligence)
		registerExternalApiTools(this.server, this.env);

		// Register ExploitDB tools
		registerExploitDbTools(this.server);

		// Hello, world!
		this.server.tool(
			"add",
			"Add two numbers the way only MCP can",
			{ a: z.number(), b: z.number() },
			async ({ a, b }) => ({
				content: [{ text: String(a + b), type: "text" }],
			}),
		);

		// Use the upstream access token to facilitate tools
		this.server.tool(
			"userInfoOctokit",
			"Get user info from GitHub, via Octokit",
			{},
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
			this.server.tool(
				"generateImage",
				"Generate an image using the `flux-1-schnell` model. Works best with 8 steps.",
				{
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
