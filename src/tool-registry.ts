// src/tool-registry.ts
//
// A module-scoped registry that captures MCP tool registrations so the
// REST `/run` shim (used by iOS Shortcuts and any other plain HTTP client)
// can dispatch to them without going through the MCP/OAuth handshake.
//
// The class duck-types the subset of `McpServer` that the various
// `register*Tools(server, ...)` functions in this repo actually use —
// just `.tool(name, description, schema, handler)`. That means we can
// pass a `ToolRegistry` anywhere an `McpServer` is expected without
// changing the tool registration files.

import type { ZodRawShape } from "zod";

export type ToolContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string }
  | { type: string; [k: string]: unknown };

export type ToolResult = {
  content: ToolContent[];
  isError?: boolean;
};

export type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;

export interface RegisteredTool {
  name: string;
  description: string;
  schema: ZodRawShape;
  handler: ToolHandler;
}

export class ToolRegistry {
  private tools = new Map<string, RegisteredTool>();

  /**
   * Mirrors `McpServer.tool()` so existing `register*Tools(server, ...)`
   * functions can be called with a ToolRegistry instead. Last write wins,
   * matching MCP server behavior.
   */
  tool(
    name: string,
    description: string,
    schema: ZodRawShape,
    handler: ToolHandler,
  ): void {
    this.tools.set(name, { name, description, schema, handler });
  }

  get(name: string): RegisteredTool | undefined {
    return this.tools.get(name);
  }

  list(): Array<{ name: string; description: string }> {
    return Array.from(this.tools.values()).map((t) => ({
      name: t.name,
      description: t.description,
    }));
  }

  size(): number {
    return this.tools.size;
  }
}

/**
 * Wraps a real McpServer so every `.tool()` call is also recorded into
 * the given registry. Use this inside `MyMCP.init()` when you want
 * registrations to fan out to BOTH the MCP server (for /mcp + /sse
 * clients) AND the module-scope registry (for /run).
 */
export function fanout(
  server: { tool: (...args: unknown[]) => unknown },
  registry: ToolRegistry,
): { tool: ToolRegistry["tool"] } {
  return {
    tool(name, description, schema, handler) {
      registry.tool(name, description, schema, handler);
      (server.tool as (
        name: string,
        description: string,
        schema: ZodRawShape,
        handler: ToolHandler,
      ) => unknown)(name, description, schema, handler);
    },
  };
}
