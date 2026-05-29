// src/tool-registry.ts
//
// A module-scoped registry that captures MCP tool registrations so the
// REST `/run` shim (used by iOS Shortcuts and any other plain HTTP client)
// can dispatch to them without going through the MCP/OAuth handshake.
//
// It mirrors the MODERN `McpServer.registerTool(name, config, handler)` API
// (config object with title/description/inputSchema/annotations). Both the
// real McpServer (inside MyMCP) and this registry satisfy the `ToolHost`
// interface, so the `register*Tools(host, ...)` functions are written once
// against `ToolHost` and work with either target.

import type { ZodRawShape } from "zod";

export type ToolContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string }
  | { type: string; [k: string]: unknown };

export type ToolResult = {
  content: ToolContent[];
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
};

export type ToolHandler = (args: Record<string, any>) => Promise<ToolResult> | ToolResult;

/** MCP tool annotations (hints clients use to reason about tool behavior). */
export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/** Config object passed to registerTool — matches the modern SDK shape. */
export interface ToolConfig {
  title?: string;
  description: string;
  inputSchema?: ZodRawShape;
  outputSchema?: ZodRawShape;
  annotations?: ToolAnnotations;
}

export interface RegisteredTool {
  name: string;
  config: ToolConfig;
  handler: ToolHandler;
}

/**
 * Minimal structural type satisfied by BOTH `McpServer` and `ToolRegistry`.
 * `register*Tools()` functions accept this so they're decoupled from the
 * SDK's strict generics while still using the modern registerTool signature.
 */
export interface ToolHost {
  registerTool(name: string, config: ToolConfig, handler: ToolHandler): unknown;
}

export class ToolRegistry implements ToolHost {
  private tools = new Map<string, RegisteredTool>();

  /**
   * Mirrors `McpServer.registerTool()`. Last write wins, matching MCP
   * server behavior.
   */
  registerTool(name: string, config: ToolConfig, handler: ToolHandler): void {
    this.tools.set(name, { name, config, handler });
  }

  get(name: string): RegisteredTool | undefined {
    return this.tools.get(name);
  }

  list(): Array<{ name: string; title?: string; description: string }> {
    return Array.from(this.tools.values()).map((t) => ({
      name: t.name,
      title: t.config.title,
      description: t.config.description,
    }));
  }

  size(): number {
    return this.tools.size;
  }
}
