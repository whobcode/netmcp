// src/tool-helpers.ts
//
// Shared helpers for MCP tool implementations. Centralizes the patterns the
// MCP best-practices guide asks for so individual tools don't duplicate them:
//   - dual response formats (human Markdown / machine JSON)
//   - structuredContent (the modern structured-output pattern)
//   - response truncation against a CHARACTER_LIMIT
//   - actionable, status-mapped error messages
//   - reusable tool annotations
//
// Keeping these here is also what the guide means by "composability / no
// duplication" — every register*Tools file imports from this one module.

import { z } from "zod";

/** Maximum characters returned in a tool's text content before truncation. */
export const CHARACTER_LIMIT = 25000;

/** Output format selector shared by all data-returning tools. */
export enum ResponseFormat {
  MARKDOWN = "markdown",
  JSON = "json",
}

/**
 * Spreadable Zod field. Add `...responseFormatField` to a tool's inputSchema
 * to give it a standard `response_format` parameter with consistent docs.
 */
export const responseFormatField = {
  response_format: z
    .nativeEnum(ResponseFormat)
    .optional()
    .default(ResponseFormat.MARKDOWN)
    .describe(
      "Output format: 'markdown' for human-readable (default) or 'json' for machine-readable structured data",
    ),
};

type TextContent = { type: "text"; text: string };
type AnyContent = TextContent | { type: string; [k: string]: unknown };

export interface ToolResultShape {
  content: AnyContent[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/**
 * Build a tool result that honors the requested response_format, attaches
 * machine-readable structuredContent, and truncates oversized text so a single
 * call can't blow out the model's context window.
 */
export function formatToolResult(
  format: ResponseFormat | undefined,
  data: { markdown: string; structured: Record<string, unknown> },
): ToolResultShape {
  const fmt = format ?? ResponseFormat.MARKDOWN;
  let text =
    fmt === ResponseFormat.JSON
      ? JSON.stringify(data.structured, null, 2)
      : data.markdown;

  let structured = data.structured;
  if (text.length > CHARACTER_LIMIT) {
    const note =
      `\n\n[Truncated at ${CHARACTER_LIMIT} characters. ` +
      `Narrow the query or use 'limit'/'offset' to reduce output.]`;
    text = text.slice(0, Math.max(0, CHARACTER_LIMIT - note.length)) + note;
    structured = { ...structured, truncated: true };
  }

  return {
    content: [{ type: "text", text }],
    structuredContent: structured,
  };
}

/**
 * Standard error result. MCP guidance: report tool errors in-band on the
 * result object (isError) rather than throwing protocol-level errors.
 */
export function toolError(message: string): ToolResultShape {
  return { content: [{ type: "text", text: message }], isError: true };
}

/** Error carrying an HTTP status, thrown by fetch helpers on non-2xx. */
export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

/**
 * Map any caught error to a clear, actionable message with a suggested next
 * step. Pass `hint` to tack on a tool-specific suggestion.
 */
export function describeError(error: unknown, context: string, hint?: string): string {
  const tail = hint ? ` ${hint}` : "";
  if (error instanceof HttpError) {
    switch (error.status) {
      case 400:
        return `Error: ${context} — bad request (400). Check your parameters.${tail}`;
      case 401:
        return `Error: ${context} — authentication failed (401). Check the API key/secret.${tail}`;
      case 403:
        return `Error: ${context} — permission denied (403). Your key may lack access or quota.${tail}`;
      case 404:
        return `Error: ${context} — not found (404). Check the identifier.${tail}`;
      case 429:
        return `Error: ${context} — rate limit exceeded (429). Wait and retry.${tail}`;
      default:
        return `Error: ${context} — request failed (HTTP ${error.status}).${tail}`;
    }
  }
  const msg = error instanceof Error ? error.message : String(error);
  return `Error: ${context} — ${msg}.${tail}`;
}

/** Annotation preset: read-only tool that reaches an external service. */
export const READONLY_OPENWORLD = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

/** Annotation preset: read-only tool over local/bundled data only. */
export const READONLY_LOCAL = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

/** Annotation preset: non-destructive tool that creates new output (e.g. image gen). */
export const WRITE_OPENWORLD = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;
