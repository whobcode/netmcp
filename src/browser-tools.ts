/**
 * Browser Tools Module
 *
 * Provides browser automation capabilities using Cloudflare's Playwright fork
 * and the Browser Rendering API.
 *
 * Tools:
 * - browser_screenshot: Take screenshots of web pages
 * - browser_get_content: Get HTML content or text from a page
 * - browser_get_markdown: Convert a web page to markdown
 * - browser_pdf: Generate PDF from a web page
 * - browser_scrape: Scrape specific elements from a page
 * - browser_execute_script: Execute JavaScript on a page and return results
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { launch, type BrowserContextOptions } from "@cloudflare/playwright";

// Type for the browser binding from Cloudflare
type BrowserBinding = Parameters<typeof launch>[0];

/**
 * Register all browser automation tools with the MCP server
 */
export function registerBrowserTools(server: McpServer, browserBinding: BrowserBinding) {
  /**
   * Take a screenshot of a web page
   */
  server.tool(
    "browser_screenshot",
    "Take a screenshot of a web page. Returns the image as base64-encoded PNG/JPEG.",
    {
      url: z.string().url().describe("The URL of the page to screenshot"),
      fullPage: z.boolean().optional().default(false).describe("Whether to capture the full scrollable page"),
      width: z.number().optional().default(1280).describe("Viewport width in pixels"),
      height: z.number().optional().default(720).describe("Viewport height in pixels"),
      format: z.enum(["png", "jpeg"]).optional().default("png").describe("Image format"),
      quality: z.number().min(0).max(100).optional().describe("JPEG quality (0-100), only for jpeg format"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
      selector: z.string().optional().describe("CSS selector to screenshot a specific element instead of the page"),
    },
    async ({ url, fullPage, width, height, format, quality, waitUntil, selector }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext({
          viewport: { width, height },
        });
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        let screenshotBuffer: Buffer;
        const screenshotOptions: any = {
          type: format,
          fullPage: selector ? false : fullPage,
        };

        if (format === "jpeg" && quality !== undefined) {
          screenshotOptions.quality = quality;
        }

        if (selector) {
          const element = await page.$(selector);
          if (!element) {
            return {
              content: [{ type: "text", text: `Error: Element not found with selector: ${selector}` }],
              isError: true,
            };
          }
          screenshotBuffer = await element.screenshot(screenshotOptions);
        } else {
          screenshotBuffer = await page.screenshot(screenshotOptions);
        }

        const base64Image = screenshotBuffer.toString("base64");
        const mimeType = format === "jpeg" ? "image/jpeg" : "image/png";

        return {
          content: [
            {
              type: "image",
              data: base64Image,
              mimeType,
            },
          ],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error taking screenshot: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Get HTML content or text from a web page
   */
  server.tool(
    "browser_get_content",
    "Get HTML content or extracted text from a web page after JavaScript rendering.",
    {
      url: z.string().url().describe("The URL of the page to fetch"),
      contentType: z.enum(["html", "text"]).optional().default("html").describe("Whether to return raw HTML or extracted text"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
      selector: z.string().optional().describe("CSS selector to extract content from a specific element"),
      waitForSelector: z.string().optional().describe("Wait for this selector to appear before extracting content"),
      timeout: z.number().optional().default(30000).describe("Timeout in milliseconds for page load"),
    },
    async ({ url, contentType, waitUntil, selector, waitForSelector, timeout }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil, timeout });

        if (waitForSelector) {
          await page.waitForSelector(waitForSelector, { timeout });
        }

        let content: string;

        if (selector) {
          const element = await page.$(selector);
          if (!element) {
            return {
              content: [{ type: "text", text: `Error: Element not found with selector: ${selector}` }],
              isError: true,
            };
          }
          content = contentType === "html"
            ? await element.innerHTML()
            : await element.innerText();
        } else {
          content = contentType === "html"
            ? await page.content()
            : await page.innerText("body");
        }

        return {
          content: [{ type: "text", text: content }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error fetching content: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Convert a web page to markdown
   */
  server.tool(
    "browser_get_markdown",
    "Fetch a web page and convert its content to markdown format. Useful for reading articles and documentation.",
    {
      url: z.string().url().describe("The URL of the page to convert to markdown"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("networkidle").describe("When to consider navigation complete"),
      selector: z.string().optional().describe("CSS selector to convert only a specific element"),
      includeLinks: z.boolean().optional().default(true).describe("Whether to include links in the markdown"),
    },
    async ({ url, waitUntil, selector, includeLinks }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        // Get the content to convert
        const markdown = await page.evaluate(({ selector, includeLinks }) => {
          function htmlToMarkdown(element: Element, includeLinks: boolean): string {
            let result = "";

            function processNode(node: Node): string {
              if (node.nodeType === Node.TEXT_NODE) {
                return node.textContent?.replace(/\s+/g, " ") || "";
              }

              if (node.nodeType !== Node.ELEMENT_NODE) {
                return "";
              }

              const el = node as Element;
              const tagName = el.tagName.toLowerCase();

              // Skip script, style, nav, footer, etc.
              if (["script", "style", "nav", "footer", "header", "aside", "noscript"].includes(tagName)) {
                return "";
              }

              let childContent = "";
              for (const child of Array.from(node.childNodes)) {
                childContent += processNode(child);
              }

              switch (tagName) {
                case "h1":
                  return `\n# ${childContent.trim()}\n\n`;
                case "h2":
                  return `\n## ${childContent.trim()}\n\n`;
                case "h3":
                  return `\n### ${childContent.trim()}\n\n`;
                case "h4":
                  return `\n#### ${childContent.trim()}\n\n`;
                case "h5":
                  return `\n##### ${childContent.trim()}\n\n`;
                case "h6":
                  return `\n###### ${childContent.trim()}\n\n`;
                case "p":
                  return `\n${childContent.trim()}\n\n`;
                case "br":
                  return "\n";
                case "strong":
                case "b":
                  return `**${childContent.trim()}**`;
                case "em":
                case "i":
                  return `*${childContent.trim()}*`;
                case "code":
                  return `\`${childContent.trim()}\``;
                case "pre":
                  return `\n\`\`\`\n${childContent.trim()}\n\`\`\`\n\n`;
                case "blockquote":
                  return `\n> ${childContent.trim().replace(/\n/g, "\n> ")}\n\n`;
                case "ul":
                  return `\n${childContent}\n`;
                case "ol":
                  return `\n${childContent}\n`;
                case "li":
                  return `- ${childContent.trim()}\n`;
                case "a":
                  if (includeLinks) {
                    const href = el.getAttribute("href");
                    if (href && !href.startsWith("#") && !href.startsWith("javascript:")) {
                      return `[${childContent.trim()}](${href})`;
                    }
                  }
                  return childContent;
                case "img":
                  const alt = el.getAttribute("alt") || "image";
                  const src = el.getAttribute("src");
                  return src ? `![${alt}](${src})` : "";
                case "hr":
                  return "\n---\n\n";
                case "div":
                case "section":
                case "article":
                case "main":
                  return childContent + "\n";
                default:
                  return childContent;
              }
            }

            result = processNode(element);
            // Clean up multiple newlines
            return result.replace(/\n{3,}/g, "\n\n").trim();
          }

          const targetElement = selector
            ? document.querySelector(selector)
            : document.querySelector("article") || document.querySelector("main") || document.body;

          if (!targetElement) {
            return "Error: Could not find content element";
          }

          return htmlToMarkdown(targetElement, includeLinks);
        }, { selector, includeLinks });

        return {
          content: [{ type: "text", text: markdown }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error converting to markdown: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Generate PDF from a web page
   */
  server.tool(
    "browser_pdf",
    "Generate a PDF from a web page. Returns the PDF as base64-encoded data.",
    {
      url: z.string().url().describe("The URL of the page to convert to PDF"),
      format: z.enum(["Letter", "Legal", "Tabloid", "Ledger", "A0", "A1", "A2", "A3", "A4", "A5", "A6"]).optional().default("A4").describe("Paper format"),
      landscape: z.boolean().optional().default(false).describe("Whether to use landscape orientation"),
      printBackground: z.boolean().optional().default(true).describe("Whether to print background graphics"),
      scale: z.number().min(0.1).max(2).optional().default(1).describe("Scale of the webpage rendering"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("networkidle").describe("When to consider navigation complete"),
    },
    async ({ url, format, landscape, printBackground, scale, waitUntil }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        const pdfBuffer = await page.pdf({
          format,
          landscape,
          printBackground,
          scale,
        });

        const base64Pdf = pdfBuffer.toString("base64");

        return {
          content: [
            { type: "text", text: `PDF generated successfully (${Math.round(pdfBuffer.length / 1024)} KB)` },
            { type: "resource", resource: { uri: `data:application/pdf;base64,${base64Pdf}`, mimeType: "application/pdf", text: base64Pdf } },
          ],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error generating PDF: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Scrape specific elements from a page
   */
  server.tool(
    "browser_scrape",
    "Scrape specific elements from a web page using CSS selectors. Returns structured data.",
    {
      url: z.string().url().describe("The URL of the page to scrape"),
      selectors: z.record(z.string()).describe("Object mapping field names to CSS selectors, e.g., {\"title\": \"h1\", \"price\": \".price\"}"),
      multiple: z.boolean().optional().default(false).describe("Whether to return multiple matches for each selector"),
      attributes: z.array(z.string()).optional().describe("HTML attributes to extract (e.g., ['href', 'src']). If not specified, extracts text content."),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
      waitForSelector: z.string().optional().describe("Wait for this selector to appear before scraping"),
    },
    async ({ url, selectors, multiple, attributes, waitUntil, waitForSelector }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        if (waitForSelector) {
          await page.waitForSelector(waitForSelector);
        }

        const results = await page.evaluate(({ selectors, multiple, attributes }) => {
          const data: Record<string, any> = {};

          for (const [field, selector] of Object.entries(selectors)) {
            const elements = multiple
              ? Array.from(document.querySelectorAll(selector))
              : [document.querySelector(selector)].filter(Boolean);

            const values = elements.map(el => {
              if (!el) return null;

              if (attributes && attributes.length > 0) {
                const attrData: Record<string, string | null> = {};
                for (const attr of attributes) {
                  attrData[attr] = el.getAttribute(attr);
                }
                attrData.text = el.textContent?.trim() || "";
                return attrData;
              }

              return el.textContent?.trim() || "";
            });

            data[field] = multiple ? values : (values[0] || null);
          }

          return data;
        }, { selectors, multiple, attributes });

        return {
          content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error scraping page: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Execute JavaScript on a page and return results
   */
  server.tool(
    "browser_execute_script",
    "Execute JavaScript code on a web page and return the result. Useful for extracting data or interacting with the page.",
    {
      url: z.string().url().describe("The URL of the page to execute script on"),
      script: z.string().describe("JavaScript code to execute. Must return a serializable value."),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
      waitForSelector: z.string().optional().describe("Wait for this selector to appear before executing script"),
    },
    async ({ url, script, waitUntil, waitForSelector }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        if (waitForSelector) {
          await page.waitForSelector(waitForSelector);
        }

        // Execute the user's script
        const result = await page.evaluate(script);

        const resultText = typeof result === "object"
          ? JSON.stringify(result, null, 2)
          : String(result);

        return {
          content: [{ type: "text", text: resultText }],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error executing script: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Get all links from a page
   */
  server.tool(
    "browser_get_links",
    "Extract all links from a web page. Useful for crawling and discovering related pages.",
    {
      url: z.string().url().describe("The URL of the page to extract links from"),
      selector: z.string().optional().describe("CSS selector to limit link extraction to a specific area"),
      includeExternal: z.boolean().optional().default(true).describe("Whether to include external links"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
    },
    async ({ url, selector, includeExternal, waitUntil }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        const baseUrl = new URL(url);

        const links = await page.evaluate(({ selector, includeExternal, baseHost }) => {
          const container = selector ? document.querySelector(selector) : document;
          if (!container) return [];

          const anchors = container.querySelectorAll("a[href]");
          const linkData: Array<{ href: string; text: string; isExternal: boolean }> = [];
          const seen = new Set<string>();

          for (const anchor of Array.from(anchors)) {
            const href = anchor.getAttribute("href");
            if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) {
              continue;
            }

            let absoluteUrl: string;
            try {
              absoluteUrl = new URL(href, window.location.href).href;
            } catch {
              continue;
            }

            if (seen.has(absoluteUrl)) continue;
            seen.add(absoluteUrl);

            const isExternal = !absoluteUrl.includes(baseHost);

            if (!includeExternal && isExternal) continue;

            linkData.push({
              href: absoluteUrl,
              text: anchor.textContent?.trim() || "",
              isExternal,
            });
          }

          return linkData;
        }, { selector, includeExternal, baseHost: baseUrl.host });

        return {
          content: [
            { type: "text", text: `Found ${links.length} links:\n\n${JSON.stringify(links, null, 2)}` },
          ],
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error extracting links: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Fill and submit a form
   */
  server.tool(
    "browser_fill_form",
    "Fill out and optionally submit a form on a web page. Useful for login forms, search forms, etc.",
    {
      url: z.string().url().describe("The URL of the page containing the form"),
      fields: z.record(z.string()).describe("Object mapping CSS selectors to values to fill, e.g., {\"#username\": \"user\", \"#password\": \"pass\"}"),
      submitSelector: z.string().optional().describe("CSS selector for the submit button. If provided, will click to submit."),
      waitAfterSubmit: z.number().optional().default(2000).describe("Milliseconds to wait after submitting"),
      screenshotAfter: z.boolean().optional().default(false).describe("Whether to take a screenshot after submission"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
    },
    async ({ url, fields, submitSelector, waitAfterSubmit, screenshotAfter, waitUntil }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        // Fill in each field
        for (const [selector, value] of Object.entries(fields)) {
          await page.fill(selector, value);
        }

        let result = `Filled ${Object.keys(fields).length} field(s)`;

        // Submit if selector provided
        if (submitSelector) {
          await page.click(submitSelector);
          await page.waitForTimeout(waitAfterSubmit);
          result += `\nClicked submit button (${submitSelector})`;
          result += `\nCurrent URL: ${page.url()}`;
        }

        const content: any[] = [{ type: "text", text: result }];

        // Take screenshot if requested
        if (screenshotAfter) {
          const screenshotBuffer = await page.screenshot({ type: "png" });
          content.push({
            type: "image",
            data: screenshotBuffer.toString("base64"),
            mimeType: "image/png",
          });
        }

        return { content };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error filling form: ${error.message}` }],
          isError: true,
        };
      }
    }
  );

  /**
   * Click an element and optionally wait for navigation
   */
  server.tool(
    "browser_click",
    "Click an element on a web page and optionally wait for navigation. Returns the new page content or a screenshot.",
    {
      url: z.string().url().describe("The URL of the page"),
      selector: z.string().describe("CSS selector of the element to click"),
      waitForNavigation: z.boolean().optional().default(false).describe("Whether to wait for page navigation after click"),
      waitForSelector: z.string().optional().describe("Wait for this selector to appear after clicking"),
      screenshot: z.boolean().optional().default(false).describe("Whether to return a screenshot after clicking"),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).optional().default("load").describe("When to consider navigation complete"),
    },
    async ({ url, selector, waitForNavigation, waitForSelector: waitForSelectorAfter, screenshot, waitUntil }) => {
      try {
        await using browser = await launch(browserBinding);
        await using context = await browser.newContext();
        await using page = await context.newPage();

        await page.goto(url, { waitUntil });

        if (waitForNavigation) {
          await Promise.all([
            page.waitForNavigation({ waitUntil }),
            page.click(selector),
          ]);
        } else {
          await page.click(selector);
        }

        if (waitForSelectorAfter) {
          await page.waitForSelector(waitForSelectorAfter);
        }

        const content: any[] = [
          { type: "text", text: `Clicked element: ${selector}\nCurrent URL: ${page.url()}` },
        ];

        if (screenshot) {
          const screenshotBuffer = await page.screenshot({ type: "png" });
          content.push({
            type: "image",
            data: screenshotBuffer.toString("base64"),
            mimeType: "image/png",
          });
        }

        return { content };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error clicking element: ${error.message}` }],
          isError: true,
        };
      }
    }
  );
}
