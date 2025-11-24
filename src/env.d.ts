// Additional environment variable types for secrets
// This file won't be overwritten by `wrangler types`

declare namespace Cloudflare {
  interface Env {
    // Required secrets (set via wrangler secret put)
    COOKIE_ENCRYPTION_KEY: string;

    // Browser Rendering binding (configured in wrangler.jsonc)
    BROWSER: Fetcher;

    // External API tool secrets (all optional)
    NVD_API_KEY?: string;
    GITHUB_TOKEN?: string;
    GITLAB_TOKEN?: string;
    SHODAN_API_KEY?: string;
    CENSYS_API_ID?: string;
    CENSYS_API_SECRET?: string;
    SECURITYTRAILS_API_KEY?: string;
  }
}
