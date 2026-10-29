/** Timeout and retry literal constants (no env). */

export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_MAX_RETRIES = 3;
export const DEFAULT_INITIAL_DELAY_MS = 100;
export const DEFAULT_MAX_DELAY_MS = 5000;

/** Timeout (ms) for domain-reputation provider lookup calls (VirusTotal/AbuseIPDB "check" requests). */
export const DOMAIN_REPUTATION_CHECK_TIMEOUT_MS = 20_000;

/** Timeout (ms) for domain-reputation provider API key validation ("test connection") calls. */
export const DOMAIN_REPUTATION_TEST_TIMEOUT_MS = 10_000;

/** How long (ms) a cached third-party provider config (e.g. domain-reputation) is reused before being refetched. */
export const CONFIG_CACHE_TTL_MS = 60_000;

/** Timeout (ms) for slower external API calls (AI provider chat completions, scanner GMP commands/exports). */
export const EXTERNAL_API_TIMEOUT_MS = 120_000;

/** Timeout (ms) for spawning a local external command-line binary (openssl, nuclei, ...). */
export const EXTERNAL_COMMAND_TIMEOUT_MS = 10_000;
