/** Rate limiter literal constants (no env). */

export const RATE_LIMIT_WINDOW_MS_15MIN = 15 * 60 * 1000;
export const RATE_LIMIT_WINDOW_MS_1MIN = 1 * 60 * 1000;

/** Auth bruteforce */
export const RATE_LIMIT_MAX_LOGIN = 10; // per IP per 15 min
export const RATE_LIMIT_MAX_LOGIN_EMAIL = 10; // per normalized email per 15 min
export const RATE_LIMIT_MAX_REGISTER_IP = 10; // per IP per 15 min
export const RATE_LIMIT_MAX_REGISTER_EMAIL = 5; // per normalized email per 15 min

export const RATE_LIMIT_MAX_PASSWORD_UPDATE = 50;
export const RATE_LIMIT_MAX_PROFILE_UPDATE = 5;
export const RATE_LIMIT_MAX_SESSION_STATUS = 60;

/** Data API rate limits */
export const RATE_LIMIT_MAX_API_DATA = 200;       // General data queries per minute (keyed per-user when authenticated)
export const RATE_LIMIT_MAX_API_EXPORT = 20;     // Export endpoints per 15 min (keyed per-user when authenticated)
export const RATE_LIMIT_MAX_API_MUTATION = 60;   // Mutation (update/rename) per 15 min (keyed per-user when authenticated)

// Every panel/refresh tick on an embedded Grafana dashboard triggers its own
// nginx auth_request sub-request to this endpoint, so a single dashboard view
// can legitimately fire far more of these per minute than a normal API read —
// keyed by IP since identity isn't resolved yet at this point.
export const RATE_LIMIT_MAX_GRAFANA_VALIDATE = 600;
