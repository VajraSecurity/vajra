/**
 * Drop-in console.log replacement that's a no-op outside dev builds.
 * Use for verbose/internal tracing (state dumps, fetched payloads) that
 * shouldn't reach a production browser console — especially where the data
 * involved is security- or compliance-sensitive (device posture, telemetry).
 * Genuine failures should still use console.error/warn directly so they
 * remain visible in production for diagnosing real user-reported issues.
 */
export const debugLog: (...args: unknown[]) => void = import.meta.env.DEV
  ? (...args) => console.log(...args)
  : () => {};
