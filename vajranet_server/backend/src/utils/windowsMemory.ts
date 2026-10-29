/**
 * Windows agents may persist memory metrics in kilobytes (same scale as
 * GetPhysicallyInstalledSystemMemory / some osquery paths) while Linux uses bytes.
 * Values below this threshold cannot be total physical RAM expressed in bytes — treat as KB.
 */
export const WINDOWS_MEMORY_RAW_LIKELY_KILOBYTES_BELOW_BYTES = 64 * 1024 * 1024;

export function isWindowsPlatform(osPlatform: string | undefined | null): boolean {
  return (osPlatform || '').toLowerCase().includes('windows');
}

/** Convert a stored memory_info / hardware counter to bytes when Windows data is in KB. */
export function normalizeWindowsMemoryMetricToBytes(raw: number): number {
  if (!Number.isFinite(raw) || raw <= 0) return raw;
  if (raw < WINDOWS_MEMORY_RAW_LIKELY_KILOBYTES_BELOW_BYTES) {
    return Math.round(raw * 1024);
  }
  return raw;
}
