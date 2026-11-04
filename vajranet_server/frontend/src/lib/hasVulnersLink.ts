const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;

/** True when an nmap detail line links to vulners.com, checked by hostname rather than substring. */
export const hasVulnersLink = (detail: string): boolean =>
  (detail.match(URL_PATTERN) ?? []).some((candidate) => {
    try {
      const { hostname } = new URL(candidate);
      return hostname === 'vulners.com' || hostname.endsWith('.vulners.com');
    } catch {
      return false;
    }
  });
