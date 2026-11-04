import { describe, expect, it } from 'vitest';
import { hasVulnersLink } from '../../lib/hasVulnersLink';
import { stripHtmlTags } from '../../lib/stripHtmlTags';

describe('stripHtmlTags', () => {
  it('removes tags and decodes entities', () => {
    expect(stripHtmlTags('<p>a&nbsp;&amp;&nbsp;b</p>')).toBe('a & b');
    expect(stripHtmlTags('&lt;tag&gt;')).toBe('<tag>');
  });
  it('removes tags formed by an earlier removal', () => {
    expect(stripHtmlTags('<<b>script>x')).not.toContain('<script');
  });
  it('does not double-decode', () => {
    expect(stripHtmlTags('&amp;lt;')).toBe('&lt;');
  });
});

describe('hasVulnersLink', () => {
  it('accepts vulners.com links', () => {
    expect(hasVulnersLink('CVE-2021-1 7.5 https://vulners.com/cve/CVE-2021-1')).toBe(true);
    expect(hasVulnersLink('EDB-1 https://www.vulners.com/x')).toBe(true);
  });
  it('rejects look-alike hosts and plain mentions', () => {
    expect(hasVulnersLink('https://vulners.com.evil.test/a')).toBe(false);
    expect(hasVulnersLink('https://evil.test/vulners.com')).toBe(false);
    expect(hasVulnersLink('see vulners.com')).toBe(false);
  });
});
