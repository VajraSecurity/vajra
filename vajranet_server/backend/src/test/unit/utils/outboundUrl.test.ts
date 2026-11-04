import axios from 'axios';
import { promises as dns } from 'dns';
import * as http from 'http';
import type { AddressInfo } from 'net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  assertAllowedServiceUrl,
  canonicalizeHttpUrl,
  createGuardedServiceHttpsAgent,
  guardedServiceHttpAgent,
  OutboundUrlError,
  scannerTlsOptions,
} from '../../../utils/outboundUrl';

describe('canonicalizeHttpUrl', () => {
  it.each([
    ['https://scanner.example.com', 'https://scanner.example.com'],
    ['https://scanner.example.com/', 'https://scanner.example.com'],
    ['  https://scanner.example.com:8834///  ', 'https://scanner.example.com:8834'],
    ['HTTP://SCANNER.example.com:8080/api/', 'http://scanner.example.com:8080/api'],
    ['https://10.0.5.187', 'https://10.0.5.187'],
    ['https://[fd12:3456::1]:8834', 'https://[fd12:3456::1]:8834'],
    ['https://host/a%20b/c%2Fd', 'https://host/a%20b/c%2Fd'],
  ])('keeps %s working as %s', (input, expected) => {
    expect(canonicalizeHttpUrl(input)).toBe(expected);
  });

  it('collapses alternate spellings to the address that gets checked', () => {
    expect(canonicalizeHttpUrl('http://2130706433')).toBe('http://127.0.0.1');
    expect(canonicalizeHttpUrl('http://0x7f.1')).toBe('http://127.0.0.1');
    expect(canonicalizeHttpUrl('https://evil.example\\@good.example')).toBe('https://evil.example/%40good.example');
  });

  it.each([
    ['ftp://host'],
    ['file:///etc/passwd'],
    ['gopher://host'],
    ['not a url'],
    ['https://user:pass@host'],
    ['https://good.example@evil.example'],
    ['https://host/?x=1'],
    ['https://host/#frag'],
    ['https://host/%zz'],
  ])('rejects %s', (input) => {
    expect(() => canonicalizeHttpUrl(input)).toThrow(OutboundUrlError);
  });

  it.each([[undefined], [null], [42], [['https://host']], [{ href: 'https://host' }]])('rejects non-string %j', (input) => {
    expect(() => canonicalizeHttpUrl(input)).toThrow(OutboundUrlError);
  });
});

describe('assertAllowedServiceUrl', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.ALLOW_LOOPBACK_SERVICE_URL;
  });

  it.each([
    ['https://10.0.5.187', 'https://10.0.5.187'],
    ['https://172.16.0.9:8834/', 'https://172.16.0.9:8834'],
    ['https://192.168.1.50:8834', 'https://192.168.1.50:8834'],
    ['https://100.64.0.1', 'https://100.64.0.1'],
    ['https://[fd12:3456::1]:8834', 'https://[fd12:3456::1]:8834'],
    ['https://8.8.8.8', 'https://8.8.8.8'],
  ])('accepts %s', async (input, expected) => {
    await expect(assertAllowedServiceUrl(input)).resolves.toBe(expected);
  });

  it.each([
    ['http://127.0.0.1:6379'],
    ['http://2130706433'],
    ['http://0x7f.1'],
    ['http://[::1]'],
    ['http://[::ffff:7f00:1]'],
    ['http://169.254.169.254/latest/meta-data'],
    ['http://[::ffff:a9fe:a9fe]'],
    ['http://[64:ff9b::a9fe:a9fe]'],
    ['http://[fe80::1]'],
    ['http://0.0.0.0'],
    ['http://192.0.2.1'],
    ['http://100.100.100.200'],
    ['http://168.63.129.16'],
    ['http://[fd00:ec2::254]'],
    ['http://[64:ff9b::a83f:8110]'],
    ['http://[64:ff9b::6464:64c8]'],
    ['http://[64:ff9b:1::a83f:8110]'],
    ['http://[::ffff:a83f:8110]'],
    ['http://[::ffff:6464:64c8]'],
  ])('refuses %s', async (input) => {
    await expect(assertAllowedServiceUrl(input)).rejects.toThrow(/Refusing to contact/);
  });

  it('refuses a hostname if any address it resolves to is reserved', async () => {
    const lookup = vi.spyOn(dns, 'lookup') as unknown as ReturnType<typeof vi.fn>;
    lookup.mockResolvedValue([{ address: '8.8.8.8', family: 4 }, { address: '169.254.169.254', family: 4 }]);
    await expect(assertAllowedServiceUrl('https://rebind.example')).rejects.toThrow(/169\.254\.169\.254/);
  });

  it('accepts a hostname that resolves to an internal network', async () => {
    const lookup = vi.spyOn(dns, 'lookup') as unknown as ReturnType<typeof vi.fn>;
    lookup.mockResolvedValue([{ address: '10.1.2.3', family: 4 }]);
    await expect(assertAllowedServiceUrl('https://nessus.corp.example:8834')).resolves.toBe('https://nessus.corp.example:8834');
  });

  it('reports a hostname that does not resolve', async () => {
    const lookup = vi.spyOn(dns, 'lookup') as unknown as ReturnType<typeof vi.fn>;
    lookup.mockRejectedValue(new Error('ENOTFOUND'));
    await expect(assertAllowedServiceUrl('https://nope.example')).rejects.toThrow(/Could not resolve/);
  });

  it('allows only loopback, not metadata, with the escape hatch on', async () => {
    process.env.ALLOW_LOOPBACK_SERVICE_URL = 'true';
    await expect(assertAllowedServiceUrl('https://127.0.0.1:8834')).resolves.toBe('https://127.0.0.1:8834');
    await expect(assertAllowedServiceUrl('https://[::1]:8834')).resolves.toBe('https://[::1]:8834');
    await expect(assertAllowedServiceUrl('http://169.254.169.254')).rejects.toThrow(OutboundUrlError);
  });
});

describe('guardedServiceHttpAgent', () => {
  const server = http.createServer((_req, res) => res.end('reached'));
  let port: number;

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => server.close());
  afterEach(() => {
    delete process.env.ALLOW_LOOPBACK_SERVICE_URL;
  });

  const request = () => axios.get(`http://localhost:${port}`, { httpAgent: guardedServiceHttpAgent, proxy: false });

  it('refuses at connect time when a hostname resolves to a refused address', async () => {
    await expect(request()).rejects.toThrow(/Refusing to contact reserved address/);
  });

  it('refuses an IP literal, which never reaches the lookup', async () => {
    await expect(
      axios.get(`http://127.0.0.1:${port}`, { httpAgent: guardedServiceHttpAgent, proxy: false }),
    ).rejects.toThrow(/Refusing to contact reserved address 127\.0\.0\.1/);
  });

  it('refuses an IP literal over https as well', async () => {
    await expect(
      axios.get(`https://127.0.0.1:${port}`, { httpsAgent: createGuardedServiceHttpsAgent(), proxy: false }),
    ).rejects.toThrow(/Refusing to contact reserved address 127\.0\.0\.1/);
  });

  it('connects to an allowed IP literal', async () => {
    process.env.ALLOW_LOOPBACK_SERVICE_URL = 'true';
    await expect(
      axios.get(`http://127.0.0.1:${port}`, { httpAgent: guardedServiceHttpAgent, proxy: false }),
    ).resolves.toMatchObject({ data: 'reached' });
  });

  it('connects when the resolved address is allowed', async () => {
    process.env.ALLOW_LOOPBACK_SERVICE_URL = 'true';
    await expect(request()).resolves.toMatchObject({ data: 'reached' });
  });
});

describe('scannerTlsOptions', () => {
  const saved = { insecure: process.env.ALLOW_INSECURE_SCANNER_TLS, ca: process.env.SCANNER_TLS_CA_FILE };
  afterEach(() => {
    if (saved.insecure === undefined) delete process.env.ALLOW_INSECURE_SCANNER_TLS; else process.env.ALLOW_INSECURE_SCANNER_TLS = saved.insecure;
    if (saved.ca === undefined) delete process.env.SCANNER_TLS_CA_FILE; else process.env.SCANNER_TLS_CA_FILE = saved.ca;
  });

  it('verifies certificates by default', () => {
    delete process.env.ALLOW_INSECURE_SCANNER_TLS;
    delete process.env.SCANNER_TLS_CA_FILE;
    expect(scannerTlsOptions()).toEqual({ rejectUnauthorized: true });
  });
  it('turns verification off only for the exact opt-out value', () => {
    process.env.ALLOW_INSECURE_SCANNER_TLS = 'true';
    expect(scannerTlsOptions().rejectUnauthorized).toBe(false);
    process.env.ALLOW_INSECURE_SCANNER_TLS = '1';
    expect(scannerTlsOptions().rejectUnauthorized).toBe(true);
  });
  it('keeps verification on when the CA file cannot be read', () => {
    delete process.env.ALLOW_INSECURE_SCANNER_TLS;
    process.env.SCANNER_TLS_CA_FILE = '/nonexistent/ca.pem';
    expect(scannerTlsOptions()).toEqual({ rejectUnauthorized: true });
  });
});
