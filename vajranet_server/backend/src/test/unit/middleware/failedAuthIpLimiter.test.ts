import express from 'express';
import type { Server } from 'http';
import type { AddressInfo } from 'net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RATE_LIMIT_MAX_FAILED_AUTH_IP } from '../../../consts';
import { failedAuthIpLimiter, failedAuthKey } from '../../../middleware/rateLimiters';

describe('failedAuthKey', () => {
  const request = (remoteAddress: string, ip: string) => ({ ip, socket: { remoteAddress } }) as never;

  it('uses the forwarded address when the connection comes from the local proxy', () => {
    expect(failedAuthKey(request('127.0.0.1', '203.0.113.7'))).toBe('203.0.113.7');
    expect(failedAuthKey(request('::ffff:127.0.0.1', '203.0.113.7'))).toBe('203.0.113.7');
  });
  it('ignores a forwarded address on a direct connection', () => {
    expect(failedAuthKey(request('198.51.100.9', '203.0.113.7'))).toBe('198.51.100.9');
    expect(failedAuthKey(request('198.51.100.9', '192.0.2.1'))).toBe('198.51.100.9');
  });
});

describe('failedAuthIpLimiter', () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    const app = express();
    app.use(failedAuthIpLimiter);
    app.get('/ok', (_req, res) => res.sendStatus(200));
    app.get('/forbidden', (_req, res) => res.sendStatus(403));
    app.get('/denied', (_req, res) => res.sendStatus(401));
    await new Promise<void>((resolve) => { server = app.listen(0, '127.0.0.1', () => resolve()); });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise((resolve) => { server.close(resolve); }));

  it('only counts 401 responses, then blocks that address', async () => {
    for (let i = 0; i < RATE_LIMIT_MAX_FAILED_AUTH_IP + 20; i++) {
      expect((await fetch(`${base}/ok`)).status).toBe(200);
    }
    expect((await fetch(`${base}/forbidden`)).status).toBe(403);

    for (let i = 0; i < RATE_LIMIT_MAX_FAILED_AUTH_IP; i++) {
      expect((await fetch(`${base}/denied`)).status).toBe(401);
    }
    const blocked = await fetch(`${base}/ok`);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('retry-after')).toBeTruthy();
  });
});
