import axios from 'axios';
import type { NextFunction, Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { testBurpsuiteConnection } from '../../../controllers/burpsuite/burpsuiteController';

vi.mock('axios');
vi.mock('../../../index', () => ({ dbSourceConnection: vi.fn() }));

function run(body: unknown) {
  const res = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
  const done = testBurpsuiteConnection({ body } as Request, res as unknown as Response, vi.fn() as NextFunction);
  return done.then(() => res);
}

describe('testBurpsuiteConnection', () => {
  beforeEach(() => {
    vi.mocked(axios.get).mockReset();
    vi.mocked(axios.get).mockResolvedValue({ data: {} });
    delete process.env.BURPSUITE_ALLOW_INSECURE_URL;
  });

  it('calls the canonical URL with an ordinary key unchanged', async () => {
    await run({ url: 'https://8.8.8.8:1337/', apiKey: 'abcDEF123' });
    expect(vi.mocked(axios.get).mock.calls[0][0]).toBe('https://8.8.8.8:1337/abcDEF123/v0.1/knowledge_base/issue_definitions');
  });

  it('keeps a crafted key inside its own path segment', async () => {
    await run({ url: 'https://8.8.8.8', apiKey: '../../admin?x=' });
    expect(vi.mocked(axios.get).mock.calls[0][0]).toBe(
      'https://8.8.8.8/..%2F..%2Fadmin%3Fx%3D/v0.1/knowledge_base/issue_definitions',
    );
  });

  it.each([
    ['https://169.254.169.254'],
    ['https://127.0.0.1'],
    ['https://10.0.0.1'],
    ['https://user:pass@8.8.8.8'],
    ['http://8.8.8.8'],
  ])('refuses %s without sending a request', async (url) => {
    const res = await run({ url, apiKey: 'k' });
    expect(res.status).toHaveBeenCalledWith(400);
    expect(axios.get).not.toHaveBeenCalled();
  });
});
