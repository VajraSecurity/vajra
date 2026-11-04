import fs from 'fs/promises';
import type { Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { saveCertinDraft } from '../../../controllers/alerts/certin_draft';
import { dbSourceConnection } from '../../../index';

vi.mock('../../../index', () => ({ dbSourceConnection: vi.fn() }));
vi.mock('../../../utils/auditTrailLogger', () => ({ logAuditTrail: vi.fn().mockResolvedValue(undefined) }));
vi.mock('fs/promises', () => {
  const mocked = { mkdir: vi.fn(), writeFile: vi.fn(), readdir: vi.fn(), readFile: vi.fn(), unlink: vi.fn() };
  return { default: mocked, ...mocked };
});

const repo = { findOne: vi.fn(), create: vi.fn(), save: vi.fn() };

function response() {
  return { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
}

function request(body: unknown) {
  return {
    body,
    jwtPayload: { id: 7, email: 'admin@example.test', name: 'Admin' },
    ip: '127.0.0.1',
    get: vi.fn(),
  } as unknown as Request;
}

describe('saveCertinDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fs.mkdir).mockResolvedValue(undefined);
    vi.mocked(fs.writeFile).mockResolvedValue(undefined);
    vi.mocked(dbSourceConnection).mockReturnValue([{ getRepository: () => repo }] as never);
    repo.findOne.mockResolvedValue(null);
    repo.create.mockImplementation((draft) => draft);
  });

  it.each([
    ['a string', 'text'],
    ['an array', [{ iAm: 'x' }]],
    ['a number', 5],
  ])('rejects formData that is %s without saving it', async (_label, formData) => {
    const res = response();
    await saveCertinDraft(request({ formData }), res as unknown as Response);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(repo.save).not.toHaveBeenCalled();
    expect(fs.writeFile).not.toHaveBeenCalled();
  });

  it.each([
    ['a string', 'alert-1'],
    ['an array holding non-strings', ['alert-1', { id: 2 }]],
  ])('rejects selectedAlertIds that is %s without saving it', async (_label, selectedAlertIds) => {
    const res = response();
    await saveCertinDraft(request({ formData: { iAm: 'x' }, selectedAlertIds }), res as unknown as Response);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(repo.save).not.toHaveBeenCalled();
    expect(fs.writeFile).not.toHaveBeenCalled();
  });

  it('writes a new draft snapshot from the saved record, readable only by the owner', async () => {
    repo.save.mockImplementation(async (draft) => ({ ...draft, id: 11, formData: { iAm: 'stored' }, selectedAlertIds: ['stored-alert'] }));
    const res = response();
    await saveCertinDraft(request({ formData: { iAm: 'submitted' }, selectedAlertIds: ['submitted-alert'] }), res as unknown as Response);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: true, draftId: 11 }));
    const [filePath, contents, options] = vi.mocked(fs.writeFile).mock.calls[0];
    expect(String(filePath)).toMatch(/Drafts[\\/]user-7_draft-11_.*\.json$/);
    expect(options).toEqual({ encoding: 'utf-8', mode: 0o600 });
    expect(JSON.parse(String(contents))).toMatchObject({
      userId: 7,
      draftId: 11,
      state: 'drafts',
      eventType: 'started',
      formData: { iAm: 'stored' },
      selectedAlertIds: ['stored-alert'],
    });
  });

  it('writes an updated draft snapshot from the saved record', async () => {
    const existing = { id: 12, userId: 7, formData: { iAm: 'old' }, expiresAt: new Date(Date.now() + 60_000) };
    repo.findOne.mockResolvedValue(existing);
    repo.save.mockImplementation(async (draft) => draft);
    const res = response();
    await saveCertinDraft(request({ formData: { iAm: 'new' } }), res as unknown as Response);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: true, draftId: 12 }));
    expect(JSON.parse(String(vi.mocked(fs.writeFile).mock.calls[0][1]))).toMatchObject({
      draftId: 12,
      eventType: 'edited',
      formData: { iAm: 'new' },
      selectedAlertIds: [],
    });
  });
});
