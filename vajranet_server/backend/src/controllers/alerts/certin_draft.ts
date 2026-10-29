import { Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { LessThan } from 'typeorm';
import { CertinDraft } from '../../orm/entities/audit/CertinDraft';
import { VajraUser } from '../../orm/entities/users/Users';
import { dbSourceConnection } from '../../index';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.certinDraft');

const DRAFT_EXPIRY_HOURS = 24;
const CERTIN_REPORTS_ROOT = path.resolve(__dirname, '../../../..', 'storage', 'certin-reports');
const CERTIN_FOLDERS = {
  completeDownloaded: 'Complete&Downloaded',
  complete: 'Complete',
  drafts: 'Drafts',
} as const;

type CertinState = 'completeDownloaded' | 'complete' | 'drafts';

const REQUIRED_CERTIN_FIELDS = [
  'iAm',
  'reporterRole',
  'reporterNameTitle',
  'reporterOrganization',
  'reporterContactNo',
  'reporterEmail',
  'reporterAddress',
  'affectedEntity',
  'incidentTypes',
  'isCritical',
  'affectedSystemIp',
  'incidentBriefDescription',
  'occurrenceDateTime',
  'detectionDateTime',
];

async function ensureCertinReportFolders() {
  await fs.mkdir(path.join(CERTIN_REPORTS_ROOT, CERTIN_FOLDERS.completeDownloaded), { recursive: true });
  await fs.mkdir(path.join(CERTIN_REPORTS_ROOT, CERTIN_FOLDERS.complete), { recursive: true });
  await fs.mkdir(path.join(CERTIN_REPORTS_ROOT, CERTIN_FOLDERS.drafts), { recursive: true });
}

function isFormComplete(formData: any): boolean {
  if (!formData || typeof formData !== 'object') return false;
  return REQUIRED_CERTIN_FIELDS.every((field) => {
    const value = (formData as Record<string, unknown>)[field];
    if (Array.isArray(value)) return value.length > 0;
    return String(value ?? '').trim().length > 0;
  });
}

function stampNow() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const mi = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}_${hh}-${mi}-${ss}`;
}

async function writeCertinSnapshot(params: {
  userId: number;
  draftId: number;
  formData: any;
  selectedAlertIds?: string[];
  state: CertinState;
  eventType?: 'started' | 'edited' | 'completed' | 'downloaded';
  actor?: { userId?: number; email?: string | null; name?: string | null };
}) {
  await ensureCertinReportFolders();
  const folder = CERTIN_FOLDERS[params.state];
  const filename = `user-${params.userId}_draft-${params.draftId}_${stampNow()}.json`;
  const payload = {
    userId: params.userId,
    draftId: params.draftId,
    state: params.state,
    storedAt: new Date().toISOString(),
    selectedAlertIds: params.selectedAlertIds ?? [],
    eventType: params.eventType ?? null,
    actor: params.actor ?? null,
    formData: params.formData,
  };
  await fs.writeFile(path.join(CERTIN_REPORTS_ROOT, folder, filename), JSON.stringify(payload, null, 2), 'utf-8');
}

async function removeCompleteSnapshotsForDraft(userId: number, draftId: number) {
  await ensureCertinReportFolders();
  const completeDir = path.join(CERTIN_REPORTS_ROOT, CERTIN_FOLDERS.complete);
  const files = await fs.readdir(completeDir);
  const prefix = `user-${userId}_draft-${draftId}_`;
  const toRemove = files.filter((name) => name.startsWith(prefix) && name.endsWith('.json'));
  await Promise.all(toRemove.map((name) => fs.unlink(path.join(completeDir, name))));
  logger.debug({ userId, draftId, removed: toRemove.length }, 'Stale CERT-In complete snapshots removed');
}

export async function saveCertinDraft(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const actorEmail = ((req as any).jwtPayload?.email ?? null) as string | null;
    const actorName = ((req as any).jwtPayload?.name ?? null) as string | null;

    const { formData, selectedAlertIds } = req.body;
    if (!formData) return res.status(400).json({ error: 'formData is required' });

    const draftRepository = dbSourceConnection()?.[0]?.getRepository(CertinDraft);
    if (!draftRepository) {
      logger.error({ userId }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }

    const existingDraft = await draftRepository.findOne({ where: { userId }, order: { updatedAt: 'DESC' } });

    const expiresAt = new Date(Date.now() + DRAFT_EXPIRY_HOURS * 60 * 60 * 1000);

    if (existingDraft && existingDraft.expiresAt && existingDraft.expiresAt > new Date()) {
      existingDraft.formData = formData;
      existingDraft.selectedAlertIds = selectedAlertIds || undefined;
      existingDraft.expiresAt = expiresAt;
      const updated = await draftRepository.save(existingDraft);
      const isComplete = isFormComplete(formData);
      const eventType = isComplete ? 'completed' : 'edited';
      try {
        await writeCertinSnapshot({
          userId,
          draftId: updated.id,
          formData,
          selectedAlertIds: selectedAlertIds || [],
          state: isComplete ? 'complete' : 'drafts',
          eventType,
          actor: { userId, email: actorEmail, name: actorName },
        });
      } catch (snapshotError) {
        logger.error({ err: snapshotError, userId, draftId: updated.id }, 'CERT-In draft saved to database but snapshot file write failed');
        throw snapshotError;
      }
      await logAuditTrail({
        action: isComplete ? 'CERTIN_DRAFT_COMPLETE' : 'CERTIN_DRAFT_EDIT',
        status: 'success',
        userId,
        email: actorEmail,
        ipAddress: req.ip || null,
        userAgent: req.get('user-agent') || null,
        details: { draftId: updated.id, selectedAlertIds: selectedAlertIds || [] },
      });
      logger.debug({ userId, draftId: updated.id, isComplete }, 'CERT-In draft updated');
      return res.json({ success: true, draftId: updated.id, expiresAt: updated.expiresAt, message: 'Draft updated successfully' });
    }

    const newDraft = draftRepository.create({ userId, formData, selectedAlertIds: selectedAlertIds || undefined, expiresAt });
    const saved = await draftRepository.save(newDraft);
    const isComplete = isFormComplete(formData);
    const eventType = isComplete ? 'completed' : 'started';
    try {
      await writeCertinSnapshot({
        userId,
        draftId: saved.id,
        formData,
        selectedAlertIds: selectedAlertIds || [],
        state: isComplete ? 'complete' : 'drafts',
        eventType,
        actor: { userId, email: actorEmail, name: actorName },
      });
    } catch (snapshotError) {
      logger.error({ err: snapshotError, userId, draftId: saved.id }, 'CERT-In draft saved to database but snapshot file write failed');
      throw snapshotError;
    }
    await logAuditTrail({
      action: isComplete ? 'CERTIN_DRAFT_COMPLETE' : 'CERTIN_DRAFT_START',
      status: 'success',
      userId,
      email: actorEmail,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      details: { draftId: saved.id, selectedAlertIds: selectedAlertIds || [] },
    });
    // existingDraft is set here whenever the prior draft row was left behind because it
    // had already expired (the update branch above only fires while still unexpired) —
    // that stale row is not deleted, only orphaned until cleanupExpiredDrafts runs.
    logger.info(
      { userId, draftId: saved.id, isComplete, replacedExpiredDraftId: existingDraft?.id ?? null },
      'CERT-In draft created',
    );
    return res.json({ success: true, draftId: saved.id, expiresAt: saved.expiresAt, message: 'Draft saved successfully' });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to save CERT-In draft');
    return res.status(500).json({ error: 'Failed to save draft' });
  }
}

export async function markCertinDraftDownloaded(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const actorEmail = ((req as any).jwtPayload?.email ?? null) as string | null;
    const actorName = ((req as any).jwtPayload?.name ?? null) as string | null;

    const { draftId } = req.params;
    const parsedDraftId = Number(draftId);
    if (!Number.isFinite(parsedDraftId)) return res.status(400).json({ error: 'Invalid draftId' });

    const draftRepository = dbSourceConnection()?.[0]?.getRepository(CertinDraft);
    if (!draftRepository) {
      logger.error({ userId, draftId: parsedDraftId }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }

    const draft = await draftRepository.findOne({ where: { id: parsedDraftId, userId } });
    if (!draft) {
      logger.info({ userId, draftId: parsedDraftId }, 'CERT-In draft download mark failed, draft not found');
      return res.status(404).json({ error: 'Draft not found' });
    }
    if (!isFormComplete(draft.formData)) {
      logger.info({ userId, draftId: parsedDraftId }, 'CERT-In draft download mark rejected, draft incomplete');
      return res.status(400).json({ error: 'Draft is incomplete and cannot be marked downloaded' });
    }

    try {
      await removeCompleteSnapshotsForDraft(userId, draft.id);
    } catch (cleanupError) {
      logger.error({ err: cleanupError, userId, draftId: draft.id }, 'CERT-In draft found but failed to clean up stale complete snapshots while marking downloaded');
      throw cleanupError;
    }
    try {
      await writeCertinSnapshot({
        userId,
        draftId: draft.id,
        formData: draft.formData,
        selectedAlertIds: draft.selectedAlertIds || [],
        state: 'completeDownloaded',
        eventType: 'downloaded',
        actor: { userId, email: actorEmail, name: actorName },
      });
    } catch (snapshotError) {
      logger.error({ err: snapshotError, userId, draftId: draft.id }, 'CERT-In draft found but snapshot file write failed while marking downloaded');
      throw snapshotError;
    }
    await logAuditTrail({
      action: 'CERTIN_DRAFT_DOWNLOAD',
      status: 'success',
      userId,
      email: actorEmail,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      details: { draftId: draft.id, selectedAlertIds: draft.selectedAlertIds || [] },
    });
    logger.info({ userId, draftId: draft.id }, 'CERT-In draft download recorded');
    return res.json({ success: true, message: 'Download recorded' });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id, draftId: req.params?.draftId }, 'Failed to record CERT-In draft download');
    return res.status(500).json({ error: 'Failed to record download' });
  }
}

export async function getCertinDraft(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const draftRepository = dbSourceConnection()?.[0]?.getRepository(CertinDraft);
    if (!draftRepository) {
      logger.error({ userId }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }
    const draft = await draftRepository.findOne({ where: { userId }, order: { updatedAt: 'DESC' } });
    if (!draft) {
      logger.debug({ userId }, 'No CERT-In draft found');
      return res.json({ draft: null, message: 'No draft found' });
    }

    if (draft.expiresAt && draft.expiresAt < new Date()) {
      await draftRepository.remove(draft);
      logger.debug({ userId, draftId: draft.id }, 'Expired CERT-In draft removed');
      return res.json({ draft: null, message: 'Draft has expired' });
    }

    const selectedAlertIds = draft.selectedAlertIds || [];
    logger.debug({ userId, draftId: draft.id }, 'CERT-In draft retrieved');
    return res.json({ draft: { id: draft.id, formData: draft.formData, selectedAlertIds, createdAt: draft.createdAt, updatedAt: draft.updatedAt, expiresAt: draft.expiresAt } });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to fetch CERT-In draft');
    return res.status(500).json({ error: 'Failed to fetch draft' });
  }
}

export async function getCertinDraftHistory(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    await ensureCertinReportFolders();
    const entries: Array<{
      filename: string;
      state: CertinState;
      storedAt: string;
      draftId?: number;
      selectedAlertIds?: string[];
      formData?: any;
      eventType?: 'started' | 'edited' | 'completed' | 'downloaded' | null;
      actor?: { userId?: number; email?: string | null; name?: string | null } | null;
    }> = [];

    const folders: Array<{ key: CertinState; name: string }> = [
      { key: 'drafts', name: CERTIN_FOLDERS.drafts },
      { key: 'complete', name: CERTIN_FOLDERS.complete },
      { key: 'completeDownloaded', name: CERTIN_FOLDERS.completeDownloaded },
    ];

    for (const folder of folders) {
      const dir = path.join(CERTIN_REPORTS_ROOT, folder.name);
      const files = await fs.readdir(dir);
      const prefix = `user-${userId}_`;
      const userFiles = files.filter((name) => name.startsWith(prefix) && name.endsWith('.json'));
      for (const fileName of userFiles) {
        try {
          const raw = await fs.readFile(path.join(dir, fileName), 'utf-8');
          const parsed = JSON.parse(raw);
          entries.push({
            filename: fileName,
            state: folder.key,
            storedAt: String(parsed?.storedAt ?? ''),
            draftId: Number(parsed?.draftId ?? 0) || undefined,
            selectedAlertIds: Array.isArray(parsed?.selectedAlertIds) ? parsed.selectedAlertIds : [],
            formData: parsed?.formData ?? null,
            eventType: parsed?.eventType ?? null,
            actor: parsed?.actor ?? null,
          });
        } catch (e) {
          logger.warn({ err: e, fileName }, 'Skipping malformed CERT-In draft snapshot file');
        }
      }
    }

    const userRepo = dbSourceConnection()?.[0]?.getRepository(VajraUser);
    if (userRepo) {
      const actorUserIds = Array.from(
        new Set(
          entries
            .map((e) => Number(e.actor?.userId ?? userId ?? 0))
            .filter((id) => Number.isFinite(id) && id > 0),
        ),
      );
      if (actorUserIds.length > 0) {
        const users = await userRepo.findByIds(actorUserIds as number[]);
        const byId = new Map<number, { name: string | null; email: string | null }>();
        users.forEach((u) => byId.set(u.id, { name: u.name ?? null, email: u.email ?? null }));
        entries.forEach((entry) => {
          const actorId = Number(entry.actor?.userId ?? userId ?? 0);
          if (!Number.isFinite(actorId) || actorId <= 0) return;
          const u = byId.get(actorId);
          if (!u) return;
          if (!entry.actor) entry.actor = { userId: actorId, name: null, email: null };
          entry.actor.name = entry.actor.name ?? u.name ?? null;
          entry.actor.email = entry.actor.email ?? u.email ?? null;
        });
      }
    }

    entries.sort((a, b) => new Date(b.storedAt).getTime() - new Date(a.storedAt).getTime());
    logger.debug({ userId, count: entries.length }, 'CERT-In draft history retrieved');
    return res.json({ success: true, history: entries });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to fetch CERT-In draft history');
    return res.status(500).json({ error: 'Failed to fetch draft history' });
  }
}

export async function deleteCertinDraft(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    let { draftId } = req.params;
    if (!draftId) return res.status(400).json({ error: 'draftId is required' });
    if (Array.isArray(draftId)) draftId = draftId[0];

    const draftRepository = dbSourceConnection()?.[0]?.getRepository(CertinDraft);
    if (!draftRepository) {
      logger.error({ userId, draftId }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }
    const draft = await draftRepository.findOne({ where: { id: parseInt(draftId, 10), userId } });
    if (!draft) {
      logger.info({ userId, draftId }, 'CERT-In draft delete failed, draft not found');
      return res.status(404).json({ error: 'Draft not found' });
    }
    await draftRepository.remove(draft);
    logger.info({ userId, draftId: draft.id }, 'CERT-In draft deleted');
    return res.json({ success: true, message: 'Draft deleted successfully' });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id, draftId: req.params?.draftId }, 'Failed to delete CERT-In draft');
    return res.status(500).json({ error: 'Failed to delete draft' });
  }
}

/**
 * Deletes expired CertinDraft rows (and, by cascade/FK, their storage). Not
 * wired to any route — invoked on a schedule from index.ts's cron
 * initialization block via runCleanupExpiredDraftsJob() below.
 */
async function cleanupExpiredDraftsCore(): Promise<number> {
  const draftRepository = dbSourceConnection()?.[0]?.getRepository(CertinDraft);
  if (!draftRepository) {
    logger.error('Expired CERT-In draft cleanup skipped: database connection not available');
    return 0;
  }
  const result = await draftRepository.delete({ expiresAt: LessThan(new Date()) });
  const count = result.affected ?? 0;
  if (count > 0) {
    logger.info({ count }, 'Expired CERT-In drafts cleaned up');
  } else {
    logger.debug({ count }, 'Expired CERT-In drafts cleaned up');
  }
  return count;
}

/** Cron-safe entry point: same cleanup, no Express req/res dependency. */
export async function runCleanupExpiredDraftsJob(): Promise<void> {
  try {
    await cleanupExpiredDraftsCore();
  } catch (error) {
    logger.error({ err: error }, 'Scheduled expired CERT-In draft cleanup failed');
  }
}
