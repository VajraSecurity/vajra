import { Request, Response, NextFunction } from 'express';
import { encrypt } from '../../utils/encryption';
import { getNessusClient, createNessusInstanceFromRaw, invalidateNessusClientCache } from '../../utils/nessusClient';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { parseAndValidateTargets } from '../network/targetValidation';
import { API_KEY_MASK_SUFFIX_LENGTH } from '../../consts/auth';
import { EXTERNAL_API_TIMEOUT_MS } from '../../consts/timeout';
import { getLogger } from '../../utils/logger';
import { sanitizeAxiosError } from '../../utils/sanitizeAxiosError';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';
import { resolveScannerGroupContext, groupIdWhereValue } from '../../utils/scannerScope';

const logger = getLogger('controllers.nessus');

const INVALID_TARGETS_MESSAGE =
  'Invalid targets. Only private network IPs/CIDRs (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) are allowed — hostnames are not accepted, and CIDR blocks must stay within a single allowed range.';

function parseIntParam(val: string | string[]): number | null {
  const s = Array.isArray(val) ? val[0] : val;
  if (!s) return null;
  const n = parseInt(s, 10);
  return isNaN(n) ? null : n;
}

async function proxyGet(_req: Request, res: Response, path: string, groupId: string | null, timeoutMs?: number) {
  try {
    const client = await getNessusClient(groupId);
    const resp = await client.get(path, timeoutMs ? { timeout: timeoutMs } : undefined);
    // Every caller of proxyGet is registered under router.get — this is a
    // routine, frequently-polled read, so keep it at debug to avoid flooding
    // production logs at the default info level.
    logger.debug({ path }, 'Nessus API request succeeded');
    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path });
  }
}

async function proxyPost(_req: Request, res: Response, path: string, groupId: string | null, body?: any) {
  try {
    const client = await getNessusClient(groupId);
    const resp = await client.post(path, body);
    logger.debug({ path }, 'Nessus API request succeeded');
    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path });
  }
}

async function proxyPut(_req: Request, res: Response, path: string, groupId: string | null, body?: any) {
  try {
    const client = await getNessusClient(groupId);
    const resp = await client.put(path, body);
    logger.debug({ path }, 'Nessus API request succeeded');
    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path });
  }
}

async function proxyDelete(_req: Request, res: Response, path: string, groupId: string | null) {
  try {
    const client = await getNessusClient(groupId);
    const resp = await client.delete(path);
    logger.debug({ path }, 'Nessus API request succeeded');
    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path });
  }
}

function handleNessusError(res: Response, err: any, context?: Record<string, unknown>) {
  // Nessus authenticates every request via the `X-ApiKeys` header (built in
  // nessusClient.ts), which axios embeds verbatim into a failed request's
  // `err.config.headers` — logging the raw error here would leak both keys
  // into the log stream, so only an allowlisted subset is ever logged.
  logger.error({ err: sanitizeAxiosError(err), ...context }, 'Nessus API request failed');
  if (err.message === 'Nessus is not configured. Please add your Nessus API credentials in Settings.') {
    return res.status(400).json({ success: false, message: err.message });
  }
  if (err.message === 'Fleet database not available') {
    return res.status(503).json({ success: false, message: err.message });
  }
  if (err.response) {
    const nessusStatus = err.response.status || 502;
    const data = err.response.data;
    const msg = data?.error || data?.message || data?.error_message || err.response.statusText || 'Nessus API error';

    // Never forward 401/403 from Nessus — the frontend auth interceptor
    // would misinterpret it as a Vajra session expiration and log the user out.
    // Wrap upstream auth errors as 502 (Bad Gateway).
    if (nessusStatus === 401 || nessusStatus === 403) {
      return res.status(502).json({
        success: false,
        message: `Nessus authentication failed: ${msg}. Check your API credentials in Settings.`,
      });
    }

    return res.status(nessusStatus).json({ success: false, message: msg });
  }
  if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
    return res.status(502).json({ success: false, message: `Cannot reach Nessus server: ${err.code}` });
  }
  if (err.code === 'ECONNABORTED') {
    return res.status(504).json({ success: false, message: 'Nessus server took too long to respond' });
  }
  return res.status(500).json({ success: false, message: err.message || 'Unexpected error communicating with Nessus' });
}

// Config endpoints

export const saveNessusConfig = async (req: Request, res: Response, _next: NextFunction) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  try {
    const { nessus_url, access_key, secret_key } = req.body;

    if (!nessus_url || typeof nessus_url !== 'string') {
      return res.status(400).json({ success: false, message: 'nessus_url is required' });
    }
    if (!access_key || typeof access_key !== 'string') {
      return res.status(400).json({ success: false, message: 'access_key is required' });
    }
    if (!secret_key || typeof secret_key !== 'string') {
      return res.status(400).json({ success: false, message: 'secret_key is required' });
    }

    const urlClean = nessus_url.replace(/\/+$/, '');

    // Require a successful live connection test with these exact credentials
    // before persisting — otherwise a typo'd URL/key silently saves and only
    // surfaces as a failure the next time something tries to use it. Reuses
    // the same test path testNessusConnection exposes standalone, so "Test
    // Connection" and "Save" can never disagree about whether credentials work.
    const testResult = await runNessusConnectionTest(urlClean, access_key, secret_key);
    if (!testResult.success) {
      logger.warn({ groupId, message: testResult.message }, 'Nessus configuration save rejected: connection test failed');
      return res.status(400).json({
        success: false,
        message: `Connection test failed, configuration was not saved: ${testResult.message || 'unable to connect'}`,
      });
    }

    const encAccess = encrypt(access_key);
    const encSecret = encrypt(secret_key);

    const { dbSourceConnection } = await import('../../index');
    const { NessusConfig } = await import('../../orm/entities/fleet/NessusConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({}, 'Nessus configuration save aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NessusConfig);

    await repo.update({ isActive: true, groupId: groupIdWhereValue(groupId) }, { isActive: false });

    const config = repo.create({
      groupId,
      nessusUrl: urlClean,
      accessKeyEncrypted: encAccess.ciphertext,
      accessKeyIv: encAccess.iv,
      accessKeyAuthTag: encAccess.authTag,
      secretKeyEncrypted: encSecret.ciphertext,
      secretKeyIv: encSecret.iv,
      secretKeyAuthTag: encSecret.authTag,
      accessKeySuffix: access_key.slice(-API_KEY_MASK_SUFFIX_LENGTH),
      secretKeySuffix: secret_key.slice(-API_KEY_MASK_SUFFIX_LENGTH),
      isActive: true,
      created_by_user_id: jwtFrom(req)?.id ?? null,
      created_by_name: jwtFrom(req)?.name ?? null,
    });

    await repo.save(config);
    invalidateNessusClientCache(groupId);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'NESSUS_CONFIG',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'CONFIG_SAVED', nessus_url: urlClean, groupId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ userId: jwt?.id ?? null, groupId }, 'Nessus configuration saved');
    return res.status(200).json({ success: true, message: 'Nessus configuration saved' });
  } catch (err: any) {
    logger.error({ err }, 'Failed to save Nessus configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to save Nessus configuration' });
  }
};

export const getNessusConfig = async (req: Request, res: Response, _next: NextFunction) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  try {
    const { dbSourceConnection } = await import('../../index');
    const { NessusConfig } = await import('../../orm/entities/fleet/NessusConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({}, 'Nessus configuration fetch aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NessusConfig);
    const config = await repo.findOne({ where: { isActive: true, groupId: groupIdWhereValue(groupId) } });

    if (!config) {
      logger.debug({ groupId }, 'Nessus configuration retrieved: none configured');
      return res.status(200).json({ success: true, data: null });
    }

    logger.debug({ configId: config.id, groupId }, 'Nessus configuration retrieved');
    return res.status(200).json({
      success: true,
      data: {
        id: config.id,
        group_id: config.groupId,
        nessus_url: config.nessusUrl,
        access_key_masked: '****' + (config.accessKeySuffix || '****'),
        secret_key_masked: '****' + (config.secretKeySuffix || '****'),
        is_active: config.isActive,
        created_by_name: config.created_by_name,
        created_at: config.created_at,
        updated_at: config.updated_at,
      },
    });
  } catch (err: any) {
    logger.error({ err }, 'Failed to fetch Nessus configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to get Nessus configuration' });
  }
};

/**
 * Shared by testNessusConnection (the standalone "Test Connection" button) and
 * saveNessusConfig, which requires it to succeed before persisting. Never writes to
 * `res` itself, so both callers decide their own response shape and status.
 */
async function runNessusConnectionTest(
  nessusUrl: string,
  accessKey: string,
  secretKey: string,
): Promise<{ success: boolean; message?: string; data?: any }> {
  try {
    const client = createNessusInstanceFromRaw(nessusUrl, accessKey, secretKey);
    const resp = await client.get('/server/status');
    logger.info({}, 'Nessus connection test succeeded');
    return { success: true, data: { status: resp.data?.status || 'connected', server: resp.data } };
  } catch (err: any) {
    // This request is built with access_key/secret_key taken straight from
    // the caller via createNessusInstanceFromRaw — same X-ApiKeys header leak
    // risk as handleNessusError above.
    logger.warn({ err: sanitizeAxiosError(err) }, 'Nessus connection test failed');
    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
      return { success: false, message: `Cannot reach Nessus server: ${err.code}` };
    }
    if (err.response?.status === 401) {
      return { success: false, message: 'Invalid API credentials' };
    }
    return { success: false, message: err.message || 'Connection test failed' };
  }
}

export const testNessusConnection = async (req: Request, res: Response, _next: NextFunction) => {
  const { nessus_url, access_key, secret_key } = req.body;

  if (!nessus_url || !access_key || !secret_key) {
    return res.status(400).json({ success: false, message: 'nessus_url, access_key, and secret_key are required' });
  }

  const urlClean = nessus_url.replace(/\/+$/, '');
  const result = await runNessusConnectionTest(urlClean, access_key, secret_key);
  return res.status(200).json(result);
};

export const deleteNessusConfig = async (req: Request, res: Response, _next: NextFunction) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  try {
    const { dbSourceConnection } = await import('../../index');
    const { NessusConfig } = await import('../../orm/entities/fleet/NessusConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({}, 'Nessus configuration deletion aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NessusConfig);
    await repo.update({ isActive: true, groupId: groupIdWhereValue(groupId) }, { isActive: false });
    invalidateNessusClientCache(groupId);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'NESSUS_CONFIG',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'CONFIG_DELETED', groupId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ groupId }, 'Nessus configuration removed');
    return res.status(200).json({ success: true, message: 'Nessus configuration removed' });
  } catch (err: any) {
    logger.error({ err }, 'Failed to delete Nessus configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to delete configuration' });
  }
};

export const testStoredConnection = async (req: Request, res: Response, _next: NextFunction) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  try {
    const client = await getNessusClient(groupId);
    const resp = await client.get('/server/status');
    logger.debug({}, 'Stored Nessus connection test succeeded');
    return res.status(200).json({
      success: true,
      data: { status: resp.data?.status || 'connected', server: resp.data },
    });
  } catch (err: any) {
    logger.warn({ err: sanitizeAxiosError(err) }, 'Stored Nessus connection test failed');
    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
      return res.status(200).json({ success: false, message: `Cannot reach Nessus server: ${err.code}` });
    }
    if (err.response?.status === 401) {
      return res.status(200).json({ success: false, message: 'Stored API credentials are invalid' });
    }
    return res.status(200).json({ success: false, message: err.message || 'Connection test failed' });
  }
};

// Server

export const getServerStatus = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/server/status', scopeResult.ctx.groupId);
};
export const getServerProperties = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/server/properties', scopeResult.ctx.groupId);
};

// Templates

export const listScanTemplates = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/editor/scan/templates', scopeResult.ctx.groupId);
};
export const listPolicyTemplates = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/editor/policy/templates', scopeResult.ctx.groupId);
};

// Scans

export const listScans = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/scans', scopeResult.ctx.groupId);
};

export const createScan = async (req: Request, res: Response, _next: NextFunction) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  const { uuid, settings } = req.body;
  if (!uuid || !settings?.name || !settings?.text_targets) {
    return res.status(400).json({ success: false, message: 'uuid, settings.name, and settings.text_targets are required' });
  }

  const validatedTargets = parseAndValidateTargets(settings.text_targets);
  if (!validatedTargets) {
    return res.status(400).json({ success: false, message: INVALID_TARGETS_MESSAGE });
  }
  req.body.settings.text_targets = validatedTargets.join(',');

  try {
    const client = await getNessusClient(groupId);
    const resp = await client.post('/scans', req.body);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'NESSUS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'SCAN_CREATED', name: settings.name, targets: settings.text_targets },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ name: settings.name, targets: settings.text_targets }, 'Nessus scan created');
    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path: '/scans', name: settings?.name });
  }
};

export const getScanDetails = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });
  return proxyGet(req, res, `/scans/${id}`, scopeResult.ctx.groupId, 90_000);
};

export const updateScan = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });

  if (req.body?.settings?.text_targets) {
    const validatedTargets = parseAndValidateTargets(req.body.settings.text_targets);
    if (!validatedTargets) {
      return res.status(400).json({ success: false, message: INVALID_TARGETS_MESSAGE });
    }
    req.body.settings.text_targets = validatedTargets.join(',');
  }

  return proxyPut(req, res, `/scans/${id}`, scopeResult.ctx.groupId, req.body);
};

export const deleteScan = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });

  try {
    const client = await getNessusClient(groupId);
    const resp = await client.delete(`/scans/${id}`);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'NESSUS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'SCAN_DELETED', scanId: id },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ scanId: id }, 'Nessus scan deleted');
    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path: `/scans/${id}`, scanId: id });
  }
};

export const launchScan = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });

  try {
    const client = await getNessusClient(groupId);
    const resp = await client.post(`/scans/${id}/launch`);

    logger.info({ scanId: id }, 'Nessus scan launched');

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'NESSUS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'SCAN_LAUNCHED', scanId: id },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    return res.status(200).json({ success: true, data: resp.data });
  } catch (err: any) {
    return handleNessusError(res, err, { path: `/scans/${id}/launch`, scanId: id });
  }
};

export const pauseScan = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });
  return proxyPost(req, res, `/scans/${id}/pause`, scopeResult.ctx.groupId);
};

export const resumeScan = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });
  return proxyPost(req, res, `/scans/${id}/resume`, scopeResult.ctx.groupId);
};

export const stopScan = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });
  return proxyPost(req, res, `/scans/${id}/stop`, scopeResult.ctx.groupId);
};

// Export

export const requestExport = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });

  const scanId = parseIntParam(req.params.scanId);
  if (scanId === null) return res.status(400).json({ success: false, message: 'Invalid scan ID' });

  const { format } = req.body;
  if (!format || !['nessus', 'csv', 'html'].includes(format)) {
    return res.status(400).json({ success: false, message: 'format must be one of: nessus, csv, html' });
  }

  return proxyPost(req, res, `/scans/${scanId}/export`, scopeResult.ctx.groupId, req.body);
};

export const getExportStatus = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });

  const scanId = parseIntParam(req.params.scanId);
  const fileId = parseIntParam(req.params.fileId);
  if (scanId === null || fileId === null) {
    return res.status(400).json({ success: false, message: 'Invalid scan ID or file ID' });
  }
  return proxyGet(req, res, `/scans/${scanId}/export/${fileId}/status`, scopeResult.ctx.groupId);
};

export const downloadExport = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) {
    return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  }
  const { groupId } = scopeResult.ctx;

  const scanId = parseIntParam(req.params.scanId);
  const fileId = parseIntParam(req.params.fileId);
  if (scanId === null || fileId === null) {
    return res.status(400).json({ success: false, message: 'Invalid scan ID or file ID' });
  }

  try {
    const client = await getNessusClient(groupId);
    const resp = await client.get(`/scans/${scanId}/export/${fileId}/download`, {
      responseType: 'stream',
      timeout: EXTERNAL_API_TIMEOUT_MS,
    });

    const contentType = String(resp.headers['content-type'] || 'application/octet-stream');
    const contentDisposition = String(resp.headers['content-disposition'] || `attachment; filename="scan_${scanId}_export"`);
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', contentDisposition);
    logger.debug({ scanId, fileId }, 'Nessus export download started');
    resp.data.pipe(res);
    resp.data.on('error', (streamErr: unknown) => {
      logger.warn({ err: sanitizeAxiosError(streamErr), scanId, fileId }, 'Nessus export download stream failed mid-transfer');
      if (!res.writableEnded) res.end();
    });
    return;
  } catch (err: any) {
    return handleNessusError(res, err, { path: `/scans/${scanId}/export/${fileId}/download`, scanId, fileId });
  }
};

// Policies

export const listPolicies = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/policies', scopeResult.ctx.groupId);
};

export const createPolicy = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  if (!req.body.uuid || !req.body.settings) {
    return res.status(400).json({ success: false, message: 'uuid and settings are required' });
  }
  return proxyPost(req, res, '/policies', scopeResult.ctx.groupId, req.body);
};

export const getPolicy = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid policy ID' });
  return proxyGet(req, res, `/policies/${id}`, scopeResult.ctx.groupId, 60_000);
};

export const updatePolicy = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid policy ID' });
  return proxyPut(req, res, `/policies/${id}`, scopeResult.ctx.groupId, req.body);
};

export const deletePolicy = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid policy ID' });
  return proxyDelete(req, res, `/policies/${id}`, scopeResult.ctx.groupId);
};

// Folders

export const listFolders = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/folders', scopeResult.ctx.groupId);
};

export const createFolder = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  if (!req.body.name) {
    return res.status(400).json({ success: false, message: 'Folder name is required' });
  }
  return proxyPost(req, res, '/folders', scopeResult.ctx.groupId, req.body);
};

export const deleteFolder = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid folder ID' });
  return proxyDelete(req, res, `/folders/${id}`, scopeResult.ctx.groupId);
};

// Plugins

export const listPluginFamilies = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  return proxyGet(req, res, '/plugins/families', scopeResult.ctx.groupId);
};

export const getPluginFamily = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid family ID' });
  return proxyGet(req, res, `/plugins/families/${id}`, scopeResult.ctx.groupId);
};

export const getPlugin = async (req: Request, res: Response) => {
  const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
  if (!scopeResult.ok) return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
  const id = parseIntParam(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid plugin ID' });
  return proxyGet(req, res, `/plugins/plugin/${id}`, scopeResult.ctx.groupId);
};
