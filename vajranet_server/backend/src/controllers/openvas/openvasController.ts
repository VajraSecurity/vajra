import { Request, Response, NextFunction } from 'express';
import { encrypt } from '../../utils/encryption';
import {
  executeGmpCommand,
  executeGmpPost,
  getOpenVASConfig,
  invalidateOpenVASClientCache,
  testConnectionWithConfig,
  OpenVASConnectionConfig,
} from '../../utils/openvasClient';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { parseAndValidateTargets } from '../network/targetValidation';
import { getLogger } from '../../utils/logger';
import { sanitizeAxiosError } from '../../utils/sanitizeAxiosError';
import {
  OPENVAS_DEFAULT_PORT_LIST_ID,
  OPENVAS_DEFAULT_SCANNER_ID,
  OPENVAS_DEFAULT_TARGET_PARAMS,
  OPENVAS_DEFAULT_TASK_PARAMS,
} from '../../consts/scanning';
import { EXTERNAL_API_TIMEOUT_MS } from '../../consts/timeout';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';
import { resolveScannerGroupContext, groupIdWhereValue } from '../../utils/scannerScope';
import { feedOpenvasReportInBackground } from '../../services/assetIdentity/openvasFeeder';

const logger = getLogger('controllers.openvas');

function paramStr(val: string | string[] | undefined): string {
  if (Array.isArray(val)) return val[0] || '';
  return val || '';
}

function ensureArray<T>(val: T | T[] | undefined | null): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

// Host validation. Uses the same shared, range-aware validator as nmap/nuclei:
// hostnames are deliberately rejected, because GVM would resolve them via DNS
// outside this check and make the private-range restriction unenforceable, and
// CIDR blocks are checked by their actual expanded range, not the leading octets.

function validateHosts(raw: string): string | null {
  const validated = parseAndValidateTargets(raw);
  return validated ? validated.join(',') : null;
}

// Type/length guards for the name/comment fields on the update* endpoints
// below (updateTarget/updateTask/updateCredential). hosts is the only field
// these forms validated before this -- name/comment were forwarded to GVM
// as-is, so a non-string body value would be passed straight into
// executeGmpPost's form params, and there was no upper bound on length at
// all. The limits are this codebase's own convention (255, matching
// node_rename.ts's name-length check), not a documented GVM server limit --
// they exist to reject an obviously-wrong or abusive request cleanly with a
// 400 rather than let it reach GVM as an opaque form post. create* has the
// same gap and is intentionally left alone here: out of scope for this pass,
// which only touches the update endpoints.
const MAX_OPENVAS_NAME_LENGTH = 255;
const MAX_OPENVAS_COMMENT_LENGTH = 1000;

/** name: required when present, must be a non-empty string within the bound. */
function isValidOptionalName(value: unknown, maxLength: number): boolean {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= maxLength;
}

/** comment: may legitimately be '' (clearing it) — only type and length are checked. */
function isValidOptionalComment(value: unknown, maxLength: number): boolean {
  return typeof value === 'string' && value.length <= maxLength;
}

function handleOpenVASError(res: Response, err: any, context?: Record<string, unknown>) {
  // executeGmpCommand/executeGmpPost rethrow their raw error unchanged (only
  // their own log line is sanitized), so this can still be an AxiosError
  // carrying the GSA session cookie/token in `err.config.headers`/`.url`, or
  // (for a login failure) the plaintext GMP password in `err.config.data` —
  // sanitize before logging for the same reason as openvasClient.ts's catches.
  logger.error({ err: sanitizeAxiosError(err), ...context }, 'OpenVAS API request failed');
  const msg = err.message || '';
  if (msg.includes('not configured')) {
    return res.status(400).json({ success: false, message: msg });
  }
  if (msg === 'Fleet database not available') {
    return res.status(503).json({ success: false, message: msg });
  }
  if (msg.includes('GSA login failed') || msg.includes('GMP 401') || msg.includes('GMP 403')) {
    return res.status(502).json({ success: false, message: `OpenVAS authentication failed. Check your GMP credentials in Settings.` });
  }
  if (msg.includes('ECONNREFUSED') || msg.includes('Connection refused')) {
    return res.status(502).json({ success: false, message: 'Cannot reach OpenVAS/GVM server. Verify the URL is correct and the server is running.' });
  }
  if (msg.includes('ECONNABORTED') || msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
    return res.status(504).json({ success: false, message: 'OpenVAS server took too long to respond' });
  }
  return res.status(500).json({ success: false, message: msg || 'Unexpected error communicating with OpenVAS' });
}

// Config endpoints

export const saveOpenVASConfig = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { gsa_url, gmp_username, gmp_password } = req.body;

    if (!gsa_url || typeof gsa_url !== 'string') {
      return res.status(400).json({ success: false, message: 'gsa_url is required (e.g. https://10.0.5.187)' });
    }
    if (!gmp_username || !gmp_password) {
      return res.status(400).json({ success: false, message: 'gmp_username and gmp_password are required' });
    }

    let urlClean = gsa_url.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(urlClean)) {
      urlClean = `https://${urlClean}`;
    }

    // Require a successful live connection test with these exact credentials
    // before persisting — same rationale as Nessus's saveNessusConfig, and
    // reuses the same testConnectionWithConfig path testOpenVASConnection
    // exposes standalone, so "Test Connection" and "Save" can never disagree.
    const testResult = await testConnectionWithConfig({ gsaUrl: urlClean, gmpUsername: gmp_username, gmpPassword: gmp_password });
    if (!testResult.success) {
      logger.warn({ groupId, message: testResult.message }, 'OpenVAS configuration save rejected: connection test failed');
      return res.status(400).json({
        success: false,
        message: `Connection test failed, configuration was not saved: ${testResult.message || 'unable to connect'}`,
      });
    }

    const encPassword = encrypt(gmp_password);

    const { dbSourceConnection } = await import('../../index');
    const { OpenVASConfig } = await import('../../orm/entities/fleet/OpenVASConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({}, 'OpenVAS configuration save aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(OpenVASConfig);
    await repo.update({ isActive: true, groupId: groupIdWhereValue(groupId) }, { isActive: false });

    const config = repo.create({
      groupId,
      nessusUrl: urlClean,
      gmpUsername: gmp_username,
      gmpPasswordEncrypted: encPassword.ciphertext,
      gmpPasswordIv: encPassword.iv,
      gmpPasswordAuthTag: encPassword.authTag,
      isActive: true,
      created_by_user_id: jwtFrom(req)?.id ?? null,
      created_by_name: jwtFrom(req)?.name ?? null,
    });

    await repo.save(config);
    invalidateOpenVASClientCache(groupId);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'OPENVAS_CONFIG',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'CONFIG_SAVED', gsa_url: urlClean },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ userId: jwt?.id ?? null }, 'OpenVAS configuration saved');
    return res.status(200).json({ success: true, message: 'OpenVAS configuration saved' });
  } catch (err: any) {
    logger.error({ err }, 'Failed to save OpenVAS configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to save OpenVAS configuration' });
  }
};

export const getOpenVASConfigEndpoint = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { dbSourceConnection } = await import('../../index');
    const { OpenVASConfig } = await import('../../orm/entities/fleet/OpenVASConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({}, 'OpenVAS configuration fetch aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(OpenVASConfig);
    const config = await repo.findOne({ where: { isActive: true, groupId: groupIdWhereValue(groupId) } });

    if (!config) {
      logger.debug({ groupId }, 'OpenVAS configuration retrieved: none configured');
      return res.status(200).json({ success: true, data: null });
    }

    logger.debug({ configId: config.id, groupId }, 'OpenVAS configuration retrieved');
    return res.status(200).json({
      success: true,
      data: {
        id: config.id,
        group_id: config.groupId,
        gsa_url: config.nessusUrl,
        gmp_username: config.gmpUsername,
        is_active: config.isActive,
        created_by_name: config.created_by_name,
        created_at: config.created_at,
        updated_at: config.updated_at,
      },
    });
  } catch (err: any) {
    logger.error({ err }, 'Failed to fetch OpenVAS configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to get OpenVAS configuration' });
  }
};

export const testOpenVASConnection = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { gsa_url, gmp_username, gmp_password } = req.body;

    if (!gsa_url || !gmp_username || !gmp_password) {
      return res.status(400).json({ success: false, message: 'gsa_url, gmp_username, and gmp_password are required' });
    }

    let urlClean = gsa_url.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(urlClean)) {
      urlClean = `https://${urlClean}`;
    }

    const config: OpenVASConnectionConfig = {
      gsaUrl: urlClean,
      gmpUsername: gmp_username,
      gmpPassword: gmp_password,
    };

    const result = await testConnectionWithConfig(config);
    logger.info({ success: result.success }, 'OpenVAS connection test completed');
    return res.status(200).json({
      success: result.success,
      data: result.success ? { version: result.version } : undefined,
      message: result.message,
    });
  } catch (err: any) {
    logger.warn({ err }, 'OpenVAS connection test failed');
    return res.status(200).json({ success: false, message: err.message || 'Connection test failed' });
  }
};

export const testStoredOpenVASConnection = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const config = await getOpenVASConfig(scopeResult.ctx.groupId);
    const result = await testConnectionWithConfig(config);
    logger.debug({ success: result.success }, 'Stored OpenVAS connection test completed');
    return res.status(200).json({
      success: result.success,
      data: result.success ? { version: result.version } : undefined,
      message: result.message,
    });
  } catch (err: any) {
    logger.warn({ err }, 'Stored OpenVAS connection test failed');
    return res.status(200).json({ success: false, message: err.message || 'Connection test failed' });
  }
};

export const deleteOpenVASConfig = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { dbSourceConnection } = await import('../../index');
    const { OpenVASConfig } = await import('../../orm/entities/fleet/OpenVASConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({}, 'OpenVAS configuration deletion aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(OpenVASConfig);
    await repo.update({ isActive: true, groupId: groupIdWhereValue(groupId) }, { isActive: false });
    invalidateOpenVASClientCache(groupId);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'OPENVAS_CONFIG',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'CONFIG_DELETED' },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({}, 'OpenVAS configuration removed');
    return res.status(200).json({ success: true, message: 'OpenVAS configuration removed' });
  } catch (err: any) {
    logger.error({ err }, 'Failed to delete OpenVAS configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to delete configuration' });
  }
};

// Server info

export const getGvmVersion = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const config = await getOpenVASConfig(scopeResult.ctx.groupId);
    const result = await testConnectionWithConfig(config);
    if (result.success) {
      logger.debug({ version: result.version }, 'GVM version retrieved');
      return res.status(200).json({ success: true, data: { version: result.version } });
    }
    return res.status(502).json({ success: false, message: result.message || 'Failed to get version' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_gvm_version' });
  }
};

// Scan configs (predefined scan profiles)

export const listScanConfigs = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_configs', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const configs = ensureArray(result?.get_configs_response?.config)
      .map((c: any) => ({
        id: c['@_id'],
        name: c.name,
        comment: c.comment || '',
        type: c.type,
        usage_type: c.usage_type || 'scan',
        in_use: c.in_use,
        family_count: c.family_count?.['#text'] ?? c.family_count ?? 0,
        nvt_count: c.nvt_count?.['#text'] ?? c.nvt_count ?? 0,
      }))
      .filter((c: any) => parseInt(c.family_count, 10) > 0);
    logger.debug({ count: configs.length }, 'OpenVAS scan configs retrieved');
    return res.status(200).json({ success: true, data: { configs } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_configs' });
  }
};

// Scanners

export const listScanners = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_scanners', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const scanners = ensureArray(result?.get_scanners_response?.scanner).map((s: any) => ({
      id: s['@_id'],
      name: s.name,
      type: s.type,
      host: s.host,
      port: s.port,
    }));
    logger.debug({ count: scanners.length }, 'OpenVAS scanners retrieved');
    return res.status(200).json({ success: true, data: { scanners } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_scanners' });
  }
};

// Targets

export const listTargets = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_targets', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const targets = ensureArray(result?.get_targets_response?.target).map((t: any) => ({
      id: t['@_id'],
      name: t.name,
      hosts: t.hosts,
      comment: t.comment || '',
      in_use: t.in_use,
      max_hosts: t.max_hosts,
      port_list: t.port_list ? { id: t.port_list['@_id'], name: t.port_list.name } : null,
      // GVM's <target> only carries a <ssh_credential id="..."/>/<smb_credential
      // id="..."/> child element when one is actually assigned — an unset
      // credential omits the element entirely rather than emitting id="0", so
      // a plain truthiness check here is correct (mirrors port_list above).
      ssh_credential: t.ssh_credential ? { id: t.ssh_credential['@_id'] } : null,
      smb_credential: t.smb_credential ? { id: t.smb_credential['@_id'] } : null,
    }));
    logger.debug({ count: targets.length }, 'OpenVAS targets retrieved');
    return res.status(200).json({ success: true, data: { targets } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_targets' });
  }
};

export const createTarget = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { name, hosts, port_list_id, comment } = req.body;
    if (!name || !hosts) {
      return res.status(400).json({ success: false, message: 'name and hosts are required' });
    }

    const validatedHosts = validateHosts(hosts);
    if (!validatedHosts) {
      return res.status(400).json({
        success: false,
        message: 'Invalid hosts. Only private network IPs/CIDRs (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) are allowed — hostnames are not accepted, and CIDR blocks must stay within a single allowed range.',
      });
    }

    // GVM's create_target requires this full field set; omitting any of them makes
    // it reject the request with a "Given <field> was invalid" action_result.
    // Same params as the manual target quickScan builds.
    const params: Record<string, string> = {
      ...OPENVAS_DEFAULT_TARGET_PARAMS,
      name,
      hosts: validatedHosts,
      comment: comment || '',
      port_list_id: port_list_id || OPENVAS_DEFAULT_PORT_LIST_ID,
      ssh_credential_id: '0',
      smb_credential_id: '0',
    };

    const result = await executeGmpPost(groupId, 'create_target', params);
    let id = result?.action_result?.id || result?.create_target_response?.['@_id'];
    if (!id) {
      // Belt-and-braces: resolve by name if GVM didn't inline an id.
      const targets = await executeGmpCommand(groupId, 'get_targets', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const allTargets = ensureArray(targets?.get_targets_response?.target);
      id = allTargets.find((t: any) => t.name === name)?.['@_id'];
    }
    if (!id) {
      // Distinguishes "GVM accepted the request but we couldn't resolve an id
      // either inline or by name lookup" from a normal success — without this,
      // the info log below would read identically to a working creation while
      // the response silently carries data.id = undefined.
      logger.warn({ name }, 'OpenVAS target created but its ID could not be resolved by inline response or name lookup');
    }
    logger.info({ targetId: id, name }, 'OpenVAS target created');
    return res.status(200).json({ success: true, data: { id } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'create_target', name: req.body?.name });
  }
};

export const deleteTarget = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Target ID is required' });
    await executeGmpPost(scopeResult.ctx.groupId, 'delete_target', { target_id: id });
    logger.info({ targetId: id }, 'OpenVAS target deleted');
    return res.status(200).json({ success: true, message: 'Target deleted' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'delete_target', targetId: req.params.id });
  }
};

export const updateTarget = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Target ID is required' });

    const { name, hosts, ssh_credential_id, smb_credential_id, comment } = req.body;
    if (name === undefined && hosts === undefined && ssh_credential_id === undefined && smb_credential_id === undefined && comment === undefined) {
      return res.status(400).json({ success: false, message: 'At least one of name, hosts, ssh_credential_id, smb_credential_id, or comment must be supplied' });
    }
    if (name !== undefined && !isValidOptionalName(name, MAX_OPENVAS_NAME_LENGTH)) {
      return res.status(400).json({ success: false, message: `name must be a non-empty string of at most ${MAX_OPENVAS_NAME_LENGTH} characters` });
    }
    if (comment !== undefined && !isValidOptionalComment(comment, MAX_OPENVAS_COMMENT_LENGTH)) {
      return res.status(400).json({ success: false, message: `comment must be a string of at most ${MAX_OPENVAS_COMMENT_LENGTH} characters` });
    }

    let validatedHosts: string | undefined;
    if (hosts !== undefined) {
      const v = validateHosts(hosts);
      if (!v) {
        return res.status(400).json({
          success: false,
          message: 'Invalid hosts. Only private network IPs/CIDRs (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) are allowed — hostnames are not accepted, and CIDR blocks must stay within a single allowed range.',
        });
      }
      validatedHosts = v;
    }

    // gsad's web-form command for editing a target is `save_target`, not the
    // raw GMP protocol's `modify_target` -- this gsad build (27.2.0) rejects
    // `modify_target` outright with a generic "Invalid command" error,
    // confirmed by direct testing against this exact GVM instance. Like
    // save_task, save_target is a full HTML-form resubmission requiring the
    // target's ENTIRE field set every time (a partial GMP-protocol patch is
    // not accepted) -- so the current object is fetched first and every
    // unsupplied field is carried over unchanged, the same way updateTask
    // does for save_task.
    //
    // Unlike a task's target_id/config_id/scanner_id (which accept a '0'
    // sentinel to mean "leave unchanged" once the task has run), GVM refuses
    // save_target OUTRIGHT -- even a fully unchanged resubmission -- for ANY
    // target currently `in_use`. Confirmed by real end-to-end HTTP testing
    // that `in_use` flips to '1' the moment ANY task is created referencing
    // this target, regardless of whether that task has ever been started --
    // "in use" means "assigned to a scan", not "that scan has run". There is
    // no sentinel workaround for this. So this must be checked and reported
    // clearly up front, rather than let GVM's opaque "Target is in use"
    // surface as a raw, unexplained GMP error.
    const allTargets = await executeGmpCommand(groupId, 'get_targets', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const current = ensureArray(allTargets?.get_targets_response?.target).find((t: any) => t['@_id'] === id);
    if (!current) {
      return res.status(404).json({ success: false, message: 'Target not found' });
    }
    if (String(current.in_use) === '1') {
      return res.status(409).json({
        success: false,
        message: 'This target is assigned to a scan. GVM marks a target "in use" as soon as any scan references it — even one that has never run — and does not allow editing its hosts or credentials in that state. Delete and recreate the scan to point it at different hosts.',
      });
    }

    // GVM's own convention for "no credential" (see createTarget/quickScan
    // above, which always send '0' rather than omitting the field) — an
    // empty-string selection from the UI means "clear this credential".
    const params: Record<string, string> = {
      target_id: id,
      name: name !== undefined ? name : current.name,
      hosts: validatedHosts !== undefined ? validatedHosts : current.hosts,
      exclude_hosts: '',
      comment: comment !== undefined ? comment : (current.comment || ''),
      port_list_id: current.port_list?.['@_id'] || OPENVAS_DEFAULT_PORT_LIST_ID,
      ssh_credential_id: ssh_credential_id !== undefined
        ? (ssh_credential_id === '' ? '0' : ssh_credential_id)
        : (current.ssh_credential?.['@_id'] || '0'),
      smb_credential_id: smb_credential_id !== undefined
        ? (smb_credential_id === '' ? '0' : smb_credential_id)
        : (current.smb_credential?.['@_id'] || '0'),
      ssh_elevate_credential_id: '0',
      esxi_credential_id: '0',
      reverse_lookup_only: '0',
      reverse_lookup_unify: '0',
      'alive_tests:': 'Scan Config Default',
      port: '22',
      target_source: 'manual',
      target_exclude_source: 'manual',
      allow_simultaneous_ips: '1',
      hosts_ordering: '',
    };

    await executeGmpPost(groupId, 'save_target', params);

    const updatedFields = [
      ...(name !== undefined ? ['name'] : []),
      ...(hosts !== undefined ? ['hosts'] : []),
      ...(ssh_credential_id !== undefined ? ['ssh_credential_id'] : []),
      ...(smb_credential_id !== undefined ? ['smb_credential_id'] : []),
      ...(comment !== undefined ? ['comment'] : []),
    ];

    // createTarget/deleteTarget don't write an audit-trail entry for target
    // mutations (only logger.info) — mirrors that existing convention rather
    // than introducing a new audit action for targets alone.
    logger.info({ targetId: id, fields: updatedFields }, 'OpenVAS target updated');
    return res.status(200).json({ success: true, message: 'Target updated' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'save_target', targetId: req.params.id });
  }
};

// Tasks (scans)

export const listTasks = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_tasks', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const tasks = ensureArray(result?.get_tasks_response?.task).map((t: any) => ({
      id: t['@_id'],
      name: t.name,
      comment: t.comment || '',
      status: t.status,
      progress: t.progress,
      trend: t.trend,
      target: t.target ? { id: t.target['@_id'], name: t.target.name } : null,
      scanner: t.scanner ? { id: t.scanner['@_id'], name: t.scanner.name } : null,
      config: t.config ? { id: t.config['@_id'], name: t.config.name } : null,
      last_report: t.last_report?.report ? {
        id: t.last_report.report['@_id'],
        timestamp: t.last_report.report.timestamp,
        severity: t.last_report.report.severity?.full || t.last_report.report.severity,
        result_count: t.last_report.report.result_count,
      } : null,
      report_count: t.report_count?.['#text'] || t.report_count || 0,
      creation_time: t.creation_time,
      modification_time: t.modification_time,
    }));
    logger.debug({ count: tasks.length }, 'OpenVAS tasks retrieved');
    return res.status(200).json({ success: true, data: { tasks } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_tasks' });
  }
};

export const createTask = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { name, target_id, config_id, scanner_id, comment } = req.body;
    if (!name || !target_id || !config_id) {
      return res.status(400).json({ success: false, message: 'name, target_id, and config_id are required' });
    }

    const params: Record<string, string> = {
      ...OPENVAS_DEFAULT_TASK_PARAMS,
      name,
      target_id,
      config_id,
      scanner_id: scanner_id || OPENVAS_DEFAULT_SCANNER_ID,
      // Confirmed live (real-HTTP E2E test, not just GVM-direct curl): unlike
      // create_target, this GVM instance rejects create_task outright
      // ("Given comment was invalid") when comment is empty/omitted — same
      // rule create_credential already works around below.
      comment: comment && comment.trim() ? comment : ' ',
    };

    const result = await executeGmpPost(groupId, 'create_task', params);
    const id = result?.action_result?.id || result?.create_task_response?.['@_id'];
    if (!id) {
      // Same ambiguity as createTarget above: GVM returned success but neither
      // the action_result nor the create_task_response carried an id, so the
      // caller gets data.id = undefined without this flagging why.
      logger.warn({ name, target_id, config_id }, 'OpenVAS task created but its ID could not be resolved from the GVM response');
    }

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'OPENVAS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'TASK_CREATED', name, target_id, config_id, task_id: id },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ taskId: id, name, target_id, config_id }, 'OpenVAS task created');
    return res.status(200).json({ success: true, data: { id } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'create_task', name: req.body?.name, target_id: req.body?.target_id });
  }
};

export const updateTask = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Task ID is required' });

    const { name, target_id, config_id, scanner_id, comment } = req.body;
    if (name === undefined && target_id === undefined && config_id === undefined && scanner_id === undefined && comment === undefined) {
      return res.status(400).json({ success: false, message: 'At least one of name, target_id, config_id, scanner_id, or comment must be supplied' });
    }
    if (name !== undefined && !isValidOptionalName(name, MAX_OPENVAS_NAME_LENGTH)) {
      return res.status(400).json({ success: false, message: `name must be a non-empty string of at most ${MAX_OPENVAS_NAME_LENGTH} characters` });
    }
    if (comment !== undefined && !isValidOptionalComment(comment, MAX_OPENVAS_COMMENT_LENGTH)) {
      return res.status(400).json({ success: false, message: `comment must be a string of at most ${MAX_OPENVAS_COMMENT_LENGTH} characters` });
    }

    // gsad's web-form command for editing a task is `save_task`, not the raw
    // GMP protocol's `modify_task` -- this gsad build (27.2.0) rejects
    // `modify_task` outright with a generic, unhelpful "Invalid command"
    // error, confirmed by direct testing against this exact GVM instance.
    // Unlike modify_task (a partial GMP-protocol patch), save_task is a full
    // HTML-form resubmission: it requires the task's ENTIRE field set every
    // time, so the current task is fetched first (same fetch-all-then-find
    // pattern getTaskDetails already uses — a `{ task_id: id }` query param
    // is NOT a real server-side filter for get_tasks in this GVM version;
    // it is silently ignored and returns an arbitrary task instead, which is
    // exactly the bug that left deleteTask's target cleanup resolving the
    // wrong task's target).
    //
    // Separately, and confirmed by direct testing: GVM refuses ANY value for
    // target_id/config_id/scanner_id -- even the task's own current,
    // unchanged one -- once the task has ever run (status other than 'New').
    // '0' is gsad's own sentinel for "leave this unchanged" in that state.
    // So a request to actually change one of these on an already-run task
    // must be rejected clearly up front, rather than silently ignored or
    // left to surface as an opaque GMP error.
    const allTasks = await executeGmpCommand(groupId, 'get_tasks', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const current = ensureArray(allTasks?.get_tasks_response?.task).find((t: any) => t['@_id'] === id);
    if (!current) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }
    const isNew = current.status === 'New';
    const currentTargetId = current.target?.['@_id'] ?? '0';
    const currentConfigId = current.config?.['@_id'] ?? '0';
    const currentScannerId = current.scanner?.['@_id'] ?? '0';

    if (!isNew) {
      const wantsTargetChange = target_id !== undefined && target_id !== currentTargetId;
      const wantsConfigChange = config_id !== undefined && config_id !== currentConfigId;
      const wantsScannerChange = scanner_id !== undefined && scanner_id !== currentScannerId;
      if (wantsTargetChange || wantsConfigChange || wantsScannerChange) {
        return res.status(409).json({
          success: false,
          message: 'GVM does not allow changing the target, scan configuration, or scanner of a scan that has already run — delete and recreate it to point at something different.',
        });
      }
    }

    const params: Record<string, string> = {
      task_id: id,
      name: name !== undefined ? name : current.name,
      comment: comment !== undefined ? comment : (current.comment || ''),
      target_id: isNew ? (target_id ?? currentTargetId) : '0',
      config_id: isNew ? (config_id ?? currentConfigId) : '0',
      scanner_id: isNew ? (scanner_id ?? currentScannerId) : '0',
      schedule_id: '0',
      schedule_periods: '0',
      in_assets: '1',
      apply_overrides: '1',
      min_qod: '70',
      alterable: '0',
      auto_delete: 'no',
      auto_delete_data: '5',
      max_checks: '4',
      max_hosts: '20',
      source_iface: '',
      hosts_ordering: '',
    };

    await executeGmpPost(groupId, 'save_task', params);

    const updatedFields = [
      ...(name !== undefined ? ['name'] : []),
      ...(target_id !== undefined ? ['target_id'] : []),
      ...(config_id !== undefined ? ['config_id'] : []),
      ...(scanner_id !== undefined ? ['scanner_id'] : []),
      ...(comment !== undefined ? ['comment'] : []),
    ];

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'OPENVAS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'TASK_UPDATED', task_id: id, fields: updatedFields },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ taskId: id, fields: updatedFields }, 'OpenVAS task updated');
    return res.status(200).json({ success: true, message: 'Task updated' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'save_task', taskId: req.params.id });
  }
};

export const startTask = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Task ID is required' });

    const result = await executeGmpPost(scopeResult.ctx.groupId, 'start_task', { task_id: id });
    const reportId = result?.start_task_response?.report_id || null;

    logger.info({ taskId: id, reportId }, 'OpenVAS task started');

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'OPENVAS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'TASK_STARTED', task_id: id, report_id: reportId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    return res.status(200).json({ success: true, data: { report_id: reportId } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'start_task', taskId: req.params.id });
  }
};

export const stopTask = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Task ID is required' });
    await executeGmpPost(scopeResult.ctx.groupId, 'stop_task', { task_id: id });
    logger.info({ taskId: id }, 'OpenVAS task stopped');
    return res.status(200).json({ success: true, message: 'Task stopped' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'stop_task', taskId: req.params.id });
  }
};

export const resumeTask = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Task ID is required' });
    await executeGmpPost(scopeResult.ctx.groupId, 'resume_task', { task_id: id });
    logger.info({ taskId: id }, 'OpenVAS task resumed');
    return res.status(200).json({ success: true, message: 'Task resumed' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'resume_task', taskId: req.params.id });
  }
};

export const deleteTask = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Task ID is required' });

    // Resolve the task's target before deleting it. GVM keeps tasks and
    // targets as separate objects — delete_task alone never touches the
    // target, so without this every deleted scan leaves its target behind
    // in GVM and the next scan created against the same host fails with
    // "target already exists" (create_target rejects a duplicate
    // name/hosts combination). Resolved server-side via get_tasks — fetching
    // ALL tasks and finding the match client-side (the same pattern
    // getTaskDetails/updateTask use), NOT via a `{ task_id: id }` query
    // param: that is not a real server-side filter for get_tasks in this GVM
    // version, and is silently ignored, returning an ARBITRARY task instead
    // (confirmed by direct testing) — which was silently resolving the wrong
    // task's target here before this fix, rather than the deleted task's own.
    // Filtering client-side rather than trusting a client-supplied target_id
    // is still the right call: deleting the wrong target on a
    // client-guessed id would be a real hazard.
    let targetId: string | null = null;
    try {
      const taskLookup = await executeGmpCommand(groupId, 'get_tasks', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const found = ensureArray(taskLookup?.get_tasks_response?.task).find((t: any) => t['@_id'] === id);
      targetId = found?.target?.['@_id'] || null;
    } catch (err: any) {
      logger.warn({ err: sanitizeAxiosError(err), taskId: id }, 'Failed to resolve target for OpenVAS task before deletion; target cleanup will be skipped');
    }

    await executeGmpPost(groupId, 'delete_task', { task_id: id });

    // Best-effort target cleanup, same error-tolerant pattern as quickScan's
    // orphaned-target rollback (~line 1045 above): must never fail the task
    // deletion itself, which has already succeeded by this point. GVM
    // legitimately rejects delete_target with an "in use" style error when
    // another task still references the same target (e.g. two scans created
    // against the same target) — that's an expected, logged, non-fatal
    // outcome, not a bug, and the same applies if the target is already gone.
    let targetDeleted = false;
    if (targetId) {
      try {
        await executeGmpPost(groupId, 'delete_target', { target_id: targetId });
        targetDeleted = true;
      } catch (err: any) {
        logger.warn({ err: sanitizeAxiosError(err), targetId, taskId: id }, 'Could not delete OpenVAS target after task deletion (likely still in use by another task) — leaving it in place');
      }
    }

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'OPENVAS_SCAN',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'TASK_DELETED', task_id: id, target_id: targetId, target_deleted: targetDeleted },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ taskId: id, targetId, targetDeleted }, 'OpenVAS task deleted');
    return res.status(200).json({ success: true, message: 'Task deleted' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'delete_task', taskId: req.params.id });
  }
};

export const getTaskDetails = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Task ID is required' });

    const result = await executeGmpCommand(groupId, 'get_tasks', undefined, 90_000, { filter: 'rows=-1' });
    const allTasks = ensureArray(result?.get_tasks_response?.task);
    const t = allTasks.find((task: any) => task['@_id'] === id);
    if (!t) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }

    // GVM's get_tasks response never actually populates a task's <target>
    // beyond id/name/trash, or a full <report> history beyond
    // last_report/current_report -- confirmed live against this exact GVM
    // instance, even for a task with report_count=5 -- despite this
    // endpoint's response shape looking like it should carry both. Two
    // follow-up lookups fill in the real `target.hosts` and `reports` values.
    //
    // For hosts: a `target_id=` query param on get_targets is, like
    // `task_id=` on get_tasks elsewhere in this file (see updateTask/
    // deleteTask above), NOT a real server-side filter in this GVM version --
    // confirmed by direct testing, it is silently ignored and the full,
    // unfiltered target list is returned regardless. So this reuses the same
    // proven fetch-all-then-find-by-id pattern as the rest of this file
    // rather than trusting that param.
    //
    // For reports: unlike those `*_id=` params, get_reports's
    // `filter=task_id=<id>` IS a real, working server-side filter --
    // confirmed live to return a task's complete report history (every past
    // report, not just the latest) -- so this fetches only this task's
    // reports instead of every report on the server.
    const [targetsResult, reportsResult] = await Promise.all([
      t.target
        ? executeGmpCommand(groupId, 'get_targets', undefined, 90_000, { filter: 'rows=-1' })
        : Promise.resolve(null),
      executeGmpCommand(groupId, 'get_reports', undefined, 90_000, { filter: `task_id=${id}` }),
    ]);

    const targetHosts = t.target
      ? ensureArray(targetsResult?.get_targets_response?.target).find((tg: any) => tg['@_id'] === t.target['@_id'])?.hosts
      : undefined;

    // get_reports wraps each report the same way get_report does its single
    // one (see getReport below): an outer <report> envelope (owner/name/
    // creation_time and a bare task ref) around an inner <report> that
    // actually carries timestamp/severity/result_count -- `r.report || r`
    // covers both shapes defensively, mirroring getReport's own fallback.
    const reports = ensureArray(reportsResult?.get_reports_response?.report).map((r: any) => {
      const inner = r.report || r;
      return {
        id: r['@_id'] || inner['@_id'],
        timestamp: inner.timestamp,
        severity: inner.severity?.full || inner.severity,
        result_count: inner.result_count?.['#text'] ?? inner.result_count,
      };
    });

    logger.debug({ taskId: id, reportCount: reports.length }, 'OpenVAS task details retrieved');
    return res.status(200).json({
      success: true,
      data: {
        id: t['@_id'],
        name: t.name,
        comment: t.comment || '',
        status: t.status,
        progress: t.progress,
        trend: t.trend,
        target: t.target ? { id: t.target['@_id'], name: t.target.name, hosts: targetHosts } : null,
        scanner: t.scanner ? { id: t.scanner['@_id'], name: t.scanner.name } : null,
        config: t.config ? { id: t.config['@_id'], name: t.config.name } : null,
        last_report: t.last_report?.report ? {
          id: t.last_report.report['@_id'],
          timestamp: t.last_report.report.timestamp,
          severity: t.last_report.report.severity?.full || t.last_report.report.severity,
        } : null,
        reports,
        report_count: t.report_count?.['#text'] || t.report_count || 0,
        creation_time: t.creation_time,
        modification_time: t.modification_time,
      },
    });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_tasks(details)', taskId: req.params.id });
  }
};

// Reports

export const getReport = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Report ID is required' });

    const result = await executeGmpCommand(
      scopeResult.ctx.groupId,
      'get_report',
      undefined,
      180_000,
      { report_id: id, ignore_pagination: '1', details: '1' },
    );

    const reportWrapper = result?.get_report_response || result?.get_reports_response;
    const reports = ensureArray(reportWrapper?.report);
    if (!reports.length) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }

    const report = reports[0];
    const inner = report.report || report;
    const results = ensureArray(inner.results?.result).map((r: any) => {
      const nvtName = r.nvt?.name || '';
      const hostRaw = r.host;
      const host = typeof hostRaw === 'string' ? hostRaw : (hostRaw?.['#text'] || hostRaw?.ip || '');

      let port = r.port || '';
      if (!port) {
        const details = ensureArray(r.detection?.result?.details?.detail);
        const loc = details.find((d: any) => d.name === 'location');
        if (loc) port = loc.value || '';
      }

      return {
        id: r['@_id'],
        name: nvtName,
        host,
        port,
        severity: r.severity,
        threat: r.threat,
        description: r.description,
        nvt: r.nvt ? {
          oid: r.nvt['@_oid'],
          name: r.nvt.name,
          family: r.nvt.family || (r.nvt.type === 'cve' ? 'CVE' : '') || '',
          cvss_base: r.nvt.cvss_base || r.nvt.severities?.['@_score'] || '',
          cve: r.nvt.cve,
          tags: r.nvt.tags,
          type: r.nvt.type || '',
        } : null,
      };
    });

    const severityCounts = { high: 0, medium: 0, low: 0, log: 0 };
    for (const r of results) {
      const sev = parseFloat(r.severity);
      if (sev >= 7.0) severityCounts.high++;
      else if (sev >= 4.0) severityCounts.medium++;
      else if (sev > 0) severityCounts.low++;
      else severityCounts.log++;
    }

    // GVM hangs the per-host facts off `report.host[].detail` as a flat list of
    // {name, value} pairs. This mapper used to keep only {ip, start, end} and
    // drop `detail` on the floor, which threw away the MAC (identity weight
    // 80), the reverse-DNS hostname (40) and the OS guess (10) — i.e. every
    // piece of evidence strong enough to tie an OpenVAS report to the
    // agent-reported host it actually concerns.
    //
    // BUG FIX (SPEC.md Addendum 3, verified live against a real report): GVM's
    // per-host <detail> list has NO entry named `hostname` — the real field is
    // `fqdn`. This mapper (and openvasFeeder.ts's own copy, used for asset
    // identity resolution below) previously looked up `hostname` and silently
    // got null every time.
    const hosts = ensureArray(inner.host).map((h: any) => {
      const details = ensureArray(h.detail);
      const detailValue = (name: string): string | null => {
        const found = details.find((d: any) => d && d.name === name);
        const value = found?.value;
        return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
      };
      return {
        ip: h.ip,
        start: h.start,
        end: h.end,
        mac: detailValue('MAC'),
        hostname: detailValue('fqdn'),
        // best_os_txt is the human string ("Microsoft Windows 11"); the CPE is
        // the fallback, and normalizeOsFamily() collapses either to a family.
        os: detailValue('best_os_txt') ?? detailValue('best_os_cpe'),
      };
    });

    logger.debug({ reportId: id, resultCount: results.length }, 'OpenVAS report retrieved');

    // Fire-and-forget asset identity resolution, through the SAME shared
    // function the automatic poller (services/assetIdentity/openvasFeeder.ts,
    // Addendum 3) uses, on the raw report body — so the authentication gate
    // and the fqdn fix can never drift between this view-triggered path and
    // the automatic one. This call returns synchronously and swallows every
    // error — viewing a report must never fail, hang, or slow down because
    // asset resolution had a bad day.
    feedOpenvasReportInBackground(String(id), inner);

    return res.status(200).json({
      success: true,
      data: {
        id: report['@_id'],
        timestamp: inner.timestamp || inner.creation_time,
        scan_start: inner.scan_start,
        scan_end: inner.scan_end,
        severity_counts: severityCounts,
        result_count: results.length,
        results,
        hosts,
      },
    });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_report', reportId: req.params.id });
  }
};

// Port lists

export const listPortLists = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_port_lists', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const raw = result?.get_port_lists_response?.port_list;
    const portLists = ensureArray(raw).map((p: any) => ({
      id: p['@_id'],
      name: p.name,
      comment: p.comment || '',
      port_count: p.port_count?.all || 0,
      in_use: p.in_use,
    }));
    logger.debug({ count: portLists.length }, 'OpenVAS port lists retrieved');
    return res.status(200).json({ success: true, data: { port_lists: portLists } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_port_lists' });
  }
};

// Report formats

export const listReportFormats = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_report_formats', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const formats = ensureArray(result?.get_report_formats_response?.report_format).map((f: any) => ({
      id: f['@_id'],
      name: f.name,
      summary: f.summary || '',
      extension: f.extension,
      content_type: f.content_type,
    }));
    logger.debug({ count: formats.length }, 'OpenVAS report formats retrieved');
    return res.status(200).json({ success: true, data: { formats } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_report_formats' });
  }
};

// Feeds

export const getFeedStatus = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_feeds');
    logger.debug({}, 'OpenVAS feed status retrieved');
    return res.status(200).json({ success: true, data: result });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_feeds' });
  }
};

// Credentials

export const listCredentials = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const result = await executeGmpCommand(scopeResult.ctx.groupId, 'get_credentials', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const creds = ensureArray(result?.get_credentials_response?.credential).map((c: any) => ({
      id: c['@_id'],
      name: c.name,
      type: c.type,
      login: c.login,
      comment: c.comment || '',
      in_use: c.in_use,
    }));
    logger.debug({ count: creds.length }, 'OpenVAS credentials retrieved');
    return res.status(200).json({ success: true, data: { credentials: creds } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'get_credentials' });
  }
};

export const createCredential = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { name, type, login, password, comment } = req.body;
    if (!name || !type || !login || !password) {
      return res.status(400).json({ success: false, message: 'name, type, login, and password are required' });
    }

    const validTypes = ['up', 'usk', 'snmp'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ success: false, message: `type must be one of: ${validTypes.join(', ')}` });
    }

    const params: Record<string, string> = {
      name,
      credential_type: type,
      credential_login: login,
      lsc_password: password,
      autogenerate: '0',
      // Unlike create_target, GVM's create_credential rejects an empty or omitted
      // comment outright ("Given comment was invalid"), so it is never optional.
      comment: comment && comment.trim() ? comment : ' ',
    };

    const result = await executeGmpPost(groupId, 'create_credential', params);
    const id = result?.action_result?.id || result?.create_credential_response?.['@_id'];
    if (!id) {
      // Same ambiguity as createTarget/createTask: GVM returned success but no
      // id was present in the response, so the caller gets data.id = undefined
      // without this flagging why.
      logger.warn({ name, type }, 'OpenVAS credential created but its ID could not be resolved from the GVM response');
    }

    logger.info({ credentialId: id, type }, 'OpenVAS credential created');
    return res.status(200).json({ success: true, data: { id } });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'create_credential', name: req.body?.name, type: req.body?.type });
  }
};

export const updateCredential = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Credential ID is required' });

    const { name, login, password, comment } = req.body;
    if (name === undefined && login === undefined && password === undefined && comment === undefined) {
      return res.status(400).json({ success: false, message: 'At least one of name, login, password, or comment must be supplied' });
    }
    if (name !== undefined && !isValidOptionalName(name, MAX_OPENVAS_NAME_LENGTH)) {
      return res.status(400).json({ success: false, message: `name must be a non-empty string of at most ${MAX_OPENVAS_NAME_LENGTH} characters` });
    }
    if (comment !== undefined && !isValidOptionalComment(comment, MAX_OPENVAS_COMMENT_LENGTH)) {
      return res.status(400).json({ success: false, message: `comment must be a string of at most ${MAX_OPENVAS_COMMENT_LENGTH} characters` });
    }

    // gsad's web-form command for editing a credential is `save_credential`,
    // not the raw GMP protocol's `modify_credential` -- this gsad build
    // (27.2.0) rejects `modify_credential` outright with a generic "Invalid
    // command" error, confirmed by direct testing against this exact GVM
    // instance. save_credential is a full HTML-form resubmission and, unlike
    // save_task/save_target, requires `credential_type` to be resent every
    // time even when unchanged (confirmed by direct testing) -- `type` is
    // deliberately not accepted from the caller at all: GVM ties a
    // credential's other fields to its type (up/usk/snmp each need a
    // different field set), and this codebase's create flow already treats
    // type as fixed at creation, so changing it isn't supported — the
    // existing type is simply fetched and resent unchanged. Unlike a
    // target, GVM does not appear to gate save_credential on `in_use` (a
    // credential already in use by a running/completed scan was
    // successfully edited during testing), so no such check is needed here.
    const allCreds = await executeGmpCommand(groupId, 'get_credentials', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
    const current = ensureArray(allCreds?.get_credentials_response?.credential).find((c: any) => c['@_id'] === id);
    if (!current) {
      return res.status(404).json({ success: false, message: 'Credential not found' });
    }

    const effectiveLogin = login !== undefined ? login : current.login;
    const effectiveComment = comment !== undefined ? comment : (current.comment || '');
    const params: Record<string, string> = {
      credential_id: id,
      name: name !== undefined ? name : current.name,
      // Same rule as create_credential: GVM rejects an empty/omitted comment
      // outright, so it is never sent blank.
      comment: effectiveComment.trim() ? effectiveComment : ' ',
      login: effectiveLogin,
      credential_login: effectiveLogin,
      credential_type: current.type,
    };
    // Only forward a password if the caller actually typed a new one. GVM
    // doesn't return the stored password (listCredentials never exposes
    // one), so the UI can't pre-fill or diff it — and sending an empty
    // string would still count as "a value was given," which could
    // blank/rotate the credential to an empty password the user never asked
    // to set. Leaving the field out entirely keeps it unchanged. Mirrors
    // create_credential's own field names/autogenerate convention.
    if (password) {
      params.lsc_password = password;
      params.autogenerate = '0';
    }

    await executeGmpPost(groupId, 'save_credential', params);

    const updatedFields = [
      ...(name !== undefined ? ['name'] : []),
      ...(login !== undefined ? ['login'] : []),
      ...(password ? ['password'] : []),
      ...(comment !== undefined ? ['comment'] : []),
    ];

    // createCredential/deleteCredential don't write an audit-trail entry for
    // credential mutations in this file (unlike OPENVAS_CONFIG/OPENVAS_SCAN
    // above) — only logger.info — so this mirrors that existing convention
    // rather than introducing a new audit action for credentials alone.
    logger.info({ credentialId: id, fields: updatedFields }, 'OpenVAS credential updated');
    return res.status(200).json({ success: true, message: 'Credential updated' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'save_credential', credentialId: req.params.id });
  }
};

export const deleteCredential = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const id = paramStr(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: 'Credential ID is required' });
    await executeGmpPost(scopeResult.ctx.groupId, 'delete_credential', { credential_id: id });
    logger.info({ credentialId: id }, 'OpenVAS credential deleted');
    return res.status(200).json({ success: true, message: 'Credential deleted' });
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'delete_credential', credentialId: req.params.id });
  }
};

// Quick scan

export const quickScan = async (req: Request, res: Response) => {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { name, hosts, config_id, scanner_id, ssh_credential_id, smb_credential_id } = req.body;
    if (!name || !hosts || !config_id) {
      return res.status(400).json({ success: false, message: 'name, hosts, and config_id are required' });
    }

    const validatedHosts = validateHosts(hosts);
    if (!validatedHosts) {
      return res.status(400).json({
        success: false,
        message: 'Invalid hosts. Only private network IPs/CIDRs (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) are allowed — hostnames are not accepted, and CIDR blocks must stay within a single allowed range.',
      });
    }

    const isCredentialed = !!(ssh_credential_id || smb_credential_id);

    // Always use manual flow — the quick_task wizard doesn't properly link scan configs
    {
      const targetParams: Record<string, string> = {
        ...OPENVAS_DEFAULT_TARGET_PARAMS,
        name: name + ' - Target',
        hosts: validatedHosts,
        comment: '',
        port_list_id: OPENVAS_DEFAULT_PORT_LIST_ID,
        ssh_credential_id: ssh_credential_id || '0',
        smb_credential_id: smb_credential_id || '0',
      };

      const targetResult = await executeGmpPost(groupId, 'create_target', targetParams);
      const targetId = targetResult?.create_target_response?.['@_id'];
      if (!targetId) {
        const msg = targetResult?.action_result?.message;
        if (!msg || !msg.includes('resource created')) {
          logger.warn({ name, hosts: validatedHosts, message: msg }, 'OpenVAS quick scan aborted: create_target did not report success');
          return res.status(500).json({ success: false, message: msg || 'Failed to create target' });
        }
      }

      // If ID came from action_result, fetch it from targets list
      let resolvedTargetId = targetId;
      if (!resolvedTargetId) {
        const targets = await executeGmpCommand(groupId, 'get_targets', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
        const allTargets = ensureArray(targets?.get_targets_response?.target);
        const created = allTargets.find((t: any) => t.name === name + ' - Target');
        resolvedTargetId = created?.['@_id'];
      }
      if (!resolvedTargetId) {
        logger.warn({ name, hosts: validatedHosts }, 'OpenVAS quick scan aborted: target was reported created but its ID could not be resolved');
        return res.status(500).json({ success: false, message: 'Target created but ID could not be resolved' });
      }

      const taskParams: Record<string, string> = {
        ...OPENVAS_DEFAULT_TASK_PARAMS,
        name,
        comment: '',
        target_id: resolvedTargetId,
        config_id,
        scanner_id: scanner_id || OPENVAS_DEFAULT_SCANNER_ID,
      };
      const taskResult = await executeGmpPost(groupId, 'create_task', taskParams);
      let taskId = taskResult?.create_task_response?.['@_id'];
      if (!taskId) {
        const msg = taskResult?.action_result?.message;
        if (!msg || !msg.includes('created')) {
          logger.warn({ name, target_id: resolvedTargetId, message: msg }, 'OpenVAS quick scan aborted: create_task did not report success, cleaning up target');
          executeGmpPost(groupId, 'delete_target', { target_id: resolvedTargetId }).catch(err =>
            logger.warn({ err: sanitizeAxiosError(err), target_id: resolvedTargetId }, 'Failed to clean up orphaned OpenVAS target after task creation failure')
          );
          return res.status(500).json({ success: false, message: msg || 'Failed to create task' });
        }
        const tasks = await executeGmpCommand(groupId, 'get_tasks', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
        const allTasks = ensureArray(tasks?.get_tasks_response?.task);
        const created = allTasks.find((t: any) => t.name === name);
        taskId = created?.['@_id'];
      }

      let started = false;
      let startError: string | undefined;
      if (taskId) {
        try {
          await executeGmpPost(groupId, 'start_task', { task_id: taskId });
          started = true;
        } catch (err: any) {
          logger.warn({ err: sanitizeAxiosError(err), taskId }, 'OpenVAS quick scan task was created but failed to start');
          startError = err?.message || 'Failed to start task';
        }
      }

      const jwt = jwtFrom(req);
      if (jwt?.id) {
        logAuditTrail({
          action: 'OPENVAS_SCAN',
          status: started ? 'success' : 'failure',
          userId: jwt.id,
          email: jwt.email ?? null,
          ipAddress: clientIpFrom(req),
          userAgent: null,
          details: { event: 'QUICK_SCAN', name, hosts: validatedHosts, config_id, credentialed: isCredentialed, task_id: taskId, started, startError },
        }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
      }

      if (!started) {
        return res.status(502).json({
          success: false,
          message: taskId
            ? `Scan target and task were created, but the task failed to start: ${startError || 'unknown error'}. It can be started manually from the OpenVAS Tasks view.`
            : 'Task was created but its ID could not be resolved, so it was not started. Check the OpenVAS Tasks view.',
        });
      }

      logger.info({ taskId, hosts: validatedHosts, credentialed: isCredentialed }, 'OpenVAS quick scan launched');

      return res.status(200).json({
        success: true,
        message: isCredentialed ? 'Credentialed scan created and launched' : 'Scan created and launched successfully',
      });
    }
  } catch (err: any) {
    return handleOpenVASError(res, err, { operation: 'quick_scan', name: req.body?.name });
  }
};
