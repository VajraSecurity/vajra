import { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { promises as dns } from 'dns';
import { encrypt, decrypt } from '../../utils/encryption';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getLogger } from '../../utils/logger';
import { isPrivateOrLoopbackIp } from '../../services/domainReputation/validation';
import { API_KEY_MASK_SUFFIX_LENGTH } from '../../consts/auth';
import { DEFAULT_TIMEOUT_MS } from '../../consts/timeout';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';
import { sanitizeAxiosError } from '../../utils/sanitizeAxiosError';
import { resolveScannerGroupContext, groupIdWhereValue } from '../../utils/scannerScope';
import { canActOnGroup, scopeGroupIds } from '../../utils/nodeScope';
import { normalizeBurpTarget } from '../../utils/urlIdentity';

const logger = getLogger('controllers.burpsuite');

// Burp Suite Enterprise's REST API embeds the API key directly in the URL
// path (e.g. https://host/<apiKey>/v0.1/scan) rather than in a header, so
// any raw axios error logged here would leak the plaintext key into the log
// file (see utils/sanitizeAxiosError.ts for why pino's default serializer
// makes this unavoidable without stripping the error first).

/**
 * On-prem escape hatch. Set BURPSUITE_ALLOW_INSECURE_URL=true to accept an
 * http:// scheme and a private/loopback address for the Burp Suite Enterprise
 * URL, for deployments whose Burp instance is internal-only and therefore can
 * neither hold a publicly-valid TLS certificate nor sit on a public address.
 *
 * Opt-in and off by default because it relaxes two real controls:
 *
 *  - CWE-319 (cleartext): Burp embeds the API key in the URL PATH, not a
 *    header, so over http:// the key crosses the network in the request line
 *    and lands in every proxy/load-balancer/access log along the way. This is
 *    materially worse than the usual "http is not encrypted" tradeoff — it is
 *    a credential disclosure, not just traffic disclosure.
 *  - CWE-918 (SSRF): skipping the private-IP check is what lets this server be
 *    pointed at an internal host at all, which is precisely what that check
 *    exists to prevent.
 *
 * Only enable when the Burp instance sits on a trusted network segment, and
 * prefer rotating the Burp API key if it has ever been sent over http://.
 */
const allowInsecureBurpUrl = (): boolean => process.env.BURPSUITE_ALLOW_INSECURE_URL === 'true';

// SSRF (CWE-918) and cleartext (CWE-319) gate for the admin-supplied Burp Suite
// Enterprise URL, which this server makes outbound requests to with the API key embedded
// in the URL path. Mirrors the resolve-then-check pattern the domain-reputation providers
// use (see services/domainReputation/providers/manualServer.ts) so every
// admin-configurable outbound target gets the same treatment.
//
// Named "Allowed" rather than "PublicHttps" because BURPSUITE_ALLOW_INSECURE_URL can
// widen what passes, at which point the narrower name would be a lie.
//
// relaxationLogLevel exists because this function runs on two very different paths.
// saveBurpsuiteConfig and testBurpsuiteConnection are user-initiated and rare, so 'warn'
// there is actionable. getActiveConfig re-validates on every read and GET /scans is
// polled continuously by the scans list UI, so 'warn' on that path would emit up to two
// lines per poll tick for a static, expected condition — the same flooding this file
// already avoids for per-scan status failures (see listBurpsuiteScans).
async function assertAllowedBurpUrl(
  rawUrl: string,
  relaxationLogLevel: 'warn' | 'debug' = 'warn',
): Promise<string> {
  const cleaned = String(rawUrl).replace(/\/+$/, '');
  const allowInsecure = allowInsecureBurpUrl();

  const schemeOk = allowInsecure ? /^https?:\/\//i.test(cleaned) : /^https:\/\//i.test(cleaned);
  if (!schemeOk) {
    throw new Error(
      allowInsecure
        ? 'Burp Suite URL must start with http:// or https://'
        : 'Burp Suite URL must start with https://',
    );
  }

  let hostname: string;
  try {
    hostname = new URL(cleaned).hostname.replace(/^\[|\]$/g, ''); // strip IPv6 literal brackets
  } catch {
    throw new Error('Burp Suite URL is not a valid URL');
  }

  const isLiteral = /^[0-9.]+$/.test(hostname) || hostname.includes(':');
  const ip = isLiteral ? hostname : (await dns.lookup(hostname)).address;

  if (isPrivateOrLoopbackIp(ip)) {
    if (!allowInsecure) {
      throw new Error(`Refusing to contact private/reserved address ${ip}`);
    }
    // Report rather than stay silent: this is a deliberately relaxed SSRF control,
    // so an acceptance of an internal target should be visible when someone later
    // asks why this server is reaching a private address. Level varies by caller —
    // see relaxationLogLevel above.
    logger[relaxationLogLevel](
      { ip, hostname },
      'BURPSUITE_ALLOW_INSECURE_URL is set — allowing private/reserved Burp Suite address',
    );
  }

  if (allowInsecure && /^http:\/\//i.test(cleaned)) {
    logger[relaxationLogLevel](
      { hostname },
      'Burp Suite URL uses http:// — the API key is embedded in the URL path and will be sent in cleartext',
    );
  }

  return cleaned;
}

const getActiveConfig = async (groupId: string | null) => {
    const { dbSourceConnection } = await import('../../index');
    const { BurpsuiteConfig } = await import('../../orm/entities/fleet/BurpsuiteConfig');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
        logger.warn({}, 'Fleet database not available while resolving Burp Suite configuration');
        return null;
    }
    const config = await ds[1].getRepository(BurpsuiteConfig).findOne({ where: { isActive: true, groupId: groupIdWhereValue(groupId) } });
    if (!config) return null;

    // Re-validate on every read, not only at save time: a row written before this
    // validation existed, or written directly to the DB, could still hold a
    // non-https/private-target apiUrl. Every call site below trusts config.apiUrl for an
    // outbound request, so a row that fails re-validation is treated as "not configured"
    // — the existing 400/404/503 handling at every caller already covers that.
    try {
        // 'debug': this path runs on every read, including each tick of the
        // scans-list poll, so a relaxation here must not log at warn repeatedly.
        // The user-initiated save/test paths still report it at warn.
        await assertAllowedBurpUrl(config.apiUrl, 'debug');
    } catch (err) {
        logger.error({ err }, 'Stored Burp Suite apiUrl failed re-validation — treating as not configured');
        return null;
    }
    return config;
};

// Endpoints

export const saveBurpsuiteConfig = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const { groupId } = scopeResult.ctx;

        const { url, apiKey } = req.body;

        if (!url || !apiKey) {
            res.status(400).json({ success: false, message: 'URL and API Key are required' });
            return;
        }

        let urlClean: string;
        try {
            urlClean = await assertAllowedBurpUrl(url);
        } catch (validationErr: any) {
            res.status(400).json({ success: false, message: validationErr.message });
            return;
        }

        // Require a successful live connection test with these exact
        // credentials before persisting — same rationale as Nessus/OpenVAS's
        // save endpoints. Reuses the same request testBurpsuiteConnection
        // exposes standalone, so "Test Connection" and "Save" can never
        // disagree about whether credentials work.
        const testResult = await runBurpsuiteConnectionTest(urlClean, apiKey);
        if (!testResult.success) {
            logger.warn({ groupId, message: testResult.message }, 'Burp Suite configuration save rejected: connection test failed');
            res.status(400).json({
                success: false,
                message: `Connection test failed, configuration was not saved: ${testResult.message || 'unable to connect'}`,
            });
            return;
        }

        const encApiKey = encrypt(apiKey);

        const { dbSourceConnection } = await import('../../index');
        const { BurpsuiteConfig } = await import('../../orm/entities/fleet/BurpsuiteConfig');
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({}, 'Burp Suite configuration save aborted: fleet database not available');
            res.status(503).json({ success: false, message: 'Fleet database not available' });
            return;
        }

        const repo = ds[1].getRepository(BurpsuiteConfig);

        // Deactivate old configs — scoped to this same group so saving a new
        // config for one group/scope never deactivates another group's or the
        // Super Administrator's own.
        await repo.update({ isActive: true, groupId: groupIdWhereValue(groupId) }, { isActive: false });

        const config = repo.create({
            groupId,
            apiUrl: urlClean,
            apiKeyEncrypted: encApiKey.ciphertext,
            apiKeyIv: encApiKey.iv,
            apiKeyAuthTag: encApiKey.authTag,
            apiKeySuffix: apiKey.length >= API_KEY_MASK_SUFFIX_LENGTH ? apiKey.slice(-API_KEY_MASK_SUFFIX_LENGTH) : apiKey,
            isActive: true,
            created_by_user_id: jwtFrom(req)?.id ?? null,
            created_by_name: jwtFrom(req)?.name ?? null,
        });

        await repo.save(config);

        const jwt = jwtFrom(req);
        if (jwt?.id) {
            logAuditTrail({
                action: 'BURPSUITE_CONFIG',
                status: 'success',
                userId: jwt.id,
                email: jwt.email ?? null,
                ipAddress: clientIpFrom(req),
                userAgent: null,
                details: { event: 'CONFIG_SAVED', api_url: urlClean, group_id: groupId },
            }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
        }

        logger.info({ userId: jwt?.id ?? null, groupId }, 'Burp Suite configuration saved');
        res.json({ success: true, message: 'Configuration saved successfully' });
    } catch (error: any) {
        logger.error({ err: error }, 'Failed to save Burp Suite configuration');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};

export const getBurpsuiteConfig = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const config = await getActiveConfig(scopeResult.ctx.groupId);
        if (config) {
            logger.debug({ isConfigured: true }, 'Burp Suite configuration retrieved');
            res.json({
                success: true,
                data: {
                    url: config.apiUrl,
                    isConfigured: true,
                    groupId: config.groupId,
                    created_by_name: config.created_by_name,
                    updated_at: config.updated_at
                }
            });
        } else {
            logger.debug({ isConfigured: false }, 'Burp Suite configuration retrieved');
            res.json({ success: true, data: null });
        }
    } catch (error: any) {
        logger.error({ err: error }, 'Failed to fetch Burp Suite configuration');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};

/**
 * Shared by testBurpsuiteConnection (the standalone "Test Connection" button) and
 * saveBurpsuiteConfig, which requires it to succeed before persisting. `urlClean` must
 * already be validated via assertAllowedBurpUrl by the caller. Never writes to `res`
 * itself, so both callers decide their own response shape and status.
 */
async function runBurpsuiteConnectionTest(urlClean: string, apiKey: string): Promise<{ success: boolean; message?: string }> {
    try {
        await axios.get(`${urlClean}/${apiKey}/v0.1/knowledge_base/issue_definitions`, {
            timeout: DEFAULT_TIMEOUT_MS,
            maxRedirects: 0 // don't let a validated-at-save-time host 30x us to an unvalidated internal target
        });
        logger.debug({}, 'Burp Suite connection test succeeded');
        return { success: true, message: 'Connection successful!' };
    } catch (error: any) {
        logger.info({ err: sanitizeAxiosError(error) }, 'Burp Suite connection test failed');
        return { success: false, message: 'Connection failed: ' + (error.message || 'Unknown error') };
    }
}

export const testBurpsuiteConnection = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const { url, apiKey } = req.body;

        if (!url || !apiKey) {
            res.status(400).json({ success: false, message: 'URL and API Key are required' });
            return;
        }

        let urlClean: string;
        try {
            urlClean = await assertAllowedBurpUrl(url);
        } catch (validationErr: any) {
            res.status(400).json({ success: false, message: validationErr.message });
            return;
        }

        const result = await runBurpsuiteConnectionTest(urlClean, apiKey);
        res.status(result.success ? 200 : 400).json(result);
    } catch (error: any) {
        logger.info({ err: sanitizeAxiosError(error) }, 'Burp Suite connection test failed');
        res.status(400).json({ success: false, message: 'Connection failed: ' + (error.message || 'Unknown error') });
    }
};

export const listBurpsuiteScans = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const { scope, groupId } = scopeResult.ctx;

        const { dbSourceConnection } = await import('../../index');
        const { BurpsuiteScanHistory } = await import('../../orm/entities/fleet/BurpsuiteScanHistory');
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({}, 'Burp Suite scan listing aborted: fleet database not available');
            res.status(503).json({ success: false, message: 'Fleet database not available' });
            return;
        }

        const repo = ds[1].getRepository(BurpsuiteScanHistory);

        // Unlike every other endpoint in this file (and every other scanner),
        // an unrestricted caller (Super Administrator) who did NOT explicitly
        // pass ?groupId= gets NO where filter at all — this is the one
        // deliberate case where ctx.groupId === null does not mean "filter to
        // the null bucket", it means "no explicit ask, so merge every group's
        // scan history (and the Super Admin's own) into one list". Burp Suite
        // is the only scanner with local scan storage, so this is a genuine
        // merged list rather than a per-group context switch — see the model
        // note atop BurpsuiteScanHistory.groupId. A Super Admin who DOES pass
        // ?groupId=X (including groupId=self/null) narrows to just that scope,
        // same as every other endpoint.
        const noExplicitGroupRequested = req.query.groupId === undefined;
        const isMergedView = scope.unrestricted && noExplicitGroupRequested;
        // Select only the columns this endpoint touches. resultsJson/metricsJson hold the
        // cached Burp issue_events/scan_metrics payloads — hundreds of KB to megabytes per
        // row, TOASTed out-of-line — and nothing here reads them: the mapped response
        // carries id/groupId/target/status/issue_counts, and the refresh path overwrites
        // them wholesale from the live Burp response. Fetching them detoasted the whole
        // scan history on every tick of the scans-list poll.
        //
        // Safe alongside the repo.save(scan) in the refresh path: save() reloads the row
        // and diffs against it, and that diff skips properties that are `undefined` on
        // the in-memory entity, so an unselected column is never written back as NULL.
        //
        // groupId is load-bearing here, not cosmetic: the merged-view refresh
        // path keys configForGroup() on scan.groupId, and it is in the response.
        const SCAN_LIST_COLUMNS = {
            id: true,
            groupId: true,
            taskId: true,
            target: true,
            status: true,
            issuesTotal: true,
            issuesHigh: true,
            issuesMedium: true,
            issuesLow: true,
            updated_at: true,
        } as const;
        const scans = isMergedView
            ? await repo.find({ select: SCAN_LIST_COLUMNS, order: { created_at: 'DESC' }, take: 50 })
            : await repo.find({ select: SCAN_LIST_COLUMNS, where: { groupId: groupIdWhereValue(groupId) }, order: { created_at: 'DESC' }, take: 50 });

        if (!isMergedView) {
            const config = await getActiveConfig(groupId);
            if (!config) {
                logger.debug({ groupId }, 'Burp Suite scan listing skipped: not configured');
                res.status(400).json({ success: false, message: 'Burpsuite not configured' });
                return;
            }
        }

        // Merged view can span scans launched under several different groups'
        // (or the Super Admin's own) Burp Suite configs, each potentially
        // pointing at a different server — a single shared `config` (as the
        // non-merged branch above uses) would be wrong here. Resolve and cache
        // one config per distinct group_id found among the listed scans
        // instead, so each scan's live status is polled against the server it
        // actually ran on.
        const configCache = new Map<string | null, Awaited<ReturnType<typeof getActiveConfig>>>();
        const configForGroup = async (scanGroupId: string | null) => {
            if (!configCache.has(scanGroupId)) {
                configCache.set(scanGroupId, await getActiveConfig(scanGroupId));
            }
            return configCache.get(scanGroupId) ?? null;
        };

        let statusUpdateFailures = 0;
        const updatedScans = await Promise.all(scans.map(async (scan) => {
            if (scan.status === 'succeeded' || scan.status === 'failed') {
                return scan;
            }

            const config = await configForGroup(scan.groupId);
            if (!config) {
                // No (or no longer valid) config for the group that launched this
                // scan — nothing to poll against; keep serving its cached status.
                return scan;
            }

            try {
                const apiKey = decrypt(
                    config.apiKeyEncrypted,
                    config.apiKeyIv,
                    config.apiKeyAuthTag
                );
                const response = await axios.get(`${config.apiUrl}/${apiKey}/v0.1/scan/${scan.taskId}`, {
                    timeout: DEFAULT_TIMEOUT_MS,
                    maxRedirects: 0 // don't let a validated-at-save-time host 30x us to an unvalidated internal target
                });

                if (response.data && response.data.scan_status) {
                    const newStatus = response.data.scan_status;
                    const issueEvents = response.data.issue_events || [];

                    let high = 0;
                    let medium = 0;
                    let low = 0;

                    issueEvents.forEach((issue: any) => {
                        const sev = (issue.issue?.severity || '').toLowerCase();
                        if (sev === 'high') high++;
                        else if (sev === 'medium') medium++;
                        else if (sev === 'low') low++;
                    });

                    scan.status = newStatus;
                    scan.issuesHigh = high;
                    scan.issuesMedium = medium;
                    scan.issuesLow = low;
                    scan.issuesTotal = high + medium + low;
                    // Cache the raw results so they remain viewable even after
                    // the task ages out of Burp Suite's own scan history.
                    if (issueEvents.length > 0) scan.resultsJson = JSON.stringify(issueEvents).replace(/\\u0000/g, '');
                    if (response.data.scan_metrics) scan.metricsJson = JSON.stringify(response.data.scan_metrics).replace(/\\u0000/g, '');

                    await repo.save(scan);
                }
            } catch (err) {
                statusUpdateFailures++;
                // GET /scans is polled repeatedly by the scans list UI — logging every
                // per-scan failure at warn would flood production logs whenever Burp
                // Suite is unreachable while several scans are running (up to `take`
                // lines per poll, per open session). Keep the per-item detail at debug
                // and surface the aggregate at warn below only when failures occurred.
                logger.debug({ err: sanitizeAxiosError(err), taskId: scan.taskId }, 'Failed to update Burp Suite scan status');
            }
            return scan;
        }));

        const mappedScans = updatedScans.map(s => ({
            id: s.id,
            groupId: s.groupId,
            target: s.target,
            status: s.status,
            issue_counts: {
                total: s.issuesTotal,
                high: s.issuesHigh,
                medium: s.issuesMedium,
                low: s.issuesLow
            },
            // Most recent activity on this scan row (status change, issue counts
            // refreshed, etc.) — for a completed scan this is effectively its
            // completion time, since that's typically the last field update.
            // repo.save() above is the only thing that ever touches this column
            // outside of scan creation, so it tracks real scan progress, not an
            // unrelated background job.
            updated_at: s.updated_at
        }));

        if (statusUpdateFailures > 0) {
            logger.warn({ count: mappedScans.length, statusUpdateFailures }, 'Burp Suite scans listed with one or more status updates failed');
        } else {
            logger.debug({ count: mappedScans.length, statusUpdateFailures }, 'Burp Suite scans listed');
        }
        res.json({ success: true, data: { scans: mappedScans } });
    } catch (error: any) {
        logger.error({ err: error }, 'Failed to list Burp Suite scans');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};

export const launchBurpsuiteScan = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const { groupId } = scopeResult.ctx;

        const { targetUrls, scanProfile } = req.body;
        const config = await getActiveConfig(groupId);

        if (!config) {
            logger.debug({}, 'Burp Suite scan launch aborted: not configured');
            res.status(400).json({ success: false, message: 'Burpsuite not configured' });
            return;
        }
        if (!targetUrls || !targetUrls.length) {
            res.status(400).json({ success: false, message: 'Target URLs are required' });
            return;
        }

        let parsedTargetUrl: URL;
        try {
            parsedTargetUrl = new URL(targetUrls[0]);
        } catch {
            res.status(400).json({ success: false, message: 'Target URL is not a valid URL' });
            return;
        }
        if (parsedTargetUrl.protocol !== 'http:' && parsedTargetUrl.protocol !== 'https:') {
            res.status(400).json({ success: false, message: 'Target URL must be http:// or https://' });
            return;
        }

        const apiKey = decrypt(
            config.apiKeyEncrypted,
            config.apiKeyIv,
            config.apiKeyAuthTag
        );

        const targetUrl = targetUrls[0];
        
        const payload: any = {
            urls: [targetUrl]
        };

        if (scanProfile && scanProfile.trim() !== '') {
            payload.scan_configurations = [
                {
                    name: scanProfile.trim(),
                    type: "NamedConfiguration"
                }
            ];
        }

        let response;
        try {
            response = await axios.post(`${config.apiUrl}/${apiKey}/v0.1/scan`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    timeout: 10000,
                    maxRedirects: 0 // don't let a validated-at-save-time host 30x us to an unvalidated internal target
                }
            );
        } catch (dispatchErr: any) {
            // Distinguishes a Burp Suite API/network failure from a later DB-save
            // failure, which would otherwise hit the same outer catch below with
            // an identical generic message.
            logger.error({ err: sanitizeAxiosError(dispatchErr), target: targetUrl }, 'Burp Suite scan launch request failed');
            throw dispatchErr;
        }

        const taskId = response.headers['location'] || response.data?.task_id || '';
        const parsedTaskId = taskId.split('/').pop() || taskId;

        if (!parsedTaskId) {
            logger.warn({ target: targetUrl, locationHeader: response.headers['location'] ?? null }, 'Burp Suite scan launch response did not include a task ID');
            res.status(502).json({ success: false, message: 'Failed to retrieve task ID from Burp Suite response' });
            return;
        }

        const { dbSourceConnection } = await import('../../index');
        const { BurpsuiteScanHistory } = await import('../../orm/entities/fleet/BurpsuiteScanHistory');
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({ target: targetUrl }, 'Burp Suite scan launch aborted: fleet database not available');
            res.status(503).json({ success: false, message: 'Fleet database not available' });
            return;
        }
        const repo = ds[1].getRepository(BurpsuiteScanHistory);

        const scan = repo.create({
            groupId,
            taskId: parsedTaskId,
            target: targetUrl,
            // Computed once here at launch time -- see BurpsuiteScanHistory
            // .normalizedTarget's own comment -- rather than left for the
            // bootstrap backfill in index.ts, which only ever catches rows
            // that predate this column.
            normalizedTarget: normalizeBurpTarget(targetUrl),
            status: 'running'
        });

        await repo.save(scan);

        logger.info({ taskId: parsedTaskId, target: targetUrl, groupId }, 'Burp Suite scan launched');

        const jwt = jwtFrom(req);
        if (jwt?.id) {
            logAuditTrail({
                action: 'BURPSUITE_SCAN',
                status: 'success',
                userId: jwt.id,
                email: jwt.email ?? null,
                ipAddress: clientIpFrom(req),
                userAgent: null,
                details: { event: 'SCAN_LAUNCHED', target: targetUrl, task_id: parsedTaskId, group_id: groupId },
            }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
        }

        res.json({ success: true, message: 'Scan launched successfully' });
    } catch (error: any) {
        logger.error({ err: sanitizeAxiosError(error), targetUrls: req.body?.targetUrls, scanProfile: req.body?.scanProfile }, 'Failed to launch Burp Suite scan');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};

export const deleteBurpsuiteConfig = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const { groupId } = scopeResult.ctx;

        const { dbSourceConnection } = await import('../../index');
        const { BurpsuiteConfig } = await import('../../orm/entities/fleet/BurpsuiteConfig');
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({}, 'Burp Suite configuration removal aborted: fleet database not available');
            res.status(503).json({ success: false, message: 'Fleet database not available' });
            return;
        }

        const repo = ds[1].getRepository(BurpsuiteConfig);
        // Scoped so this only ever deactivates the caller's own scope's row —
        // never another group's or (for a Group Admin) the Super Admin's own.
        await repo.update({ isActive: true, groupId: groupIdWhereValue(groupId) }, { isActive: false });

        logger.info({ groupId }, 'Burp Suite configuration removed');

        const jwt = jwtFrom(req);
        if (jwt?.id) {
            logAuditTrail({
                action: 'BURPSUITE_CONFIG',
                status: 'success',
                userId: jwt.id,
                email: jwt.email ?? null,
                ipAddress: clientIpFrom(req),
                userAgent: null,
                details: { event: 'CONFIG_REMOVED', group_id: groupId },
            }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
        }

        res.json({ success: true, message: 'Configuration removed successfully' });
    } catch (error: any) {
        logger.error({ err: error }, 'Failed to delete Burp Suite configuration');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};

export const testStoredBurpsuiteConnection = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const config = await getActiveConfig(scopeResult.ctx.groupId);
        if (!config) {
            logger.debug({}, 'Stored Burp Suite connection test aborted: not configured');
            res.status(404).json({ success: false, message: 'Burpsuite is not configured' });
            return;
        }

        const apiKey = decrypt(
            config.apiKeyEncrypted,
            config.apiKeyIv,
            config.apiKeyAuthTag
        );

        await axios.get(`${config.apiUrl}/${apiKey}/v0.1/knowledge_base/issue_definitions`, {
            timeout: DEFAULT_TIMEOUT_MS,
            maxRedirects: 0 // don't let a validated-at-save-time host 30x us to an unvalidated internal target
        });

        logger.debug({}, 'Stored Burp Suite connection test succeeded');
        res.json({ success: true, message: 'Connection successful!' });
    } catch (error: any) {
        logger.warn({ err: sanitizeAxiosError(error) }, 'Stored Burp Suite connection test failed');
        res.status(400).json({ success: false, message: 'Connection failed: ' + (error.message || 'Unknown error') });
    }
};

export const getBurpsuiteScanDetails = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const { scope } = scopeResult.ctx;

        const id = Number(req.params.taskId);
        if (!Number.isFinite(id)) {
            res.status(400).json({ success: false, message: 'Invalid scan id.' });
            return;
        }

        const { dbSourceConnection } = await import('../../index');
        const { BurpsuiteScanHistory } = await import('../../orm/entities/fleet/BurpsuiteScanHistory');
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({ id }, 'Burp Suite scan details fetch aborted: fleet database not available');
            res.status(503).json({ success: false, message: 'Fleet database not available' });
            return;
        }

        const repo = ds[1].getRepository(BurpsuiteScanHistory);
        const scan = await repo.findOne({ where: { id } });

        if (!scan) {
            res.status(404).json({ success: false, message: 'Scan not found' });
            return;
        }

        // A Super Administrator may view any scan (matches the merged list in
        // listBurpsuiteScans); a Group Admin/Viewer may only view a scan
        // launched under one of their own groups — never the Super Admin's own
        // (group_id null) scan, and never another group's.
        if (!scope.unrestricted && !(scan.groupId !== null && scopeGroupIds(scope).includes(scan.groupId))) {
            res.status(403).json({ success: false, message: 'You do not have access to this scan.' });
            return;
        }

        // Poll against the Burp server the scan actually ran on, which may
        // differ from the caller's own resolved scope (e.g. a Super Admin
        // viewing a specific group's scan from the merged list).
        const config = await getActiveConfig(scan.groupId);
        if (!config) {
            logger.debug({ id }, 'Burp Suite scan details fetch skipped: not configured');
            res.status(404).json({ success: false, message: 'Burpsuite is not configured' });
            return;
        }

        // A scan that already reached a terminal state was recorded from a real
        // Burp response (by this endpoint or by listBurpsuiteScans) — serve that
        // recorded result directly instead of re-polling Burp on every view.
        let liveData: { scan_status?: string; scan_metrics?: any; issue_events?: any[] } | null = null;
        let stale = false;
        const isTerminal = scan.status === 'succeeded' || scan.status === 'failed';

        if (!isTerminal) {
            const apiKey = decrypt(
                config.apiKeyEncrypted,
                config.apiKeyIv,
                config.apiKeyAuthTag
            );

            try {
                const response = await axios.get(`${config.apiUrl}/${apiKey}/v0.1/scan/${scan.taskId}`, {
                    timeout: DEFAULT_TIMEOUT_MS,
                    maxRedirects: 0 // don't let a validated-at-save-time host 30x us to an unvalidated internal target
                });
                liveData = response.data;
            } catch (liveErr) {
                // Task may have aged out of Burp Suite's own history (e.g. after a
                // restart or its history size limit was hit).
                if (!scan.resultsJson) {
                    // Never had a successful poll and Burp is unreachable now — nothing to show yet.
                    logger.warn({ err: sanitizeAxiosError(liveErr), taskId: scan.taskId }, 'Live Burp Suite fetch failed and no cached results are available');
                    res.status(502).json({ success: false, message: 'Unable to reach Burp Suite and no cached results are available for this scan yet' });
                    return;
                }
                // We do have an earlier cached snapshot — serve it, but flag it as
                // stale so the caller doesn't present it as a confirmed live status.
                logger.warn({ err: sanitizeAxiosError(liveErr), taskId: scan.taskId }, 'Live Burp Suite fetch failed, falling back to cached results');
                stale = true;
            }

            if (liveData) {
                scan.status = liveData.scan_status || scan.status;
                if (liveData.issue_events?.length) scan.resultsJson = JSON.stringify(liveData.issue_events).replace(/\\u0000/g, '');
                if (liveData.scan_metrics) scan.metricsJson = JSON.stringify(liveData.scan_metrics).replace(/\\u0000/g, '');
                await repo.save(scan);
            }
        }

        const issues = liveData?.issue_events ?? (scan.resultsJson ? JSON.parse(scan.resultsJson) : []);
        const metrics = liveData?.scan_metrics ?? (scan.metricsJson ? JSON.parse(scan.metricsJson) : null);

        logger.debug({ taskId: scan.taskId, stale }, 'Burp Suite scan details retrieved');
        res.json({
            success: true,
            stale,
            data: {
                task: {
                    id: scan.id,
                    groupId: scan.groupId,
                    target: scan.target,
                    status: scan.status,
                    created_at: scan.created_at,
                    metrics,
                    issuesTotal: scan.issuesTotal,
                    issuesHigh: scan.issuesHigh,
                    issuesMedium: scan.issuesMedium,
                    issuesLow: scan.issuesLow
                },
                issues
            }
        });
    } catch (error: any) {
        logger.error({ err: error, id: Number(req.params.taskId) }, 'Failed to fetch Burp Suite scan details');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};

export const deleteBurpsuiteScan = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
    try {
        const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
        if (!scopeResult.ok) {
            res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
            return;
        }
        const { scope } = scopeResult.ctx;

        const id = Number(req.params.taskId);
        if (!Number.isFinite(id)) {
            res.status(400).json({ success: false, message: 'Invalid scan id.' });
            return;
        }
        const { dbSourceConnection } = await import('../../index');
        const { BurpsuiteScanHistory } = await import('../../orm/entities/fleet/BurpsuiteScanHistory');

        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({ id }, 'Burp Suite scan deletion aborted: fleet database not available');
            res.status(503).json({ success: false, message: 'Fleet database not available' });
            return;
        }

        const repo = ds[1].getRepository(BurpsuiteScanHistory);
        const scan = await repo.findOne({ where: { id } });

        if (!scan) {
            logger.info({ id }, 'Burp Suite scan deletion skipped: scan not found');
            res.json({ success: true, message: 'Scan deleted successfully' });
            return;
        }

        // A Super Administrator may delete any scan; a Group Admin only a scan
        // launched under a group they act on — never the Super Admin's own
        // (group_id null) scan. canActOnGroup takes a string groupId, so the
        // null case (Super Admin's own scope) is checked separately first.
        if (!scope.unrestricted && (scan.groupId === null || !canActOnGroup(scope, scan.groupId))) {
            res.status(403).json({ success: false, message: 'You do not have access to this scan.' });
            return;
        }

        await repo.delete({ id });

        logger.debug({ id, groupId: scan.groupId }, 'Burp Suite scan deleted');
        res.json({ success: true, message: 'Scan deleted successfully' });
    } catch (error: any) {
        logger.error({ err: error, id: Number(req.params.taskId) }, 'Failed to delete Burp Suite scan');
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
};
