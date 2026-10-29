import { Request, Response } from 'express';
import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { encrypt, decrypt } from '../../utils/encryption';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import type { AiProvider } from '../../orm/entities/ai/AiProviderConfig';
import { API_KEY_MASK_SUFFIX_LENGTH } from '../../consts/auth';
import { getLogger } from '../../utils/logger';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';
import { DEFAULT_AI_MODEL_BY_PROVIDER } from '../../services/aiChat';

const logger = getLogger('controllers.aiProviderConfig');

const VALID_PROVIDERS: AiProvider[] = ['anthropic', 'openai'];

async function getPrimaryDb(op: string) {
  const { dbSourceConnection } = await import('../../index');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 1 || !ds[0].isInitialized) {
    logger.warn({ op }, 'Primary database not available');
    return null;
  }
  return ds[0];
}

// Reasoning models (OpenAI's GPT-5.x family, Anthropic models with thinking
// enabled) spend hidden reasoning tokens out of the same budget as the visible
// reply — a 1-token cap can be exhausted by reasoning alone before any output
// is produced, which OpenAI reports back as a 400 rather than an empty reply.
// Give the connectivity check enough headroom to actually get a reply either way.
const PING_MAX_TOKENS = 64;

// A Super-Admin-supplied base_url that is unreachable or slow-to-hang would
// otherwise leave this request open indefinitely; bound it well below the
// full chat REQUEST_TIMEOUT_MS since this is just a connectivity check.
const PING_TIMEOUT_MS = 15_000;

async function pingProvider(
  provider: AiProvider,
  apiKey: string,
  opts: { model?: string | null; baseUrl?: string | null; organization?: string | null },
): Promise<{ success: boolean; message: string }> {
  try {
    if (provider === 'anthropic') {
      const client = new Anthropic({ apiKey, baseURL: opts.baseUrl || undefined, timeout: PING_TIMEOUT_MS });
      await client.messages.create({
        model: opts.model || DEFAULT_AI_MODEL_BY_PROVIDER.anthropic,
        max_tokens: PING_MAX_TOKENS,
        messages: [{ role: 'user', content: 'ping' }],
      });
    } else {
      const client = new OpenAI({
        apiKey,
        baseURL: opts.baseUrl || undefined,
        organization: opts.organization || undefined,
        timeout: PING_TIMEOUT_MS,
      });
      await client.chat.completions.create({
        model: opts.model || DEFAULT_AI_MODEL_BY_PROVIDER.openai,
        max_completion_tokens: PING_MAX_TOKENS,
        messages: [{ role: 'user', content: 'ping' }],
      });
    }
    return { success: true, message: 'Connection successful' };
  } catch (err: any) {
    logger.debug({ err, provider }, 'AI provider ping failed');
    return { success: false, message: err?.message || 'Connection failed' };
  }
}

export const saveAiProviderConfig = async (req: Request, res: Response) => {
  try {
    const { provider, api_key, model, base_url, organization, max_output_tokens } = req.body ?? {};

    if (!VALID_PROVIDERS.includes(provider)) {
      return res.status(400).json({ success: false, message: 'provider must be "anthropic" or "openai"' });
    }
    if (!api_key || typeof api_key !== 'string') {
      return res.status(400).json({ success: false, message: 'api_key is required' });
    }
    if (max_output_tokens !== undefined && max_output_tokens !== null) {
      const n = Number(max_output_tokens);
      if (!Number.isInteger(n) || n < 1 || n > 128000) {
        return res.status(400).json({ success: false, message: 'max_output_tokens must be an integer between 1 and 128000' });
      }
    }

    const db = await getPrimaryDb('saveAiProviderConfig');
    if (!db) return res.status(503).json({ success: false, message: 'Database unavailable' });

    const { AiProviderConfig } = await import('../../orm/entities/ai/AiProviderConfig');
    const enc = encrypt(api_key);

    const jwt = jwtFrom(req);
    await db.transaction(async (manager) => {
      await manager.query('LOCK TABLE ai_provider_configs IN EXCLUSIVE MODE');
      await manager.update(AiProviderConfig, { isActive: true }, { isActive: false });

      const config = manager.create(AiProviderConfig, {
        provider,
        apiKeyEncrypted: enc.ciphertext,
        apiKeyIv: enc.iv,
        apiKeyAuthTag: enc.authTag,
        apiKeySuffix: api_key.slice(-API_KEY_MASK_SUFFIX_LENGTH),
        model: model ? String(model).trim() || null : null,
        baseUrl: base_url ? String(base_url).trim() || null : null,
        organization: organization ? String(organization).trim() || null : null,
        maxOutputTokens: max_output_tokens ? Number(max_output_tokens) : null,
        isActive: true,
        created_by_user_id: jwt?.id ?? null,
        created_by_name: jwt?.name ?? null,
      });
      await manager.save(config);
    });

    if (jwt?.id) {
      logAuditTrail({
        action: 'AI_PROVIDER_CONFIG',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'CONFIG_SAVED', provider },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ provider, userId: jwt?.id ?? null }, 'AI provider configuration saved');
    return res.status(200).json({ success: true, message: 'AI provider configuration saved' });
  } catch (err: any) {
    logger.error({ err, provider: (req.body as { provider?: string })?.provider ?? null }, 'Failed to save AI provider configuration');
    return res.status(500).json({ success: false, message: err?.message || 'Failed to save AI provider configuration' });
  }
};

// Any authenticated user can check whether the assistant is configured —
// unlike the other endpoints below, this deliberately isn't Super-Admin-only,
// so the chat UI can tell non-admins why the assistant won't respond instead
// of leaving them guessing.
export const getAiProviderConfigStatus = async (_req: Request, res: Response) => {
  try {
    const db = await getPrimaryDb('getAiProviderConfigStatus');
    if (!db) return res.status(503).json({ success: false, message: 'Database unavailable' });

    const { AiProviderConfig } = await import('../../orm/entities/ai/AiProviderConfig');
    const repo = db.getRepository(AiProviderConfig);
    const count = await repo.count({ where: { isActive: true } });

    logger.debug({ configured: count > 0 }, 'AI provider configuration status checked');
    return res.status(200).json({ success: true, configured: count > 0 });
  } catch (err: any) {
    logger.error({ err }, 'Failed to check AI provider status');
    return res.status(500).json({ success: false, message: err?.message || 'Failed to check AI provider status' });
  }
};

export const getAiProviderConfig = async (_req: Request, res: Response) => {
  try {
    const db = await getPrimaryDb('getAiProviderConfig');
    if (!db) return res.status(503).json({ success: false, message: 'Database unavailable' });

    const { AiProviderConfig } = await import('../../orm/entities/ai/AiProviderConfig');
    const repo = db.getRepository(AiProviderConfig);
    const config = await repo.findOne({ where: { isActive: true } });

    if (!config) {
      logger.debug({}, 'AI provider configuration retrieved: none configured');
      return res.status(200).json({ success: true, data: null });
    }

    logger.debug({ provider: config.provider }, 'AI provider configuration retrieved');
    return res.status(200).json({
      success: true,
      data: {
        provider: config.provider,
        api_key_masked: '****' + (config.apiKeySuffix || '****'),
        model: config.model,
        base_url: config.baseUrl,
        organization: config.organization,
        max_output_tokens: config.maxOutputTokens,
        created_by_name: config.created_by_name,
        created_at: config.created_at,
        updated_at: config.updated_at,
      },
    });
  } catch (err: any) {
    logger.error({ err }, 'Failed to get AI provider configuration');
    return res.status(500).json({ success: false, message: err?.message || 'Failed to get AI provider configuration' });
  }
};

export const testAiProviderConfig = async (req: Request, res: Response) => {
  try {
    const { provider, api_key, model, base_url, organization } = req.body ?? {};

    if (api_key && typeof api_key === 'string') {
      if (!VALID_PROVIDERS.includes(provider)) {
        return res.status(400).json({ success: false, message: 'provider must be "anthropic" or "openai"' });
      }
      const result = await pingProvider(provider, api_key, { model, baseUrl: base_url, organization });
      if (result.success) {
        logger.info({ provider }, 'AI provider connection test succeeded');
      } else {
        logger.warn({ provider, message: result.message }, 'AI provider connection test failed');
      }
      return res.status(200).json(result);
    }

    // No raw key supplied — test the stored active config.
    const db = await getPrimaryDb('testAiProviderConfig');
    if (!db) return res.status(503).json({ success: false, message: 'Database unavailable' });

    const { AiProviderConfig } = await import('../../orm/entities/ai/AiProviderConfig');
    const repo = db.getRepository(AiProviderConfig);
    const config = await repo.findOne({ where: { isActive: true } });
    if (!config) return res.status(404).json({ success: false, message: 'No AI provider configured' });

    const decryptedKey = decrypt(config.apiKeyEncrypted, config.apiKeyIv, config.apiKeyAuthTag);
    const result = await pingProvider(config.provider, decryptedKey, {
      model: config.model,
      baseUrl: config.baseUrl,
      organization: config.organization,
    });
    if (result.success) {
      logger.info({ provider: config.provider }, 'AI provider connection test succeeded');
    } else {
      logger.warn({ provider: config.provider, message: result.message }, 'AI provider connection test failed');
    }
    return res.status(200).json(result);
  } catch (err: any) {
    logger.warn({ err, provider: (req.body as { provider?: string })?.provider ?? null }, 'AI provider connection test failed');
    return res.status(500).json({ success: false, message: err?.message || 'Failed to test AI provider connection' });
  }
};

export const deleteAiProviderConfig = async (req: Request, res: Response) => {
  try {
    const db = await getPrimaryDb('deleteAiProviderConfig');
    if (!db) return res.status(503).json({ success: false, message: 'Database unavailable' });

    const { AiProviderConfig } = await import('../../orm/entities/ai/AiProviderConfig');
    const repo = db.getRepository(AiProviderConfig);
    const result = await repo.update({ isActive: true }, { isActive: false });

    if (!result.affected) {
      logger.info({}, 'AI provider configuration removal skipped: no active configuration found');
      return res.status(404).json({ success: false, message: 'No active AI provider configuration found' });
    }

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'AI_PROVIDER_CONFIG',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { event: 'CONFIG_REMOVED' },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ userId: jwt?.id ?? null }, 'AI provider configuration removed');
    return res.status(200).json({ success: true, message: 'AI provider configuration removed' });
  } catch (err: any) {
    logger.error({ err }, 'Failed to remove AI provider configuration');
    return res.status(500).json({ success: false, message: err?.message || 'Failed to remove AI provider configuration' });
  }
};
