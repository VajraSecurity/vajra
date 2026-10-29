import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { SavedQuery } from '../../orm/entities/fleet/SavedQuery';
import type { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { getLogger } from '../../utils/logger';
import { isPgUndefinedTableError } from '../../utils/dbErrors';

const logger = getLogger('controllers.threatHunting.savedQueries');

/** Max length (chars) a saved query's `name` is truncated to before storage. */
const SAVED_QUERY_NAME_MAX_LEN = 255;
/** Max length (chars) a saved query's `description` is truncated to before storage. */
const SAVED_QUERY_DESCRIPTION_MAX_LEN = 5000;
/** Max length (chars) a saved query's `query` (SQL text) is truncated to before storage. */
const SAVED_QUERY_SQL_MAX_LEN = 100000;

function sanitizeString(v: unknown, maxLen: number): string | null {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s.length === 0 ? null : s.slice(0, maxLen);
}

function normalizePlatformValue(v: unknown): string | null {
  if (v === null || v === undefined) return null;

  const normalizeItem = (raw: unknown): string | null => {
    const s = String(raw).trim().toLowerCase();
    if (s === 'all') return 'all';
    if (s === 'linux' || s === 'windows' || s === 'macos') return s;
    return null;
  };

  if (Array.isArray(v)) {
    const values = Array.from(
      new Set(
        v
          .map((item) => normalizeItem(item))
          .filter((item): item is 'linux' | 'windows' | 'macos' => item === 'linux' || item === 'windows' || item === 'macos'),
      ),
    );
    return values.length === 0 ? 'all' : values.join(',');
  }

  const raw = String(v).trim().toLowerCase();
  if (raw === 'all') return 'all';

  const parts = raw
    .split(',')
    .map((item) => normalizeItem(item))
    .filter((item): item is 'linux' | 'windows' | 'macos' => item === 'linux' || item === 'windows' || item === 'macos');

  if (parts.length === 0) return null;
  return Array.from(new Set(parts)).join(',');
}

function normalizeNodeStateValue(v: unknown): 'historic' | 'live' | 'both' | null {
  if (v === null || v === undefined) return null;
  const s = String(v).trim().toLowerCase();
  if (s === 'historic' || s === 'live' || s === 'both') return s;
  return null;
}

function normalizeDefenseKitValue(v: unknown): Array<'detection' | 'fragments' | 'policy'> | null {
  if (v === null || v === undefined) return null;
  if (!Array.isArray(v)) return null;
  const allowed = new Set(['detection', 'fragments', 'policy']);
  const values = Array.from(
    new Set(
      v.map((item) => String(item).trim().toLowerCase()).filter((item) => allowed.has(item)),
    ),
  ) as Array<'detection' | 'fragments' | 'policy'>;
  return values;
}

function normalizeDetectionSubtypesValue(v: unknown): string[] | null {
  if (v === null || v === undefined) return null;
  if (!Array.isArray(v)) return null;
  const allowed = new Set([
    'c2',
    'collection',
    'credentials',
    'discovery',
    'evasion',
    'execution',
    'exfil',
    'impact',
    'initial access',
    'persistence',
    'privesc',
  ]);
  return Array.from(
    new Set(
      v
        .map((item) => String(item).trim().toLowerCase())
        .filter((item) => allowed.has(item)),
    ),
  );
}

/** Returns the secondary DB repository, or null if DB is not ready. */
function getDb() {
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) return null;
  return ds[1].getRepository(SavedQuery);
}

export async function list_saved_queries(_req: Request, res: Response, next: NextFunction) {
  try {
    const repo = getDb();
    if (!repo) {
      logger.warn({}, 'Saved queries listing aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const queries = await repo.find({ order: { updated_at: 'DESC' } });
    logger.debug({ count: queries.length }, 'Saved queries listed');
    return res.status(200).json({ success: true, data: queries });
  } catch (err: unknown) {
    // Table may not exist yet (production env, synchronize=false, migration not run)
    if (isPgUndefinedTableError(err)) {
      logger.debug({ count: 0 }, 'Saved queries listed: table not yet migrated');
      return res.status(200).json({ success: true, data: [] });
    }
    logger.error({ err }, 'Failed to fetch saved queries');
    return next(new CustomError(500, 'Raw', 'Failed to fetch saved queries', null, err));
  }
}

export async function get_saved_query(req: Request, res: Response, next: NextFunction) {
  try {
    const id = parseInt(String(req.params.id), 10);
    if (!Number.isFinite(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const repo = getDb();
    if (!repo) {
      logger.warn({ id }, 'Saved query fetch aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const q = await repo.findOne({ where: { id } });
    if (!q) return res.status(404).json({ success: false, message: 'Query not found' });

    logger.debug({ id }, 'Saved query retrieved');
    return res.status(200).json({ success: true, data: q });
  } catch (err: unknown) {
    if (isPgUndefinedTableError(err)) {
      logger.warn({ id: req.params.id }, 'Saved query fetch returned not-found: saved_queries table not yet migrated');
      return res.status(404).json({ success: false, message: 'Query not found' });
    }
    logger.error({ err, id: req.params.id }, 'Failed to fetch saved query');
    return next(new CustomError(500, 'Raw', 'Failed to fetch query', null, err));
  }
}

export async function create_saved_query(req: Request, res: Response, next: NextFunction) {
  try {
    const { name, description, query, platform, node_state, defense_kit, detection_subtypes } = req.body as Record<string, unknown>;
    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

    const cleanName = sanitizeString(name, SAVED_QUERY_NAME_MAX_LEN);
    if (!cleanName) return res.status(400).json({ success: false, message: 'name is required' });

    const cleanQuery = sanitizeString(query, SAVED_QUERY_SQL_MAX_LEN);
    if (!cleanQuery) return res.status(400).json({ success: false, message: 'query is required' });

    const cleanPlatform = normalizePlatformValue(platform) ?? 'all';
    if (cleanPlatform === null) {
      return res.status(400).json({ success: false, message: 'platform must be all or a comma-separated list of linux, windows, macos' });
    }
    const cleanNodeState = normalizeNodeStateValue(node_state) ?? 'both';
    if (node_state !== undefined && cleanNodeState === null) {
      return res.status(400).json({ success: false, message: 'node_state must be one of historic, live, both' });
    }
    const cleanDefenseKit = normalizeDefenseKitValue(defense_kit) ?? [];
    if (defense_kit !== undefined && cleanDefenseKit === null) {
      return res.status(400).json({ success: false, message: 'defense_kit must be an array of detection, fragments, policy' });
    }
    const cleanDetectionSubtypes = normalizeDetectionSubtypesValue(detection_subtypes) ?? [];
    if (detection_subtypes !== undefined && cleanDetectionSubtypes === null) {
      return res.status(400).json({ success: false, message: 'detection_subtypes must be an array of valid detection subtype values' });
    }
    if (cleanDefenseKit.includes('detection') && cleanDetectionSubtypes.length === 0) {
      return res.status(400).json({ success: false, message: 'Select at least one detection subtype when detection is selected' });
    }

    const repo = getDb();
    if (!repo) {
      logger.warn({}, 'Saved query creation aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const sq = repo.create({
      name: cleanName,
      description: sanitizeString(description, SAVED_QUERY_DESCRIPTION_MAX_LEN),
      query: cleanQuery,
      platform: cleanPlatform,
      node_state: cleanNodeState,
      defense_kit: cleanDefenseKit,
      detection_subtypes: cleanDefenseKit.includes('detection') ? cleanDetectionSubtypes : [],
      created_by_user_id: jwtPayload?.id ?? null,
      created_by_name: sanitizeString(jwtPayload?.name ?? null, SAVED_QUERY_NAME_MAX_LEN),
    });

    const saved = await repo.save(sq);
    logger.info({ id: saved.id, name: saved.name }, 'Saved query created');
    return res.status(201).json({ success: true, data: saved });
  } catch (err: unknown) {
    if (isPgUndefinedTableError(err)) {
      logger.warn({}, 'Saved query creation aborted: saved_queries table not yet migrated');
      return res.status(503).json({ success: false, message: 'saved_queries table not initialised — run database migrations' });
    }
    logger.error({ err, name: (req.body as Record<string, unknown> | undefined)?.name }, 'Failed to create saved query');
    return next(new CustomError(500, 'Raw', 'Failed to create query', null, err));
  }
}

export async function update_saved_query(req: Request, res: Response, next: NextFunction) {
  try {
    const id = parseInt(String(req.params.id), 10);
    if (!Number.isFinite(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const { name, description, query, platform, node_state, defense_kit, detection_subtypes } = req.body as Record<string, unknown>;

    const repo = getDb();
    if (!repo) {
      logger.warn({ id }, 'Saved query update aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const sq = await repo.findOne({ where: { id } });
    if (!sq) return res.status(404).json({ success: false, message: 'Query not found' });

    if (name !== undefined) {
      const cleanName = sanitizeString(name, SAVED_QUERY_NAME_MAX_LEN);
      if (!cleanName) return res.status(400).json({ success: false, message: 'name must not be empty' });
      sq.name = cleanName;
    }
    if (description !== undefined) sq.description = sanitizeString(description, SAVED_QUERY_DESCRIPTION_MAX_LEN);
    if (query !== undefined) {
      const cleanQuery = sanitizeString(query, SAVED_QUERY_SQL_MAX_LEN);
      if (!cleanQuery) return res.status(400).json({ success: false, message: 'query must not be empty' });
      sq.query = cleanQuery;
    }
    if (platform !== undefined) {
      const cleanPlatform = normalizePlatformValue(platform);
      if (cleanPlatform === null) {
        return res.status(400).json({ success: false, message: 'platform must be all or a comma-separated list of linux, windows, macos' });
      }
      sq.platform = cleanPlatform;
    }
    if (node_state !== undefined) {
      const cleanNodeState = normalizeNodeStateValue(node_state);
      if (cleanNodeState === null) {
        return res.status(400).json({ success: false, message: 'node_state must be one of historic, live, both' });
      }
      sq.node_state = cleanNodeState;
    }
    if (defense_kit !== undefined) {
      const cleanDefenseKit = normalizeDefenseKitValue(defense_kit);
      if (cleanDefenseKit === null) {
        return res.status(400).json({ success: false, message: 'defense_kit must be an array of detection, fragments, policy' });
      }
      sq.defense_kit = cleanDefenseKit;
      if (!cleanDefenseKit.includes('detection')) sq.detection_subtypes = [];
    }
    if (detection_subtypes !== undefined) {
      const cleanDetectionSubtypes = normalizeDetectionSubtypesValue(detection_subtypes);
      if (cleanDetectionSubtypes === null) {
        return res.status(400).json({ success: false, message: 'detection_subtypes must be an array of valid detection subtype values' });
      }
      sq.detection_subtypes = cleanDetectionSubtypes;
    }
    if ((sq.defense_kit ?? []).includes('detection') && (sq.detection_subtypes ?? []).length === 0) {
      return res.status(400).json({ success: false, message: 'Select at least one detection subtype when detection is selected' });
    }

    const updated = await repo.save(sq);
    logger.info({ id }, 'Saved query updated');
    return res.status(200).json({ success: true, data: updated });
  } catch (err: unknown) {
    if (isPgUndefinedTableError(err)) {
      logger.warn({ id: req.params.id }, 'Saved query update returned not-found: saved_queries table not yet migrated');
      return res.status(404).json({ success: false, message: 'Query not found' });
    }
    logger.error({ err, id: req.params.id }, 'Failed to update saved query');
    return next(new CustomError(500, 'Raw', 'Failed to update query', null, err));
  }
}

export async function delete_saved_query(req: Request, res: Response, next: NextFunction) {
  try {
    const id = parseInt(String(req.params.id), 10);
    if (!Number.isFinite(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const repo = getDb();
    if (!repo) {
      logger.warn({ id }, 'Saved query deletion aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const sq = await repo.findOne({ where: { id } });
    if (!sq) return res.status(404).json({ success: false, message: 'Query not found' });

    await repo.remove(sq);
    logger.info({ id }, 'Saved query deleted');
    return res.status(200).json({ success: true, message: 'Query deleted' });
  } catch (err: unknown) {
    if (isPgUndefinedTableError(err)) {
      logger.warn({ id: req.params.id }, 'Saved query deletion returned not-found: saved_queries table not yet migrated');
      return res.status(404).json({ success: false, message: 'Query not found' });
    }
    logger.error({ err, id: req.params.id }, 'Failed to delete saved query');
    return next(new CustomError(500, 'Raw', 'Failed to delete query', null, err));
  }
}

import fs from 'fs';
import path from 'path';
import csv from 'csv-parser';

export async function populate_default_saved_queries(
  _req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const repo = getDb();

    if (!repo) {
      logger.warn({}, 'Default saved queries population aborted: fleet database not available');
      return res.status(500).json({
        success: false,
        message: 'Fleet database not available',
      });
    }

    const count = await repo.count();

    if (count > 0) {
      logger.info({ count }, 'Default saved queries population skipped: already populated');
      return res.status(200).json({
        success: true,
        message: 'Default queries already populated',
      });
    }

    const csvPath = path.join(
      process.cwd(),
      'data',
      'savedqueries.csv'
    );

    const rows: Record<string, string>[] = [];

    await new Promise<void>((resolve, reject) => {
      fs.createReadStream(csvPath)
        .pipe(csv())
        .on('data', (row: Record<string, string>) => rows.push(row))
        .on('end', () => resolve())
        .on('error', reject);
    });

    const entities = [];
    let skippedCount = 0;

    for (const row of rows) {
      const cleanName = sanitizeString(row.name, SAVED_QUERY_NAME_MAX_LEN);
      const cleanQuery = sanitizeString(row.query, SAVED_QUERY_SQL_MAX_LEN);

      if (!cleanName || !cleanQuery) {
        skippedCount++;
        continue;
      }

      const cleanPlatform =
        normalizePlatformValue(row.platform) ?? 'all';

      const cleanNodeState =
        normalizeNodeStateValue(row.node_state) ?? 'both';

      const cleanDefenseKit =
        normalizeDefenseKitValue(
          row.defence_kit
            ? row.defence_kit.split(',').map(s => s.trim())
            : []
        ) ?? [];

      const cleanDetectionSubtypes =
        normalizeDetectionSubtypesValue(
          row.detection_subtypes
            ? row.detection_subtypes.split(',').map(s => s.trim())
            : []
        ) ?? [];

      entities.push(
        repo.create({
          name: cleanName,
          description: sanitizeString(
            row.description,
            SAVED_QUERY_DESCRIPTION_MAX_LEN
          ),
          query: cleanQuery,
          platform: cleanPlatform,
          node_state: cleanNodeState,
          defense_kit: cleanDefenseKit,
          detection_subtypes:
            cleanDefenseKit.includes('detection')
              ? cleanDetectionSubtypes
              : [],
          created_by_user_id: null,
          created_by_name: 'System',
        })
      );
    }

    await repo.save(entities);

    logger.info({ count: entities.length, skipped: skippedCount, totalRows: rows.length }, 'Populated default saved queries');

    return res.status(201).json({
      success: true,
      inserted: entities.length,
    });
  } catch (err: unknown) {
    if (isPgUndefinedTableError(err)) {
      logger.warn({}, 'Default saved queries population aborted: saved_queries table not yet migrated');
      return res.status(503).json({
        success: false,
        message:
          'saved_queries table not initialised — run database migrations',
      });
    }

    logger.error({ err }, 'Failed to populate default saved queries');
    return next(new CustomError(500, 'Raw', 'Failed to populate default queries', null, err));
  }
}
