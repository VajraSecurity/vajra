import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { RECENT_ROWS_ID_WINDOW } from '../../consts/database';
import { isPgUndefinedTableError } from '../../utils/dbErrors';

const logger = getLogger('nodes.nodeStorage');

function parseNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = typeof value === 'number' ? value : parseInt(String(value).trim(), 10);
  return Number.isFinite(n) ? n : null;
}

export async function node_storage(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ success: false, message: 'Host identifier is required' });
    }

    const dataSources = dbSourceConnection();
    if (!dataSources || dataSources.length < 2) {
      logger.error({ host_identifier }, 'Database connection not initialized');
      return res.status(500).json({ success: false, message: 'Database connection not initialized' });
    }

    const db = dataSources[1];

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.debug({ host_identifier, reason: 'host_out_of_scope' }, 'Node storage request rejected');
      return res.status(404).json({ success: false, message: 'Node not found' });
    }

    const nodeRows = await db.query(
      `SELECT host_identifier, os_platform FROM nodes WHERE host_identifier = $1 LIMIT 1`,
      [host_identifier],
    );

    if (!nodeRows?.length) {
      // Distinct from the host_out_of_scope rejection above (same 404 shape
      // otherwise) — this host passed the scope check but has no row in
      // `nodes` at all (e.g. deleted after being added to a group), which
      // without this would be indistinguishable in logs from a normal
      // out-of-scope rejection.
      logger.debug({ host_identifier, reason: 'node_not_found' }, 'Node storage request rejected');
      return res.status(404).json({ success: false, message: 'Node not found' });
    }

    const node = nodeRows[0] as Record<string, unknown>;
    const osPlatform = String(node.os_platform || '').toLowerCase();
    const isWindows = osPlatform.includes('windows');

    let volumes: Array<{
      name: string;
      mount: string;
      fs: string;
      totalBytes: number;
      usedBytes: number;
      availableBytes: number;
      bootPartition?: boolean;
    }> = [];
    let mounts: Array<Record<string, unknown>> = [];
    let diskInfo: Array<Record<string, unknown>> = [];
    let bitlocker: Array<Record<string, unknown>> = [];
    let diskEncryption: Array<Record<string, unknown>> = [];

    if (isWindows) {
      // Windows: logical_drives gives per-drive utilization (C:, D:, etc.)
      try {
        const ldRows = await db.query(
          `SELECT DISTINCT ON (device_id) device_id, description, free_space, size, file_system, boot_partition
           FROM logical_drives
           WHERE host_identifier = $1
             AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM logical_drives)
           ORDER BY device_id, unixtime DESC`,
          [host_identifier],
        );
        const rows = Array.isArray(ldRows) ? (ldRows as Array<Record<string, unknown>>) : [];
        volumes = rows.map((row) => {
          const totalBytes = parseNumber(row.size) ?? 0;
          const availableBytes = parseNumber(row.free_space) ?? 0;
          const usedBytes = Math.max(0, totalBytes - availableBytes);
          return {
            name: String(row.device_id || 'Volume'),
            mount: String(row.device_id || ''),
            fs: String(row.file_system || 'unknown'),
            totalBytes,
            usedBytes,
            availableBytes,
            bootPartition: row.boot_partition === 1 || row.boot_partition === true,
          };
        });
      } catch (err: unknown) {
        if (!isPgUndefinedTableError(err)) {
          logger.error({ err, host_identifier, step: 'logical_drives' }, 'Node storage query failed');
          throw err;
        }
        logger.warn({ err, host_identifier }, 'logical_drives table unavailable, falling back to empty volumes');
      }
    } else {
      // Linux/macOS: use mounts table
      try {
        const mountRows = await db.query(
          `SELECT DISTINCT ON (path) device, device_alias, path, type,
            COALESCE(blocks_size, 0)::bigint * COALESCE(blocks, 0)::bigint AS total_bytes,
            COALESCE(blocks_size, 0)::bigint * COALESCE(blocks_available, 0)::bigint AS available_bytes,
            COALESCE(blocks_size, 0)::bigint * COALESCE(blocks_free, 0)::bigint AS free_bytes,
            blocks_size, blocks, blocks_free, blocks_available, inodes, inodes_free, flags
          FROM mounts
          WHERE host_identifier = $1
            AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM mounts)
          ORDER BY path, unixtime DESC`,
          [host_identifier],
        );
        mounts = Array.isArray(mountRows) ? (mountRows as Array<Record<string, unknown>>) : [];
      } catch (err: unknown) {
        if (!isPgUndefinedTableError(err)) {
          logger.error({ err, host_identifier, step: 'mounts' }, 'Node storage query failed');
          throw err;
        }
        logger.warn({ err, host_identifier }, 'mounts table unavailable, falling back to empty volumes');
      }

      volumes = mounts.map((row) => {
        const totalBytes = parseNumber(row.total_bytes) ?? 0;
        const availableBytes = parseNumber(row.available_bytes) ?? parseNumber(row.free_bytes) ?? 0;
        const usedBytes = Math.max(0, totalBytes - availableBytes);
        return {
          name: String(row.device_alias || row.device || 'Volume'),
          mount: String(row.path || ''),
          fs: String(row.type || 'unknown'),
          totalBytes,
          usedBytes,
          availableBytes,
        };
      });
    }

    try {
      const diskRows = await db.query(
        `SELECT DISTINCT ON (disk_index) disk_id, pnp_device_id, partitions, disk_index, type, disk_size,
          manufacturer, hardware_model, name, serial, description
        FROM disk_info
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM disk_info)
        ORDER BY disk_index, unixtime DESC`,
        [host_identifier],
      );
      diskInfo = Array.isArray(diskRows) ? (diskRows as Array<Record<string, unknown>>) : [];
    } catch (err: unknown) {
      if (!isPgUndefinedTableError(err)) {
        logger.error({ err, host_identifier, step: 'disk_info' }, 'Node storage query failed');
        throw err;
      }
      logger.warn({ err, host_identifier }, 'disk_info table unavailable, falling back to empty disk info');
    }

    try {
      const bitlockerRows = await db.query(
        `SELECT DISTINCT ON (drive_letter) device_id, drive_letter, persistent_volume_id, conversion_status,
          protection_status, encryption_method, version, percentage_encrypted, lock_status
        FROM bitlocker_info
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM bitlocker_info)
        ORDER BY drive_letter, unixtime DESC`,
        [host_identifier],
      );
      bitlocker = Array.isArray(bitlockerRows) ? (bitlockerRows as Array<Record<string, unknown>>) : [];
    } catch (err: unknown) {
      if (!isPgUndefinedTableError(err)) {
        logger.error({ err, host_identifier, step: 'bitlocker_info' }, 'Node storage query failed');
        throw err;
      }
      logger.warn({ err, host_identifier }, 'bitlocker_info table unavailable, falling back to empty bitlocker info');
    }

    try {
      // `disk_encryption` is append-only telemetry: one row per volume per check-in, so
      // hundreds of thousands of rows describing at most a few dozen volumes per host.
      // Written as `WHERE host_identifier = $1 AND id > (SELECT MAX(id) - N ...)` the id
      // bound becomes the driving indexed predicate, so the planner walks
      // disk_encryption_pkey over the whole id window and post-filters the host.
      //
      // Instead, enumerate the handful of real volume names for this host with a
      // recursive loose index scan, then fetch one row per name. Both halves ride
      // idx_disk_encryption_host_name_unixtime (host_identifier, name, unixtime DESC),
      // which the naive shape can never reach.
      //
      // The `id > MAX(id) - RECENT_ROWS_ID_WINDOW` predicate is load-bearing and must
      // stay: it excludes hosts whose newest row has aged out of the window. The
      // trailing UNION ALL branch handles a NULL `name` (the column has no NOT NULL
      // constraint), which the recursive `name > prev` walk can never reach but a
      // DISTINCT ON would have emitted as a final group.
      const diskEncryptionRows = await db.query(
        `WITH RECURSIVE lo AS (
          SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} AS min_id FROM disk_encryption
        ),
        names AS (
          SELECT (SELECT d.name
                    FROM disk_encryption d
                   WHERE d.host_identifier = $1
                   ORDER BY d.name
                   LIMIT 1) AS nm
          UNION ALL
          SELECT (SELECT d.name
                    FROM disk_encryption d
                   WHERE d.host_identifier = $1 AND d.name > names.nm
                   ORDER BY d.name
                   LIMIT 1)
            FROM names
           WHERE names.nm IS NOT NULL
        )
        SELECT r.name, r.uuid, r.encrypted, r.type, r.encryption_status, r.uid, r.user_uuid, r.filevault_status
        FROM (
          SELECT s.*
            FROM names
            CROSS JOIN lo
            CROSS JOIN LATERAL (
              SELECT d.name, d.uuid, d.encrypted, d.type, d.encryption_status, d.uid, d.user_uuid, d.filevault_status
                FROM disk_encryption d
               WHERE d.host_identifier = $1
                 AND d.name = names.nm
                 AND d.id > lo.min_id
               ORDER BY d.unixtime DESC
               LIMIT 1
            ) s
           WHERE names.nm IS NOT NULL
          UNION ALL
          SELECT s.*
            FROM lo
            CROSS JOIN LATERAL (
              SELECT d.name, d.uuid, d.encrypted, d.type, d.encryption_status, d.uid, d.user_uuid, d.filevault_status
                FROM disk_encryption d
               WHERE d.host_identifier = $1
                 AND d.name IS NULL
                 AND d.id > lo.min_id
               ORDER BY d.unixtime DESC
               LIMIT 1
            ) s
        ) r
        ORDER BY r.name`,
        [host_identifier],
      );
      diskEncryption = Array.isArray(diskEncryptionRows) ? (diskEncryptionRows as Array<Record<string, unknown>>) : [];
    } catch (err: unknown) {
      if (!isPgUndefinedTableError(err)) {
        logger.error({ err, host_identifier, step: 'disk_encryption' }, 'Node storage query failed');
        throw err;
      }
      logger.warn({ err, host_identifier }, 'disk_encryption table unavailable, falling back to empty disk encryption info');
    }

    logger.debug({ host_identifier, volume_count: volumes.length }, 'Node storage information retrieved');
    return res.status(200).json({
      success: true,
      data: {
        platform: osPlatform,
        volumes,
        mounts,
        diskInfo,
        bitlocker,
        diskEncryption,
      },
    });
  } catch (err) {
    logger.error({ err, host_identifier: req.params?.host_identifier }, 'Failed to fetch node storage information');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
