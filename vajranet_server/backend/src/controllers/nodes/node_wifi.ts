import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodes.nodeWifi');

/**
 * GET /api/nodes/wifi/:host_identifier
 *
 * Returns the latest WiFi snapshot recorded for the given node.
 * The snapshot is written by the WebSocket handler whenever the Linux agent
 * sends a `wifi_push` message.  Returns null data when no snapshot exists yet.
 */
export async function node_wifi_latest(req: Request, res: Response, _next: NextFunction) {
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
      logger.debug({ host_identifier, reason: 'host_out_of_scope' }, 'Latest wifi snapshot request rejected');
      return res.status(404).json({ success: false, message: 'Node not found' });
    }

    const result = await db.query(
      `SELECT
         id, host_identifier, event_type,
         connected_ssid, connected_bssid, connected_interface,
         connected_signal, connected_frequency, connected_channel,
         connected_bitrate, connected_security, connected_ip,
         is_connected, saved_profiles, wifi_timestamp, recorded_at
       FROM wifi_events
       WHERE host_identifier = $1
       ORDER BY recorded_at DESC
       LIMIT 1`,
      [host_identifier],
    );

    if (!result?.length) {
      logger.debug({ host_identifier, found: false }, 'Latest wifi snapshot retrieved');
      return res.status(200).json({ success: true, data: null });
    }

    logger.debug({ host_identifier, found: true }, 'Latest wifi snapshot retrieved');
    return res.status(200).json({ success: true, data: result[0] });
  } catch (err) {
    logger.error({ err, host_identifier: req.params?.host_identifier }, 'Failed to fetch latest wifi snapshot');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
