/**
 * Raw pg Client for LISTEN/NOTIFY and other use cases that need a dedicated connection.
 * Uses the same env vars as ormconfig (PG_HOST, PG_PORT, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB).
 * Includes automatic reconnection on unexpected disconnections.
 */

import { Client } from 'pg';
import { PG_DEFAULT_PORT } from '../consts';
import { getLogger } from '../utils/logger';

const logger = getLogger('orm.rawPgClient');

let rawClient: Client | null = null;
let rawClientSecondary: Client | null = null;
let primaryReconnecting = false;
let secondaryReconnecting = false;

/**
 * Attach error and end handlers that nullify the client reference so the
 * next getRawPgClient() / getRawPgClientSecondary() call creates a fresh
 * connection instead of reusing a dead one.
 *
 * Both 'error' and 'end' must be handled:
 *  - 'error' fires on unexpected failures (DB crash, network drop).
 *  - 'end'   fires on a clean server-initiated close.
 * Without the 'end' handler the cached reference stays pointing at a dead
 * client, so every subsequent call returns the same dead client — causing
 * liveWeb.ts setupNotifications() to loop endlessly retrying LISTEN on it.
 */
function attachErrorHandler(client: Client, label: string, resetFn: () => void): void {
  client.on('error', (err: Error) => {
    logger.error({ err, label }, 'Raw PG client error');
    client.end().catch(() => {});
    resetFn();
  });
  client.on('end', () => {
    logger.warn({ label }, 'Raw PG client connection ended, will reconnect on next call');
    client.end().catch(() => {});
    resetFn();
  });
}

export async function getRawPgClient(): Promise<Client> {
  if (rawClient) {
    return rawClient;
  }
  if (primaryReconnecting) {
    logger.warn('Primary raw PG client connect already in progress, rejecting concurrent request');
    throw new Error('Primary raw PG client is reconnecting');
  }
  primaryReconnecting = true;
  try {
    const client = new Client({
      host: process.env.PG_HOST,
      port: Number(process.env.PG_PORT) || PG_DEFAULT_PORT,
      user: process.env.POSTGRES_USER,
      password: process.env.POSTGRES_PASSWORD,
      database: process.env.POSTGRES_DB,
      application_name: 'vajra-backend-raw-primary',
    });
    attachErrorHandler(client, 'primary', () => {
      rawClient = null;
      logger.warn('Primary raw PG client disconnected, will reconnect on next call');
    });
    await client.connect();
    rawClient = client;
    logger.info('Primary raw PG client connected');
    return rawClient;
  } catch (err) {
    logger.error({ err, label: 'primary' }, 'Failed to connect raw PG client');
    throw err;
  } finally {
    primaryReconnecting = false;
  }
}

/** Raw pg Client for the secondary (fleet_new) database. */
export async function getRawPgClientSecondary(): Promise<Client> {
  if (rawClientSecondary) {
    return rawClientSecondary;
  }
  if (secondaryReconnecting) {
    logger.warn('Secondary raw PG client connect already in progress, rejecting concurrent request');
    throw new Error('Secondary raw PG client is reconnecting');
  }
  secondaryReconnecting = true;
  try {
    const client = new Client({
      host: process.env.PG_HOST1,
      port: Number(process.env.PG_PORT1) || PG_DEFAULT_PORT,
      user: process.env.POSTGRES_USER1,
      password: process.env.POSTGRES_PASSWORD1,
      database: process.env.POSTGRES_DB1,
      application_name: 'vajra-backend-raw-fleet',
    });
    attachErrorHandler(client, 'secondary', () => {
      rawClientSecondary = null;
      logger.warn('Secondary raw PG client disconnected, will reconnect on next call');
    });
    await client.connect();
    rawClientSecondary = client;
    logger.info('Secondary raw PG client connected');
    return rawClientSecondary;
  } catch (err) {
    logger.error({ err, label: 'secondary' }, 'Failed to connect raw PG client');
    throw err;
  } finally {
    secondaryReconnecting = false;
  }
}

export async function closeRawPgClient(): Promise<void> {
  if (rawClient) {
    await rawClient.end().catch((err) => logger.warn({ err, label: 'primary' }, 'Error closing raw PG client'));
    rawClient = null;
  }
  if (rawClientSecondary) {
    await rawClientSecondary.end().catch((err) => logger.warn({ err, label: 'secondary' }, 'Error closing raw PG client'));
    rawClientSecondary = null;
  }
}
