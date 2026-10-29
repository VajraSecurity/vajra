import { DataSourceOptions } from 'typeorm';
import { SnakeNamingStrategy } from 'typeorm-naming-strategies';
import {
  POOL_SIZE,
  HUNT_POOL_SIZE,
  DB_STATEMENT_TIMEOUT_MS,
  DB_QUERY_TIMEOUT_MS_POOL,
  DB_IDLE_IN_TRANSACTION_TIMEOUT_MS,
  DB_POOL_IDLE_TIMEOUT_MS,
  DB_POOL_CONNECTION_TIMEOUT_MS,
} from '../../consts';
import { getLogger } from '../../utils/logger';

const logger = getLogger('orm.config');

// Shared node-postgres pool settings. Without these a runaway query holds its
// pool slot indefinitely (the Express watchdog answers the client but never
// cancels the query), and pooled connections are never reaped — production
// showed backends idle for 59 days. See the constants for why the statement
// timeout sits above REQUEST_TIMEOUT_MS rather than below it.
const poolExtra = {
  statement_timeout: DB_STATEMENT_TIMEOUT_MS,
  query_timeout: DB_QUERY_TIMEOUT_MS_POOL,
  idle_in_transaction_session_timeout: DB_IDLE_IN_TRANSACTION_TIMEOUT_MS,
  idleTimeoutMillis: DB_POOL_IDLE_TIMEOUT_MS,
  connectionTimeoutMillis: DB_POOL_CONNECTION_TIMEOUT_MS,
};

// Primary Database Configuration
export const databaseConfig: DataSourceOptions = {
  type: 'postgres',
  name: 'default',
  host: process.env.PG_HOST,
  port: Number(process.env.PG_PORT),
  username: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.POSTGRES_DB,
  synchronize: process.env.NODE_ENV !== 'production',
  logging: false,
  entities: [
    __dirname + '/../entities/users/**/*.{js,ts}',
    __dirname + '/../entities/audit/**/*.{js,ts}',
    __dirname + '/../entities/session/**/*.{js,ts}',
    __dirname + '/../entities/ai/**/*.{js,ts}',
    __dirname + '/../entities/rule_engine/**/*.{js,ts}',
  ],
  namingStrategy: new SnakeNamingStrategy(),
  poolSize: POOL_SIZE,
  applicationName: 'vajra-backend-primary',
  extra: poolExtra,
  poolErrorHandler: (err) => logger.error({ err }, 'Connection pool error (primary)'),
};

// Secondary Database Configuration
export const databaseConfig2: DataSourceOptions = {
  type: 'postgres',
  name: 'secondary',
  host: process.env.PG_HOST1,
  port: Number(process.env.PG_PORT1),
  username: process.env.POSTGRES_USER1,
  password: process.env.POSTGRES_PASSWORD1,
  database: process.env.POSTGRES_DB1,
  synchronize: process.env.NODE_ENV !== 'production',
  logging: false,
  // The users, audit and session entities belong to the primary DB only (see
  // databaseConfig above) and must not be registered here. Registering them
  // makes synchronize() — active whenever NODE_ENV !== 'production', including
  // db:setup:fleet — create a second, unused copy of vajra_users, audit_logs,
  // audit_trail, user_sessions and the certin_compliance tables on the fleet DB.
  // Nothing reads them through this connection: real access goes via
  // dbSources[0], or raw SQL against the fleet tables in entities/fleet/.
  // Deployments that already have those duplicate tables keep them; dropping
  // them is a data decision, not a code change.
  entities: [
    // Fleet entities (nodes, compliance, etc.) live in the secondary DB
    __dirname + '/../entities/fleet/**/*.{js,ts}',
  ],
  namingStrategy: new SnakeNamingStrategy(),
  poolSize: POOL_SIZE,
  applicationName: 'vajra-backend-fleet',
  extra: poolExtra,
  poolErrorHandler: (err) => logger.error({ err }, 'Connection pool error (secondary)'),
};

// Group-scoped historical-hunting connection.
//
// Same physical database as the secondary/fleet config above, but authenticated
// as a separate, lower-privilege role (vajra_hunt) that does not own the fleet
// tables. Ownership is what matters here: Postgres skips Row-Level Security
// entirely for a table's owner (and for superusers), so the secondary config
// above is completely unaffected by any RLS policy — this is the ONE connection
// where per-group row filtering is actually enforced by the database, used only
// when a caller's access is restricted to specific groups (never for Super
// Admin / global queries, which keep using the secondary connection as before).
//
// Optional at startup: if POSTGRES_HUNT_USER/PASSWORD aren't set, or the role
// hasn't been provisioned yet (see setupHuntRole() in ormconfig-setup.ts), the
// app runs fine without it — group-scoped historical hunting just reports
// "not available" rather than the whole server failing to start.
export const databaseConfigHunt: DataSourceOptions = {
  type: 'postgres',
  name: 'hunt',
  host: process.env.PG_HOST1,
  port: Number(process.env.PG_PORT1),
  username: process.env.POSTGRES_HUNT_USER,
  password: process.env.POSTGRES_HUNT_PASSWORD,
  database: process.env.POSTGRES_DB1,
  synchronize: false, // this role must never create or alter schema
  logging: false,
  entities: [], // raw manager.query() only — no repositories used on this connection
  namingStrategy: new SnakeNamingStrategy(),
  poolSize: HUNT_POOL_SIZE,
  applicationName: 'vajra-backend-hunt',
  extra: poolExtra,
  poolErrorHandler: (err) => logger.error({ err }, 'Connection pool error (hunt)'),
};

// vajra_users indexes are created by orm/config/ormconfig-setup.ts at startup,
// not by TypeORM synchronize (disabled above). Note that idx_vajra_users_email
// is a unique index on LOWER(email), not on email, so only a case-folded
// predicate such as WHERE LOWER(email) = LOWER($1) can use it.

export default databaseConfig;
