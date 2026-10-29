import { DataSource, DataSourceOptions} from 'typeorm';
import { getLogger } from '../utils/logger';

const logger = getLogger('orm.dbCreateConnection');

export const dbCreateConnection = async (
  ...configs: DataSourceOptions[]
): Promise<DataSource[] | null> => {
  const dataSources: DataSource[] = [];
  let currentConfig: DataSourceOptions | undefined;

  try {
    for (const config of configs) {
      currentConfig = config;
      const appDataSource = await new DataSource(config).initialize();
      logger.info({ name: config.name, database: config.database }, 'Database connection established');
      dataSources.push(appDataSource);
    }
    return dataSources;
  } catch (err) {
    // currentConfig identifies which of the (possibly several) configs passed
    // in was mid-initialize when this failed — without it, a failure on the
    // 2nd or 3rd connection in the list is indistinguishable from the 1st.
    logger.error({ err, name: currentConfig?.name, database: currentConfig?.database }, 'Database connection failed');

    // Cleanup already initialized connections
    for (const ds of dataSources) {
      try {
        if (ds.isInitialized) {
          await ds.destroy();
        }
      } catch (cleanupErr) {
        logger.error({ err: cleanupErr, name: ds.name, database: ds.options?.database }, 'Error during database connection cleanup');
      }
    }

    throw err;
  }
};