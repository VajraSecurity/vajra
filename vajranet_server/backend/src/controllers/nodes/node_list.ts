import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import {
  PAGINATION_DEFAULT_ROWS,
  PAGINATION_MAX_ROWS_NODES,
  NODE_STATUS_ONLINE_THRESHOLD_SECONDS,
} from '../../consts';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { LATEST_SECURITY_PRODUCTS_QUERY } from '../../utils/latestSecurityProducts';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodes.nodeList');

export async function node_list(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.error('Database connection not initialized or insufficient sources');
      return res.status(500).json({
        status: 'Error',
        message: 'Database connection not initialized or insufficient sources'
      });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };

    const rows = Math.max(1, Math.min(parseInt(req.query.rows as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_NODES));
    const pageno = Math.max(parseInt(req.query.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * rows;

    // Scoped (non-Super-Admin) callers only see nodes in their assigned group(s).
    // Nodes with no group at all are hidden from scoped users (fail-safe default).
    const scopeWhere = scope.unrestricted ? '' : 'WHERE owner_group_id = ANY($3::text[])';
    const params: unknown[] = scope.unrestricted ? [rows, offset] : [rows, offset, scopeGroupIds(scope)];

    const query = `
      SELECT
        id, hostname, os_name, os_platform, agent_online, host_identifier, enrolled_on, last_seen, isolated, critical, critical_reason, address, group_ids,
        CASE
          WHEN last_seen > (EXTRACT(EPOCH FROM NOW()) - ${NODE_STATUS_ONLINE_THRESHOLD_SECONDS}) THEN 'Online'
          ELSE 'Offline'
        END AS status
      FROM nodes
      ${scopeWhere}
      ORDER BY last_seen DESC
      LIMIT $1 OFFSET $2
    `;

    // Tagged with `step` on failure — without it, a failure in this main
    // nodes query is indistinguishable in the outer catch's generic "Failed
    // to fetch node list" log from a failure in the security-products
    // enrichment query below (same pattern as node_programs.ts's taggedQuery).
    const result = await entityManager.query(query, params).catch((err: unknown) => {
      logger.error({ err, step: 'nodes' }, 'Node list query failed for one step');
      throw err;
    });

    if (!result || result.length === 0) {
      logger.debug({ count: 0 }, 'Node list retrieved');
      return res.status(200).json({
        success: true,
        count: 0,
        nodes: [],
        message: 'No nodes found'
      });
    }

    const hostIdentifiers = result.map((node: any) => node.host_identifier);
    
    // Latest state per (host, product). See LATEST_SECURITY_PRODUCTS_QUERY for
    // why this is a loose index scan rather than the obvious ROW_NUMBER() form.
    const securityProductsQuery = LATEST_SECURITY_PRODUCTS_QUERY;

    const securityProducts = await entityManager.query(securityProductsQuery, [hostIdentifiers]).catch((err: unknown) => {
      logger.error({ err, step: 'security_products' }, 'Node list query failed for one step');
      throw err;
    });

    const productsByHost = new Map<string, Array<{name: string, state: string}>>();
    securityProducts.forEach((product: any) => {
      if (!productsByHost.has(product.host_identifier)) {
        productsByHost.set(product.host_identifier, []);
      }
      productsByHost.get(product.host_identifier)!.push({
        name: product.name,
        state: product.state
      });
    });

    const enrichedNodes = result.map((node: any) => {
      const products = productsByHost.get(node.host_identifier) || [];

      return {
        ...node,
        security_products: products
      };
    });

    logger.debug({ count: enrichedNodes.length }, 'Node list retrieved');
    return res.status(200).json({
      success: true,
      count: enrichedNodes.length,
      nodes: enrichedNodes
    });

  } catch (err) {
    logger.error({ err }, 'Failed to fetch node list');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
