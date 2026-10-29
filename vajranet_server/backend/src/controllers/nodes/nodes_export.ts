import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { NODE_STATUS_ONLINE_THRESHOLD_SECONDS, PAGINATION_MAX_ROWS_NODES } from '../../consts';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { LATEST_SECURITY_PRODUCTS_QUERY } from '../../utils/latestSecurityProducts';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodes.nodesExport');

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  let str = typeof value === 'string' ? value : String(value);
  if (/^[=+\-@]/.test(str)) {
    str = "'" + str;
  }
  const escaped = str.replace(/"/g, '""');
  // Quote if cell contains commas, quotes, or newlines.
  if (/[",\n\r]/.test(str)) return `"${escaped}"`;
  return escaped;
}

function securityProductsToCell(products: Array<{ name?: unknown; state?: unknown }> | undefined): string {
  if (!Array.isArray(products) || products.length === 0) return '';
  return products
    .map((p) => `${String(p?.name ?? '').trim()}:${String(p?.state ?? '').trim()}`)
    .filter((s) => s !== ':')
    .join(';');
}

/**
 * Export all nodes as a CSV.
 * Includes each node's latest known `security_products` (name/state pairs).
 */
export const nodes_export = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.error('Database connection not available');
      return res.status(500).json({ status: 'Error', message: 'Database connection not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    const scopeWhere = scope.unrestricted ? '' : 'WHERE owner_group_id = ANY($1::text[])';
    const nodesParams: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    const nodesQuery = `
      SELECT
        id, hostname, os_name, os_platform, agent_online, host_identifier, enrolled_on, last_seen, isolated,
        CASE
          WHEN last_seen > (EXTRACT(EPOCH FROM NOW()) - ${NODE_STATUS_ONLINE_THRESHOLD_SECONDS}) THEN 'Online'
          ELSE 'Offline'
        END AS status
      FROM nodes
      ${scopeWhere}
      ORDER BY last_seen DESC
      LIMIT ${PAGINATION_MAX_ROWS_NODES}
    `;

    // Tagged with `step` on failure — without it, a failure in this main
    // nodes query is indistinguishable in the outer catch's generic "Failed
    // to export nodes as CSV" log from a failure in the security-products
    // enrichment query below (same pattern as node_programs.ts's taggedQuery).
    const nodes: any[] = await entityManager.query(nodesQuery, nodesParams).catch((err: unknown) => {
      logger.warn({ err, step: 'nodes' }, 'Node export query failed for one step');
      throw err;
    });

    const hostIdentifiers = Array.isArray(nodes)
      ? nodes.map((n) => n?.host_identifier).filter((h) => h !== null && h !== undefined)
      : [];

    const productsByHost = new Map<string, Array<{ name: string; state: string }>>();

    if (hostIdentifiers.length > 0) {
      // Latest state per (host, product) — shared loose-index-scan form.
      const securityProductsQuery = LATEST_SECURITY_PRODUCTS_QUERY;

      const securityProducts = await entityManager.query(securityProductsQuery, [hostIdentifiers]).catch((err: unknown) => {
        logger.warn({ err, step: 'security_products' }, 'Node export query failed for one step');
        throw err;
      });

      securityProducts.forEach((product: any) => {
        if (!productsByHost.has(product.host_identifier)) {
          productsByHost.set(product.host_identifier, []);
        }
        productsByHost.get(product.host_identifier)!.push({
          name: String(product.name ?? ''),
          state: String(product.state ?? ''),
        });
      });
    }

    const headers = [
      'id',
      'hostname',
      'os_name',
      'os_platform',
      'agent_online',
      'host_identifier',
      'enrolled_on',
      'last_seen',
      'isolated',
      'status',
      'security_products',
    ];

    const lines: string[] = [];
    lines.push(headers.map(csvCell).join(','));

    for (const node of nodes ?? []) {
      const hostIdentifier = String(node?.host_identifier ?? '');
      const products = productsByHost.get(hostIdentifier);

      const row = [
        node?.id ?? '',
        node?.hostname ?? '',
        node?.os_name ?? '',
        node?.os_platform ?? '',
        node?.agent_online ?? '',
        node?.host_identifier ?? '',
        node?.enrolled_on ?? '',
        node?.last_seen ?? '',
        node?.isolated ?? '',
        node?.status ?? '',
        securityProductsToCell(products),
      ];

      lines.push(row.map(csvCell).join(','));
    }

    const csv = lines.join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="nodes.csv"');
    res.setHeader('Cache-Control', 'no-store');
    logger.debug({ count: nodes?.length ?? 0 }, 'Nodes exported as CSV');
    return res.status(200).send(csv);
  } catch (err) {
    logger.error({ err }, 'Failed to export nodes as CSV');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};