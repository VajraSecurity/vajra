import api from '../../api/axiosInstance';

export type NodeRow = {
  host_identifier: string;
  hostname: string;
  /** e.g. "windows", "ubuntu" — used to pick Windows vs Linux agent paths */
  os_platform?: string | null;
};

/** Matches NodesView: non-Windows → Linux agent path */
export function isLinuxNode(row: NodeRow): boolean {
  return !(row.os_platform || '').toLowerCase().includes('windows');
}

/** Inverse of isLinuxNode — used by the Windows maintained-apps software tab,
 * the one picker in this codebase that targets Windows hosts specifically. */
export function isWindowsNode(row: NodeRow): boolean {
  return (row.os_platform || '').toLowerCase().includes('windows');
}

export const MAX_BULK_OPERATIONS = 2500;

export function normalizeNodesList(payload: unknown): NodeRow[] {
  let arr: unknown[] = [];
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const o = payload as Record<string, unknown>;
    if (Array.isArray(o.data)) arr = o.data;
    else if (Array.isArray(o.nodes)) arr = o.nodes;
  } else if (Array.isArray(payload)) {
    arr = payload;
  }

  const rows: NodeRow[] = [];
  for (const item of arr) {
    if (!item || typeof item !== 'object') continue;
    const n = item as Record<string, unknown>;
    const host = String(n.host_identifier ?? n.id ?? '').trim();
    if (!host) continue;
    const hostname = String(n.hostname ?? n.name ?? 'Unknown').trim() || 'Unknown';
    const os_platform =
      n.os_platform != null
        ? String(n.os_platform)
        : n.os != null
          ? String(n.os)
          : null;
    rows.push({ host_identifier: host, hostname, os_platform });
  }

  rows.sort((a, b) => a.hostname.localeCompare(b.hostname) || a.host_identifier.localeCompare(b.host_identifier));
  return rows;
}

async function requestNodesList(): Promise<{ nodes: NodeRow[]; error: string | null }> {
  try {
    const res = await api.get<unknown>('/nodes/identifiers');
    return { nodes: normalizeNodesList(res.data), error: null };
  } catch (e: unknown) {
    const msg = e && typeof e === 'object' && 'message' in e ? String((e as Error).message) : 'Failed to load nodes';
    return { nodes: [], error: msg };
  }
}

let inFlightNodesList: Promise<{ nodes: NodeRow[]; error: string | null }> | null = null;

/**
 * Always-fresh fleet list, but only one request at a time.
 *
 * Unlike fetchNodesListCached() below this keeps its per-mount freshness —
 * the handle is dropped as soon as the request settles, so any later call
 * goes back to the network. It only collapses genuinely *concurrent*
 * duplicates, which mounting any screen with both a node counter and a node
 * picker produces: Responsive/index.tsx asks for the list purely to render
 * "Total nodes: N" at the exact moment its active tab asks for the same list
 * to populate the picker, so every visit fired two identical unpaginated
 * GET /nodes/identifiers. Callers derive their own arrays from the result
 * (`list.filter(...)`) and never mutate it, so sharing one response between
 * them is indistinguishable from two identical ones.
 */
export function fetchNodesList(): Promise<{ nodes: NodeRow[]; error: string | null }> {
  if (inFlightNodesList) return inFlightNodesList;
  const pending = requestNodesList().finally(() => {
    if (inFlightNodesList === pending) inFlightNodesList = null;
  });
  inFlightNodesList = pending;
  return pending;
}

let cachedNodesPromise: Promise<{ nodes: NodeRow[]; error: string | null }> | null = null;

/**
 * Process-lifetime cache around fetchNodesList() — several patch-management
 * components (one usePatchPushFlow per SoftwareInventoryPage/AvailableUpdatesPage
 * row, plus PatchJobHistory/RebootRequiredPanel) all just want a
 * host_identifier -> hostname/OS lookup for display and would otherwise each
 * fire an identical GET /nodes/identifiers. A failed fetch clears the cache
 * so the next caller retries instead of being stuck replaying the same error.
 */
export function fetchNodesListCached(): Promise<{ nodes: NodeRow[]; error: string | null }> {
  if (!cachedNodesPromise) {
    cachedNodesPromise = fetchNodesList().catch((e) => {
      cachedNodesPromise = null;
      throw e;
    });
  }
  return cachedNodesPromise;
}

// This module-level cache must not outlive the session it was fetched under:
// logout here is an SPA navigate() (see Sidebar.tsx's handleLogout), never a
// full page reload, so without this the cache would silently survive a
// logout -> different-user-login in the same tab. This app has group-scoped
// RBAC (some users see a narrower host set than others) — serving a stale,
// wider-scoped cache to the next logged-in user would leak hostname/OS
// metadata for hosts they're not authorized to see. clearAuthData()
// (services/auth.ts) already dispatches this event on every logout.
if (typeof window !== 'undefined') {
  window.addEventListener('auth-change', () => {
    cachedNodesPromise = null;
    cachedNodesByHost = null;
  });
}

/** Builds a lowercased-host_identifier lookup map from a NodeRow list. */
export function toNodesByHost(nodes: NodeRow[]): Map<string, NodeRow> {
  return new Map(nodes.map((n) => [n.host_identifier.toLowerCase(), n]));
}

let cachedNodesByHost: { source: NodeRow[]; map: Map<string, NodeRow> } | null = null;

/**
 * fetchNodesListCached() + toNodesByHost() in one, with the derived Map itself
 * cached alongside the node list.
 *
 * fetchNodesListCached() already collapses the network call, but every caller
 * then built its own private fleet-sized Map from the shared array. The patch
 * tables mount one usePatchPushFlow per table row (25 by default), so a user
 * working down a page of packages accumulated one full Map per row touched,
 * each holding a distinct object identity that defeats any downstream
 * useMemo keyed on it. Keyed on the source array's identity so a post-logout
 * (or otherwise re-fetched) list rebuilds instead of serving a stale map.
 */
export function fetchNodesByHostCached(): Promise<Map<string, NodeRow>> {
  return fetchNodesListCached().then(({ nodes }) => {
    if (cachedNodesByHost?.source !== nodes) {
      cachedNodesByHost = { source: nodes, map: toNodesByHost(nodes) };
    }
    return cachedNodesByHost.map;
  });
}
