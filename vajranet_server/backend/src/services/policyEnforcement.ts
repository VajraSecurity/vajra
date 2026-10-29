/**
 * Applies enabled `Policy` rows to agents by translating their `config` into
 * the same `type:'agent'` websocket commands the Enforcement tabs already
 * send interactively (frontend/src/features/Responsive/ResponsivePortTab.tsx,
 * ResponsiveIpTab.tsx, responsiveHardwareCommands.ts) — an agent build sees
 * no difference between a policy-driven command and one an admin sent by
 * hand from the Responsive tabs.
 *
 * Three call sites wire this in:
 *   - policy_management.ts: push after create/update/assignTargets, fire-
 *     and-forget, to currently-connected targets (mutation-time).
 *   - websocket/node.ts's nodeExt(): push on agent (re)connect, so a policy
 *     enabled/changed while a node was offline still lands once it's back.
 *   - a periodic sweep (see policy_management.ts's setInterval registration —
 *     same module-scope pattern as patch_management.ts's sweepStalePatchJobs)
 *     that re-runs the reconnect logic for every currently connected host,
 *     as a safety net for a mutation-time push that failed silently (e.g. a
 *     transient dispatch error).
 *
 * Deliberately not handled: disabling or deleting a policy sends no reverting
 * command, because there is no reliable pre-policy state to revert to. It only
 * stops future (re)applies; whatever was already pushed to a node stays applied
 * until something else changes it.
 *
 * Known limitation: dispatchToAgent (websocket/node.ts) only reaches agents
 * connected to THIS backend process. In a multi-instance deployment behind
 * Redis-based routing, a policy change or reconnect handled by instance A
 * does not push to agents connected to instance B. Cross-instance broadcast
 * (e.g. Redis pub/sub) would close this gap but is out of scope here.
 *
 * Known protocol gaps: Policy's config schema captures a couple of fields
 * the live `type:'agent'` wire protocol has no slot for today — the same gap
 * exists for the interactive Enforcement tabs, not introduced here:
 *   - portRules.protocol ('tcp' | 'udp' | 'both') is not transmitted.
 *   - usb.scope ('all' | 'storage-only') is not transmitted.
 * Both fields stay stored/editable (the UI already exposes them), but they
 * only affect what's saved, not what's applied, until the agent-side
 * protocol is extended to accept them.
 */

// This forms a require cycle (src/index.ts -> websocket/index.ts ->
// websocket/node.ts -> here -> ../index), as websocket/node.ts and
// websocket/patchDispatch.ts also do. Safe only because dbSourceConnection() is
// called from async functions below and never at module-load time, so it is
// never touched mid-cycle before index.ts finishes evaluating.
import { dbSourceConnection } from '../index';
import { Policy } from '../orm/entities/fleet/Policy';
import { getLogger } from '../utils/logger';

const logger = getLogger('services.policyEnforcement');

function getFleetDb() {
  const sources = dbSourceConnection();
  const db = sources?.[1];
  if (!db || !db.isInitialized) return null;
  return db;
}

/** Matches websocket/node.ts's dispatchToAgent signature exactly. */
export type AgentDispatchFn = (
  hostIdentifier: string,
  payload: Record<string, unknown>,
) => { dispatched: boolean; error?: string };

/** True for hosts dispatchToAgent can currently reach on this process (websocket/node.ts). */
export type IsHostConnectedFn = (hostIdentifier: string) => boolean;

type PlatformCategory = 'windows' | 'macos' | 'linux';

// No canonical raw-os-string to category mapping exists elsewhere:
// isLinuxNode/isWindowsNode in responsiveNodeUtils.ts only split
// Windows/not-Windows. This extends the same substring matching with a macOS
// bucket, for Policy.platforms comparisons.
function platformCategory(osPlatform: string | null | undefined): PlatformCategory {
  const p = (osPlatform || '').toLowerCase();
  if (p.includes('windows')) return 'windows';
  if (p.includes('mac') || p.includes('darwin')) return 'macos';
  return 'linux';
}

// Port/IP rules' wire arg2 is a three-way traffic direction ('all'|'in'|'out'),
// identical in ResponsivePortTab.tsx and ResponsiveIpTab.tsx. Only ipRules has a
// matching concept; portRules has none, so port commands always send 'all'.
function trafficTypeFor(direction: string | undefined): 'all' | 'in' | 'out' {
  if (direction === 'inbound') return 'in';
  if (direction === 'outbound') return 'out';
  return 'all';
}

/**
 * Turns one policy's config into the type:'agent' commands its enabled rules
 * require, matching the Enforcement tabs' wire shapes exactly. `hostOsPlatform`
 * picks the Linux vs Windows Bluetooth branch, as responsiveHardwareCommands.ts's
 * isLinuxNode check does.
 */
export function buildAgentCommands(policy: Policy, hostOsPlatform: string | null): Record<string, unknown>[] {
  const c = (policy.config as Record<string, any>) || {};
  const reason = `Policy: ${policy.name}`;
  const commands: Record<string, unknown>[] = [];

  const portRules = c.portRules;
  if (portRules?.enabled && Array.isArray(portRules.ports)) {
    for (const port of portRules.ports) {
      commands.push({
        type: 'agent',
        params: {
          agent:  'port',
          action: portRules.action,
          arg1:   port,
          arg2:   'all', // portRules has no direction field — see module doc comment
          arg3:   reason,
          reason,
        },
      });
    }
  }

  const ipRules = c.ipRules;
  if (ipRules?.enabled && Array.isArray(ipRules.ips)) {
    for (const ip of ipRules.ips) {
      commands.push({
        type: 'agent',
        params: {
          agent:  'ip',
          action: ipRules.action,
          arg1:   ip,
          arg2:   trafficTypeFor(ipRules.direction),
          arg3:   reason,
          reason,
        },
      });
    }
  }

  const usb = c.usb;
  if (usb?.enabled) {
    commands.push({
      type: 'agent',
      params: {
        agent:  'removableDevice',
        action: usb.action === 'block' ? 'disable' : 'enable', // usb.scope has no wire slot — see module doc comment
        arg1:   reason,
        reason,
      },
    });
  }

  const bluetooth = c.bluetooth;
  if (bluetooth?.enabled) {
    const action = bluetooth.action === 'block' ? 'disable' : 'enable';
    if (platformCategory(hostOsPlatform) === 'windows') {
      commands.push({
        type: 'agent',
        params: {
          agent:        'powershell',
          command_keys: [action === 'enable' ? '48' : '47'],
          arg1:         reason,
          reason,
        },
      });
    } else {
      commands.push({
        type: 'agent',
        params: { agent: 'bluetooth', action, arg1: reason, reason },
      });
    }
  }

  return commands;
}

/**
 * Resolves target_mode/target_node_ids/target_group_ids/platforms into a
 * concrete host_identifier list. Used at mutation time (Hook A), where the
 * full target set — online or not — needs to be known before filtering down
 * to currently-connected hosts.
 */
export async function resolvePolicyTargetHosts(
  policy: Pick<Policy, 'target_mode' | 'target_node_ids' | 'target_group_ids' | 'platforms'>,
): Promise<string[]> {
  const db = getFleetDb();
  if (!db) return [];
  const mode = policy.target_mode ?? 'all';

  let hostIds: string[];
  if (mode === 'none') {
    return [];
  } else if (mode === 'all') {
    const rows: { host_identifier: string }[] = await db.query('SELECT host_identifier FROM nodes');
    hostIds = rows.map((r) => r.host_identifier);
  } else if (mode === 'nodes') {
    hostIds = policy.target_node_ids ?? [];
  } else if (mode === 'groups') {
    const groupIds = policy.target_group_ids ?? [];
    if (groupIds.length === 0) return [];
    const rows: { host_identifier: string }[] = await db.query(
      'SELECT host_identifier FROM nodes WHERE owner_group_id = ANY($1)',
      [groupIds],
    );
    hostIds = rows.map((r) => r.host_identifier);
  } else {
    // mixed
    const groupIds = policy.target_group_ids ?? [];
    const nodeIds  = policy.target_node_ids  ?? [];
    const rows: { host_identifier: string }[] = groupIds.length > 0
      ? await db.query('SELECT host_identifier FROM nodes WHERE owner_group_id = ANY($1)', [groupIds])
      : [];
    hostIds = Array.from(new Set([...nodeIds, ...rows.map((r) => r.host_identifier)]));
  }

  if (Array.isArray(policy.platforms) && policy.platforms.length > 0 && hostIds.length > 0) {
    const allowed = new Set(policy.platforms.map((p) => p.toLowerCase()));
    const rows: { host_identifier: string; os_platform: string | null }[] = await db.query(
      'SELECT host_identifier, os_platform FROM nodes WHERE host_identifier = ANY($1)',
      [hostIds],
    );
    hostIds = rows.filter((r) => allowed.has(platformCategory(r.os_platform))).map((r) => r.host_identifier);
  }

  return hostIds;
}

/**
 * Applies one policy to every currently-connected host in its resolved target
 * set. Fire-and-forget per host, since dispatchToAgent never waits for an ack.
 * Never throws: a per-host or per-command dispatch failure is logged and the
 * remaining hosts still run.
 */
export async function applyPolicyToConnectedTargets(
  policy: Policy,
  dispatch: AgentDispatchFn,
  isConnected: IsHostConnectedFn,
): Promise<void> {
  try {
    const targetHosts = await resolvePolicyTargetHosts(policy);
    const onlineHosts = targetHosts.filter(isConnected);
    if (onlineHosts.length === 0) return;

    const db = getFleetDb();
    const platformRows: { host_identifier: string; os_platform: string | null }[] = db
      ? await db.query('SELECT host_identifier, os_platform FROM nodes WHERE host_identifier = ANY($1)', [onlineHosts])
      : [];
    const platformByHost = new Map(platformRows.map((r) => [r.host_identifier, r.os_platform]));

    let dispatchedCount = 0;
    for (const hostId of onlineHosts) {
      const commands = buildAgentCommands(policy, platformByHost.get(hostId) ?? null);
      for (const cmd of commands) {
        const result = dispatch(hostId, cmd);
        if (result.dispatched) dispatchedCount++;
        else logger.warn({ policyId: policy.id, hostId, error: result.error }, 'Policy command dispatch failed');
      }
    }
    logger.info({ policyId: policy.id, hostCount: onlineHosts.length, dispatchedCount }, 'Policy applied to connected targets');
  } catch (err) {
    logger.error({ err, policyId: policy.id }, 'Failed to apply policy to connected targets');
  }
}

/**
 * Reconnect-time and reconciliation-sweep counterpart: finds every enabled
 * policy targeting this one host and re-applies each. Uses a single indexed
 * query against policies and nodes rather than resolvePolicyTargetHosts per
 * policy, because this runs once per connecting or swept host.
 */
export async function reapplyEnabledPoliciesForHost(hostIdentifier: string, dispatch: AgentDispatchFn): Promise<void> {
  try {
    const db = getFleetDb();
    if (!db) return;

    const nodeRows: { os_platform: string | null }[] = await db.query(
      'SELECT os_platform FROM nodes WHERE host_identifier = $1 LIMIT 1',
      [hostIdentifier],
    );
    if (nodeRows.length === 0) return; // unknown host — nothing to apply
    const hostOsPlatform = nodeRows[0].os_platform;

    const repo = db.getRepository(Policy);
    const candidates = await repo
      .createQueryBuilder('p')
      .where('p.enabled = true')
      .andWhere(
        `(p.target_mode = 'all'
           OR (p.target_mode IN ('nodes', 'mixed') AND :hostId = ANY(p.target_node_ids))
           OR (p.target_mode IN ('groups', 'mixed') AND EXISTS (
                 SELECT 1 FROM nodes n WHERE n.host_identifier = :hostId AND n.owner_group_id = ANY(p.target_group_ids)
               ))
        )`,
        { hostId: hostIdentifier },
      )
      .getMany();

    const category = platformCategory(hostOsPlatform);
    const applicable = candidates.filter(
      (p) => !p.platforms?.length || p.platforms.some((pl) => pl.toLowerCase() === category),
    );
    if (applicable.length === 0) return;

    let dispatchedCount = 0;
    for (const policy of applicable) {
      const commands = buildAgentCommands(policy, hostOsPlatform);
      for (const cmd of commands) {
        const result = dispatch(hostIdentifier, cmd);
        if (result.dispatched) dispatchedCount++;
        else logger.warn({ policyId: policy.id, hostIdentifier, error: result.error }, 'Policy reapply dispatch failed');
      }
    }
    logger.info({ hostIdentifier, policyCount: applicable.length, dispatchedCount }, 'Reapplied enabled policies for host');
  } catch (err) {
    // Log the failure's identity, not the whole error graph. This runs per
    // connected host on every reconciliation sweep, so a persistent failure (e.g.
    // schema drift invalidating the policies query) would otherwise write a full
    // QueryFailedError — stack, SQL, bound parameters and a nested duplicate
    // stack — per host per tick, enough to dominate log output and block the
    // event loop on writes. Code plus message identifies the fault, and the
    // Postgres log still records the statement.
    const cause = err as { code?: string; message?: string };
    logger.error(
      { hostIdentifier, errCode: cause?.code, errMessage: cause?.message },
      'Failed to reapply enabled policies for host',
    );
  }
}
