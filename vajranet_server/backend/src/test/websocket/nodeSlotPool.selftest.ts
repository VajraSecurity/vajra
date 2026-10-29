/**
 * Executable regression harness for the nodeUi/nodeExt slot pool in
 * websocket/node.ts.
 *
 *   node_modules/.bin/ts-node -T src/test/websocket/nodeSlotPool.selftest.ts
 *
 * The real module is loaded (not a reimplementation); only its I/O-bound
 * dependencies (primary/fleet DB, Redis, session resolution, node scope,
 * audit trail, sibling websocket modules) are replaced with in-process
 * fakes via a Module._load hook installed before the require below.
 *
 * These tests pin CURRENT behaviour. Each one that covers a fixed bug is
 * marked FIX: and is expected to FAIL when the harness is pointed at the
 * pre-fix file (see VAJRA_NODE_MODULE).
 */

import assert from 'assert';
import * as path from 'path';

// ─── Fake Redis ──────────────────────────────────────────────────────────────

class FakeRedis {
  store = new Map<string, string>();
  async get(k: string) { return this.store.has(k) ? this.store.get(k)! : null; }
  async set(k: string, v: string, _o?: unknown) { this.store.set(k, v); return 'OK'; }
  async del(k: string) { return this.store.delete(k) ? 1 : 0; }
  async expire(k: string, _s: number) { return this.store.has(k) ? 1 : 0; }
}

const REDIS: FakeRedis | null = process.env.VAJRA_FAKE_REDIS ? new FakeRedis() : null;

// ─── Controllable session resolution ─────────────────────────────────────────

type Session = { jwt: any; effectiveRole: string; scope: any };
const UNRESTRICTED: Session = {
  jwt: { id: 1, email: 'sa@x.com', role: 'Super Administrator' },
  effectiveRole: 'Super Administrator',
  scope: { unrestricted: true },
};

/** When set, resolveNodeUiWsSession returns this promise instead of resolving now. */
let sessionGate: Promise<Session | null> | null = null;
const sessionFor: (req: any) => Session | null = () => UNRESTRICTED;

// ─── Module stubs ────────────────────────────────────────────────────────────

const noopLogger = {
  trace: () => {}, debug: () => {}, info: () => {},
  warn: () => {}, error: () => {}, fatal: () => {}, child: () => noopLogger,
};

const STUBS: Record<string, any> = {
  '/src/index.ts': { dbSourceConnection: () => null },
  '/src/utils/redisClient.ts': { getRedisClient: () => REDIS },
  '/src/utils/logger.ts': { getLogger: () => noopLogger },
  '/src/utils/wsAuth.ts': {
    getWsJwtPayload: async () => UNRESTRICTED.jwt,
    resolveNodeUiWsSession: async (req: any) => {
      if (sessionGate) return sessionGate;
      return sessionFor(req);
    },
  },
  '/src/utils/nodeScope.ts': {
    scopeGroupIds: (s: any) => (s.unrestricted ? [] : s.groups.map((g: any) => g.id)),
    actableGroupIds: (s: any) => (s.unrestricted ? [] : s.groups.map((g: any) => g.id)),
    canActOnGroup: () => true,
    assertHostInScope: async () => true,
    assertCanActOnHost: async () => true,
  },
  '/src/utils/auditTrailLogger.ts': { logAuditTrail: async () => {} },
  '/src/websocket/liveWeb.ts': { broadcastToLiveClients: () => {} },
  '/src/websocket/nodeStatusEvents.ts': { emitNodeStatusChange: () => {} },
  '/src/websocket/patchDispatch.ts': {
    dispatchPendingPatchCommands: async () => {},
    dispatchNextPendingPatchCommand: async () => {},
  },
  '/src/controllers/nodes/patch_management.ts': {
    createPatchJob: async () => null,
    findHostsInFlight: async () => [],
  },
  '/src/services/policyEnforcement.ts': { reapplyEnabledPoliciesForHost: async () => {} },
};

const Mod: any = require('module');
const origLoad = Mod._load;
Mod._load = function (this: unknown, ...args: any[]) {
  const [request, parent, isMain] = args as [string, any, boolean];
  let resolved: string;
  try { resolved = Mod._resolveFilename(request, parent, isMain); }
  catch { return origLoad.apply(this, args); }
  const norm = resolved.split(path.sep).join('/');
  for (const key of Object.keys(STUBS)) if (norm.endsWith(key)) return STUBS[key];
  return origLoad.apply(this, args);
};

// Which implementation to exercise: current (default) or a pre-fix copy.
const TARGET = process.env.VAJRA_NODE_MODULE || '../../websocket/node';
const nodeMod = require(TARGET);
const { nodeUi, nodeExt, ridCleanupInterval, jobDrainInterval } = nodeMod;

// ─── Fake WebSocket ──────────────────────────────────────────────────────────

let wsSeq = 0;
class FakeWs {
  name = `ws${++wsSeq}`;
  sent: string[] = [];
  handlers = new Map<string, ((...a: any[]) => any)[]>();
  closed: { code?: number; reason?: string } | null = null;
  failSend = false;
  bufferedAmount = 0;
  on(e: string, fn: (...a: any[]) => any) {
    if (!this.handlers.has(e)) this.handlers.set(e, []);
    this.handlers.get(e)!.push(fn);
  }
  send(d: string) { if (this.failSend) throw new Error('EPIPE (simulated dead socket)'); this.sent.push(d); }
  close(code?: number, reason?: string) { this.closed = { code, reason }; }
  async emit(e: string, ...args: any[]) {
    for (const fn of this.handlers.get(e) || []) await fn(...args);
  }
  /** Parsed frames that are agent responses (have a rid), ignoring error frames. */
  rids(): string[] {
    return this.sent
      .map((s) => { try { return JSON.parse(s); } catch { return null; } })
      .filter((o) => o && typeof o.rid === 'string')
      .map((o) => o.rid);
  }
}

const REQ = { headers: { cookie: 'x' } } as any;
const extReq = (hostId: string) => ({ headers: { 'agent-info': JSON.stringify({ host_identifier: hostId }) } }) as any;

function connectUi(): FakeWs { const ws = new FakeWs(); nodeUi(ws as any, REQ); return ws; }
function connectExt(hostId: string): FakeWs { const ws = new FakeWs(); nodeExt(ws as any, extReq(hostId)); return ws; }

const uiSend = (ws: FakeWs, msg: any) => ws.emit('message', JSON.stringify(msg));
const extSend = (ws: FakeWs, msg: any) => ws.emit('message', JSON.stringify(msg));
const tick = () => new Promise((r) => setImmediate(r));

// ─── Tests ───────────────────────────────────────────────────────────────────

const results: { name: string; ok: boolean; err?: string }[] = [];
async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); results.push({ name, ok: true }); }
  catch (e: any) { results.push({ name, ok: false, err: e?.message || String(e) }); }
}

const HOST = 'host-A';
const cmd = (rid: string) => ({
  host_identifier: HOST, type: 'agent', rid,
  params: { agent: 'networkManager', action: 'status' },
});

async function main() {
  // ── 1. Baseline: normal request/response round-trip is delivered ──────────
  await test('baseline: agent response is routed back to the requesting UI client', async () => {
    const ext = connectExt(HOST);
    const ui = connectUi();
    await tick();
    await uiSend(ui, cmd('R-base'));
    assert.strictEqual(ext.sent.length, 1, 'command must be forwarded to the agent');
    assert.strictEqual(JSON.parse(ext.sent[0]).rid, 'R-base');
    await extSend(ext, { rid: 'R-base', response: 'ok' });
    assert.deepStrictEqual(ui.rids(), ['R-base'], 'UI must receive exactly its own response');
    await ui.emit('close'); await ext.emit('close');
  });

  // ── 2. Ordering / no loss / no duplication over a burst ───────────────────
  await test('burst: N responses delivered exactly once, in agent send order', async () => {
    const ext = connectExt(HOST);
    const ui = connectUi();
    await tick();
    const rids = Array.from({ length: 25 }, (_, i) => `R-burst-${i}`);
    for (const r of rids) await uiSend(ui, cmd(r));
    assert.strictEqual(ext.sent.length, 25, 'every command forwarded');
    for (const r of rids) await extSend(ext, { rid: r, response: 'ok' });
    assert.deepStrictEqual(ui.rids(), rids, 'all responses, same order, no dupes, none dropped');
    await ui.emit('close'); await ext.emit('close');
  });

  // ── 3. FIX: double-free via failed ext→UI delivery ────────────────────────
  // Pre-fix, the ext→UI delivery path nulled CLIENTS[slot] and pushed the slot
  // onto clientFreeList WITHOUT removing the socket from wsToClientIndex, so
  // the socket's later 'close' pushed the SAME slot a second time. Two later
  // browser clients were then handed one slot and rid routing delivered one
  // user's agent response to the other.
  await test('FIX double-free: a slot freed by failed delivery + later close is not handed to two clients', async () => {
    const ext = connectExt(HOST);
    const victim = connectUi();
    await tick();
    await uiSend(victim, cmd('R-dead'));

    victim.failSend = true;                       // socket dies unnoticed
    await extSend(ext, { rid: 'R-dead', response: 'ok' });  // delivery fails -> slot freed
    await victim.emit('close');                   // the real close arrives later

    const b = connectUi();
    const c = connectUi();
    await tick();

    await uiSend(b, cmd('R-b'));
    await extSend(ext, { rid: 'R-b', response: 'for-b' });

    assert.deepStrictEqual(b.rids(), ['R-b'], 'client B must receive its own response');
    assert.deepStrictEqual(c.rids(), [], 'client C must NOT receive client B\'s agent response');
    await b.emit('close'); await c.emit('close'); await ext.emit('close');
  });

  // ── 4. FIX: rid registration race guard ───────────────────────────────────
  // The handler awaits session resolution before registering rid -> slot. If
  // the socket closes during that await the slot returns to the LIFO free list
  // and the next client gets it; registering the rid afterwards would route
  // this user's agent response to that new client.
  await test('FIX rid race: rid registered after the socket closed must not route to the slot\'s new owner', async () => {
    const ext = connectExt(HOST);
    const victim = connectUi();
    await tick();

    let release!: (s: Session) => void;
    sessionGate = new Promise<Session | null>((res) => { release = res as any; });

    const inflight = uiSend(victim, cmd('R-race'));   // blocks inside the await
    await tick();
    await victim.emit('close');                       // slot returned to free list
    const successor = connectUi();                    // LIFO -> takes the same slot
    await tick();

    release(UNRESTRICTED);
    sessionGate = null;
    await inflight;

    await extSend(ext, { rid: 'R-race', response: 'secret-for-victim' });

    assert.deepStrictEqual(
      successor.rids(), [],
      'the successor on the recycled slot must NOT receive the departed client\'s agent response',
    );
    await successor.emit('close'); await ext.emit('close');
  });

  // ── 5. The guard must not skip legitimate work ────────────────────────────
  // Documented intent: the guard suppresses only the rid/scope WRITE, never the
  // dispatch. A command from a client that disconnects mid-flight must still
  // reach the agent (behaviour preserved from before the fix).
  await test('guard scope: a command from a mid-flight-disconnected client still reaches the agent', async () => {
    const ext = connectExt(HOST);
    const ui = connectUi();
    await tick();
    const before = ext.sent.length;

    let release!: (s: Session) => void;
    sessionGate = new Promise<Session | null>((res) => { release = res as any; });
    const inflight = uiSend(ui, cmd('R-still-dispatch'));
    await tick();
    await ui.emit('close');
    release(UNRESTRICTED);
    sessionGate = null;
    await inflight;

    assert.strictEqual(ext.sent.length, before + 1, 'the agent command must still be dispatched');
    assert.strictEqual(JSON.parse(ext.sent[before]).rid, 'R-still-dispatch');
    await ext.emit('close');
  });

  // ── 6. The guard must not fire on the normal path ─────────────────────────
  await test('guard scope: normal (non-racing) requests are never skipped', async () => {
    const ext = connectExt(HOST);
    const ui = connectUi();
    await tick();
    for (let i = 0; i < 10; i++) {
      await uiSend(ui, cmd(`R-normal-${i}`));
      await extSend(ext, { rid: `R-normal-${i}`, response: 'ok' });
    }
    assert.strictEqual(ui.rids().length, 10, 'every normal request must be answered');
    await ui.emit('close'); await ext.emit('close');
  });

  // ── 7. releaseClientSlot sweeps in-flight rids on close ───────────────────
  await test('close sweep: an in-flight rid does not route to the next owner of the slot', async () => {
    const ext = connectExt(HOST);
    const a = connectUi();
    await tick();
    await uiSend(a, cmd('R-inflight'));   // registered against A's slot
    await a.emit('close');                // slot freed; rid must be swept
    const b = connectUi();
    await tick();
    await extSend(ext, { rid: 'R-inflight', response: 'for-a' });
    assert.deepStrictEqual(b.rids(), [], 'B must not inherit A\'s in-flight response');
    await b.emit('close'); await ext.emit('close');
  });

  // ── 8. Agent-not-connected still answers the UI immediately ───────────────
  await test('no agent: UI gets an immediate error frame, rid preserved', async () => {
    const ui = connectUi();
    await tick();
    await uiSend(ui, { host_identifier: 'ghost-host', type: 'agent', rid: 'R-ghost', params: { agent: 'a', action: 'status' } });
    assert.strictEqual(ui.sent.length, 1);
    const f = JSON.parse(ui.sent[0]);
    assert.strictEqual(f.error, 'Agent not connected');
    assert.strictEqual(f.rid, 'R-ghost');
    await ui.emit('close');
  });

  // ── 9b. A slot pruned by a failed PUSH also closes that socket ──
  // The push-broadcast prune frees the slot AND closes the socket. Previously
  // it only freed the slot, so a client whose send threw once stayed connected
  // while owning no slot: its later commands still reached the agent (the rid
  // guard suppresses only the routing write) but no response could ever be
  // routed back, and the tab had no onclose to trigger its reconnect/backoff --
  // every request just burned its full timeout instead. Closing makes the
  // failure observable to the client. Note the response is still not routed
  // back (dropping beats the pre-fix misroute to whichever client inherited the
  // slot), and the free-then-close ordering is the double-free case covered
  // above.
  await test('a client pruned by a failed push still dispatches, receives no response, and is closed', async () => {
    const ext = connectExt(HOST);
    const ui = connectUi();
    await tick();

    ui.failSend = true;
    await extSend(ext, { rid: 'clamav_push', response: 'x' }); // prune frees ui's slot
    ui.failSend = false;
    ui.sent.length = 0;

    const before = ext.sent.length;
    await uiSend(ui, cmd('R-orphan'));
    assert.strictEqual(ext.sent.length, before + 1, 'command still reaches the agent');

    await extSend(ext, { rid: 'R-orphan', response: 'ok' });
    assert.deepStrictEqual(ui.rids(), [], 'but no response is routed back to the pruned socket');
    assert.strictEqual(ui.closed?.code, 1011, 'and the socket is closed so the client can reconnect');

    await ui.emit('close'); await ext.emit('close');
  });

  // ── 9. Slot is actually reused (pool does not leak) ───────────────────────
  await test('pool: connect/disconnect churn does not exhaust or leak slots', async () => {
    const ext = connectExt(HOST);
    for (let i = 0; i < 200; i++) {
      const ui = connectUi();
      await tick();
      await uiSend(ui, cmd(`R-churn-${i}`));
      await extSend(ext, { rid: `R-churn-${i}`, response: 'ok' });
      assert.strictEqual(ui.rids().length, 1, `churn iteration ${i} must be answered`);
      assert.strictEqual(ui.closed, null, `churn iteration ${i} must not be rejected for capacity`);
      await ui.emit('close');
    }
    await ext.emit('close');
  });
}

main().then(() => {
  clearInterval(ridCleanupInterval);
  clearInterval(jobDrainInterval);
  const label = process.env.VAJRA_LABEL || 'current';
  const redisLabel = REDIS ? 'redis=fake' : 'redis=null';
  let failed = 0;
  for (const r of results) {
    if (!r.ok) failed++;
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  [${label} ${redisLabel}]  ${r.name}${r.ok ? '' : `\n        -> ${r.err}`}`);
  }
  console.log(`\n${results.length - failed}/${results.length} passed  [${label} ${redisLabel}]`);
  process.exit(failed > 0 ? 1 : 0);
});
