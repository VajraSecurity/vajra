/**
 * Verification harness (TEAM 1): proves that narrowing listBurpsuiteScans' repo.find()
 * to an explicit column list cannot null the omitted results_json / metrics_json columns
 * when repo.save() runs afterwards. Runs against a local throwaway DB only.
 */
import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { SnakeNamingStrategy } from 'typeorm-naming-strategies';
import { BurpsuiteScanHistory } from '../orm/entities/fleet/BurpsuiteScanHistory';

const SELECT = {
  id: true, taskId: true, target: true, status: true,
  issuesTotal: true, issuesHigh: true, issuesMedium: true, issuesLow: true,
} as const;

async function main() {
  const statements: string[] = [];
  const ds = new DataSource({
    type: 'postgres',
    host: '/var/run/postgresql',
    username: process.env.USER,
    database: 'zz_typeorm_verify',
    entities: [BurpsuiteScanHistory],
    namingStrategy: new SnakeNamingStrategy(),
    synchronize: true,
    logging: ['query'],
    logger: {
      logQuery: (q: string) => { statements.push(q); },
      logQueryError: () => {}, logQuerySlow: () => {}, logSchemaBuild: () => {},
      logMigration: () => {}, log: () => {},
    } as any,
  });
  await ds.initialize();
  const repo = ds.getRepository(BurpsuiteScanHistory);
  await repo.clear();

  const BIG = JSON.stringify(Array.from({ length: 20000 }, (_, i) => ({ i, issue: { severity: 'high' } })));
  const METRICS = JSON.stringify({ crawl: 'done', audit: 'done' });

  let failures = 0;
  const check = (name: string, ok: boolean, detail = '') => {
    console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail ? ' :: ' + detail : ''));
    if (!ok) failures++;
  };

  const scenarios = ['no-issue_events', 'empty-issue_events', 'populated-issue_events'] as const;
  for (const scenario of scenarios) {
    await repo.clear();
    const seeded = await repo.save(repo.create({
      taskId: 't-' + scenario, target: 'http://example.test', status: 'running',
      issuesTotal: 1, issuesHigh: 1, issuesMedium: 0, issuesLow: 0,
      resultsJson: BIG, metricsJson: METRICS,
    }));

    // Exactly what the NEW controller does.
    const scans = await repo.find({ select: SELECT as any, order: { created_at: 'DESC' }, take: 50 });
    const scan = scans[0];
    check('[' + scenario + '] omitted cols are undefined (not null) after partial find',
      scan.resultsJson === undefined && scan.metricsJson === undefined,
      'resultsJson=' + String(scan.resultsJson) + ' metricsJson=' + String(scan.metricsJson));

    // Simulate the refresh path in the controller.
    const issueEvents: any[] = scenario === 'populated-issue_events'
      ? [{ issue: { severity: 'high' } }, { issue: { severity: 'low' } }]
      : [];
    const scanMetrics: any = scenario === 'no-issue_events' ? null : { crawl: 'x' };

    let high = 0, medium = 0, low = 0;
    issueEvents.forEach((e: any) => {
      const sev = (e.issue?.severity || '').toLowerCase();
      if (sev === 'high') high++; else if (sev === 'medium') medium++; else if (sev === 'low') low++;
    });
    scan.status = 'succeeded';
    scan.issuesHigh = high; scan.issuesMedium = medium; scan.issuesLow = low;
    scan.issuesTotal = high + medium + low;
    if (issueEvents.length > 0) scan.resultsJson = JSON.stringify(issueEvents);
    if (scanMetrics) scan.metricsJson = JSON.stringify(scanMetrics);

    statements.length = 0;
    await repo.save(scan);
    const updates = statements.filter((q) => /^\s*UPDATE/i.test(q));
    const reloads = statements.filter((q) => /^\s*SELECT/i.test(q));
    const emitted = updates.join(' ;; ');

    const raw = await ds.query(
      'SELECT results_json, metrics_json, status, issues_total FROM burpsuite_scan_history WHERE id = $1',
      [seeded.id],
    );
    const row = raw[0];

    if (issueEvents.length > 0) {
      check('[' + scenario + '] results_json overwritten as intended',
        row.results_json === JSON.stringify(issueEvents));
    } else {
      check('[' + scenario + '] results_json PRESERVED (not nulled)',
        row.results_json === BIG,
        row.results_json === null ? 'GOT NULL' : 'len=' + String(row.results_json && row.results_json.length));
      check('[' + scenario + '] UPDATE does not mention results_json',
        updates.length > 0 && !/results_json/i.test(emitted), emitted.slice(0, 250));
      check('[' + scenario + '] (info) save() reload SELECT refetches results_json',
        true, 'reloadSelects=' + reloads.length + ' refetchesResultsJson=' + String(/results_json/i.test(reloads.join(' '))));
    }
    if (scanMetrics) {
      check('[' + scenario + '] metrics_json overwritten as intended', row.metrics_json === JSON.stringify(scanMetrics));
    } else {
      check('[' + scenario + '] metrics_json PRESERVED (not nulled)', row.metrics_json === METRICS,
        row.metrics_json === null ? 'GOT NULL' : 'ok');
    }
    check('[' + scenario + '] status/counts written',
      row.status === 'succeeded' && Number(row.issues_total) === high + medium + low);
  }

  // Byte-identical response mapping: full-select vs narrowed-select.
  await repo.clear();
  for (let i = 0; i < 5; i++) {
    await repo.save(repo.create({
      taskId: 'task-' + i, target: 'http://t' + i + '.test', status: i % 2 ? 'succeeded' : 'failed',
      issuesTotal: i, issuesHigh: i, issuesMedium: 0, issuesLow: 0,
      resultsJson: BIG, metricsJson: METRICS,
    }));
  }
  const mapper = (s: BurpsuiteScanHistory) => ({
    id: s.id, target: s.target, status: s.status,
    issue_counts: { total: s.issuesTotal, high: s.issuesHigh, medium: s.issuesMedium, low: s.issuesLow },
  });
  const oldWay = (await repo.find({ order: { created_at: 'DESC' }, take: 50 })).map(mapper);
  const newWay = (await repo.find({ select: SELECT as any, order: { created_at: 'DESC' }, take: 50 })).map(mapper);
  check('response JSON byte-identical (SELECT * vs narrowed)',
    JSON.stringify({ success: true, data: { scans: oldWay } }) === JSON.stringify({ success: true, data: { scans: newWay } }),
    JSON.stringify(newWay).slice(0, 200));

  await ds.destroy();
  console.log(failures === 0 ? 'ALL CHECKS PASSED' : String(failures) + ' CHECK(S) FAILED');
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(2); });
