import { ChartJSNodeCanvas } from 'chartjs-node-canvas';
import { getLogger } from '../utils/logger';

const logger = getLogger('controllers.generateCharts');

type HistPt = { label: string; score: number };

// Renderer reuse. A ChartJSNodeCanvas is expensive to construct: its constructor
// freshRequire()s node-canvas and its initialize() does `require('chart.js/auto')`
// and then deletes every chart.js key out of require.cache, so every `new`
// re-evaluates the whole Chart.js bundle and owns a private copy of it — more
// synchronous CPU than the render itself. On a single-process server with no
// clustering or worker threads, that time also stalls agent check-ins and the
// WebSocket layer, so instances are cached per canvas size instead.
//
// Reuse is safe because an instance carries no render-scoped mutable state:
// - width/height/type and the canvas factory are fixed at construction, which is
//   exactly what the cache key pins, and
// - renderChart() allocates a *fresh* canvas per call and calls chart.destroy()
//   when the data URL is produced, so nothing survives between renders, and
// - the only plugin ever registered is chartjs-node-canvas's own
//   BackgroundColourPlugin, registered once at construction against that
//   instance's private Chart.js copy and parameterised by the *same* width/
//   height/colour the key encodes. It is stateless per draw (it just fills the
//   instance's w×h rect). We pass no chartCallback and no `plugins` option, so
//   there is nothing else instance-local to leak.
// Two same-size charts rendered concurrently via Promise.all therefore share one
// Chart.js copy but get independent Chart objects on independent canvases —
// the ordinary "several charts on one page" case.
//
// Every call site passes backgroundColour:'white', so it is baked in here rather
// than made part of the key.
const canvasCache = new Map<string, ChartJSNodeCanvas>();

// This module's call sites use eight fixed canvas sizes, plus one variable-size
// chart (control_bars) whose height is bounded by the largest framework's
// guideline count. The cap is a safety valve so an unforeseen caller cannot grow
// the cache into a leak: once it is full, canvasFor() just builds a throwaway
// instance per call.
const CANVAS_CACHE_MAX = 64;

function canvasFor(width: number, height: number): ChartJSNodeCanvas {
  const key = `${width}x${height}`;
  const cached = canvasCache.get(key);
  if (cached) return cached;
  const created = new ChartJSNodeCanvas({ width, height, backgroundColour: 'white' });
  if (canvasCache.size < CANVAS_CACHE_MAX) canvasCache.set(key, created);
  return created;
}

/** Brand color for each compliance framework, shared by every chart/report renderer that shows all four side by side. */
export const FRAMEWORK_COLORS = {
  sebi: '#1a4f8a',
  irdai: '#6a1b9a',
  certin: '#00695c',
  vajra: '#8F407F',
} as const;

/** Fixed green/red pair used throughout report charts for a pass-vs-fail (or compliant-vs-not) split. */
export const STATUS_COLOR_PASS = '#136f63';
export const STATUS_COLOR_FAIL = '#ab3428';

// Report generation (reports.ts) renders many of these concurrently via
// Promise.all — without per-chart context here, a canvas/font rendering
// failure would surface only as an opaque "Failed to generate report" at the
// caller, with no way to tell which specific chart triggered it.
async function donut(
  labels: string[], data: number[], colors: string[], title: string,
  w = 440, h = 300,
): Promise<string> {
  const c = canvasFor(w, h);
  try {
    return await c.renderToDataURL({
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: '#fff' }] },
      options: {
        cutout: '55%',
        plugins: {
          legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 10 } },
          title: { display: true, text: title, font: { size: 12 }, padding: { bottom: 8 } },
        },
      } as any,
    });
  } catch (err) {
    logger.error({ err, chart: 'donut', title }, 'Failed to render chart');
    throw err;
  }
}

export async function generateFrameworkCharts(
  snapshot: any,
  controls: any[] = [],
  _color: string = FRAMEWORK_COLORS.vajra,
): Promise<Record<string, string | undefined>> {
  const compliant    = snapshot.fully_compliant_nodes ?? 0;
  const total        = snapshot.windows_with_results ?? 0;
  const nonCompliant = Math.max(0, total - compliant);

  const sorted = controls.filter(c => c.passRatePct != null).sort((a, b) => a.passRatePct - b.passRatePct);

  // The charts below are kicked off together and joined at the bottom rather than
  // awaited one at a time. They share no data — each only reads
  // `snapshot`/`controls`/`sorted`, all computed synchronously above — and
  // node-canvas's callback form of toDataURL() does the PNG encode on the libuv
  // threadpool, not the event loop, so running them concurrently shortens the
  // request and hands the loop back sooner. reports.ts renders its org-report
  // charts the same way.
  //
  // Each promise keeps its own .catch so the per-chart context survives in the
  // log. Promise.all still rejects with the first error, and every promise has a
  // handler attached, so there are no unhandled rejections.

  // 1. Endpoint compliance donut
  const coverage_donut_p = donut(
    ['Fully Compliant', 'Not Fully Compliant'],
    [compliant, nonCompliant],
    [STATUS_COLOR_PASS, STATUS_COLOR_FAIL],
    'Endpoint Compliance Distribution',
    460, 320,
  );

  // 2. Stacked bar: passing vs failing host counts for non-100% controls only
  let control_bars_p: Promise<string | undefined> = Promise.resolve(undefined);
  const nonPerfect = sorted.filter(c => c.passRatePct < 100 && c.eligibleHosts > 0);
  if (nonPerfect.length > 0) {
    const h = Math.max(300, nonPerfect.length * 30 + 130);
    const bc = canvasFor(680, h);
    control_bars_p = bc.renderToDataURL({
      type: 'bar',
      data: {
        labels: nonPerfect.map(c => `#${c.key}`),
        datasets: [
          {
            label: 'Passing Hosts',
            data: nonPerfect.map(c => c.passHosts),
            backgroundColor: 'rgba(19,111,99,0.82)',
            borderWidth: 0, borderRadius: 3, barThickness: 22,
          },
          {
            label: 'Failing Hosts',
            data: nonPerfect.map(c => c.eligibleHosts - c.passHosts),
            backgroundColor: 'rgba(171,52,40,0.82)',
            borderWidth: 0, borderRadius: 3, barThickness: 22,
          },
        ],
      },
      options: {
        indexAxis: 'y' as const,
        responsive: false,
        plugins: {
          legend: { position: 'bottom', labels: { font: { size: 10 }, padding: 10 } },
          title: { display: true, text: 'Partially Compliant Controls — Pass vs. Fail Host Count', font: { size: 12 }, padding: { bottom: 14 } },
        },
        scales: {
          x: { stacked: true, grid: { color: '#efefef' }, ticks: { stepSize: 1, font: { size: 10 } }, title: { display: true, text: 'Number of Hosts', font: { size: 10 } } },
          y: { stacked: true, grid: { display: false }, ticks: { font: { size: 10 } } },
        },
      } as any,
    }).catch((err) => {
      logger.error({ err, chart: 'control_bars' }, 'Failed to render chart');
      throw err;
    });
  }

  // 3. Control health breakdown pie (green / amber / red)
  let health_pie_p: Promise<string | undefined> = Promise.resolve(undefined);
  if (sorted.length > 0) {
    const g  = sorted.filter(c => c.passRatePct >= 90).length;
    const am = sorted.filter(c => c.passRatePct >= 75 && c.passRatePct < 90).length;
    const r  = sorted.filter(c => c.passRatePct < 75).length;
    const na = controls.filter(c => c.passRatePct == null).length;
    const parts: Array<{ l: string; v: number; col: string }> = [];
    if (g  > 0) parts.push({ l: `≥90%  Good (${g})`,   v: g,  col: STATUS_COLOR_PASS });
    if (am > 0) parts.push({ l: `75–89%  Fair (${am})`, v: am, col: '#ca8a04' });
    if (r  > 0) parts.push({ l: `<75%  At Risk (${r})`, v: r,  col: STATUS_COLOR_FAIL });
    if (na > 0) parts.push({ l: `N/A (${na})`,          v: na, col: '#9ca3af' });
    if (parts.length > 0) {
      health_pie_p = donut(
        parts.map(p => p.l), parts.map(p => p.v), parts.map(p => p.col),
        'Control Health Breakdown',
      );
    }
  }

  // 4. Node compliance tier donut (Strong / Moderate / Needs Attention)
  let node_tiers_p: Promise<string | undefined> = Promise.resolve(undefined);
  {
    const strong   = snapshot.strong_count          ?? 0;
    const moderate = snapshot.moderate_count         ?? 0;
    const needsAttn = snapshot.needs_attention_count ?? 0;
    if (strong + moderate + needsAttn > 0) {
      const parts: Array<{ l: string; v: number; col: string }> = [];
      if (strong    > 0) parts.push({ l: `Strong ≥80% (${strong})`,          v: strong,    col: STATUS_COLOR_PASS });
      if (moderate  > 0) parts.push({ l: `Moderate 60–79% (${moderate})`,    v: moderate,  col: '#ca8a04' });
      if (needsAttn > 0) parts.push({ l: `Needs Attention <60% (${needsAttn})`, v: needsAttn, col: STATUS_COLOR_FAIL });
      if (parts.length > 0) {
        node_tiers_p = donut(
          parts.map(p => p.l), parts.map(p => p.v), parts.map(p => p.col),
          'Node Compliance Tier Distribution', 460, 320,
        );
      }
    }
  }

  // 5. Pass rate distribution histogram
  let rate_histogram_p: Promise<string | undefined> = Promise.resolve(undefined);
  if (sorted.length > 0) {
    const buckets = [0, 0, 0, 0, 0];
    for (const c of sorted) {
      const p = c.passRatePct;
      if (p < 20) buckets[0]++;
      else if (p < 40) buckets[1]++;
      else if (p < 60) buckets[2]++;
      else if (p < 80) buckets[3]++;
      else buckets[4]++;
    }
    const hc = canvasFor(580, 280);
    rate_histogram_p = hc.renderToDataURL({
      type: 'bar',
      data: {
        labels: ['0–19%', '20–39%', '40–59%', '60–79%', '80–100%'],
        datasets: [{
          data: buckets,
          backgroundColor: ['rgba(171,52,40,0.82)', 'rgba(171,52,40,0.7)', 'rgba(202,138,4,0.82)', 'rgba(202,138,4,0.7)', 'rgba(19,111,99,0.82)'],
          borderWidth: 0, borderRadius: 5,
        }],
      },
      options: {
        responsive: false,
        plugins: {
          legend: { display: false },
          title: { display: true, text: 'Control Pass Rate Distribution', font: { size: 11 }, padding: { bottom: 8 } },
        },
        scales: {
          y: {
            ticks: { stepSize: 1, font: { size: 10 } }, grid: { color: '#efefef' },
            title: { display: true, text: 'Controls', font: { size: 10 } },
          },
          x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        },
      } as any,
    }).catch((err) => {
      logger.error({ err, chart: 'rate_histogram' }, 'Failed to render chart');
      throw err;
    });
  }

  const [coverage_donut, control_bars, health_pie, node_tiers, rate_histogram] = await Promise.all([
    coverage_donut_p, control_bars_p, health_pie_p, node_tiers_p, rate_histogram_p,
  ]);

  return { coverage_donut, control_bars, health_pie, node_tiers, rate_histogram };
}

export async function generateHistoryLine(
  history: HistPt[],
  frameworkName: string,
  color: string,
): Promise<string | undefined> {
  if (history.length < 2) return undefined;
  const c = canvasFor(700, 280);
  try {
    return await c.renderToDataURL({
      type: 'line',
      data: {
        labels: history.map(h => h.label),
        datasets: [{
          label: 'Compliant %',
          data: history.map(h => h.score),
          borderColor: color,
          backgroundColor: color + '22',
          borderWidth: 2.5,
          pointRadius: 4,
          pointBackgroundColor: color,
          fill: true,
          tension: 0.35,
        }],
      },
      options: {
        responsive: false,
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: `${frameworkName} — Compliance Trend (last ${history.length} snapshots)`,
            font: { size: 12 }, padding: { bottom: 10 },
          },
        },
        scales: {
          y: { min: 0, max: 100, ticks: { callback: (v: any) => `${v}%`, font: { size: 11 } }, grid: { color: '#efefef' } },
          x: { grid: { color: '#efefef' }, ticks: { font: { size: 10 } } },
        },
      } as any,
    });
  } catch (err) {
    logger.error({ err, chart: 'history_line', frameworkName }, 'Failed to render chart');
    throw err;
  }
}

export async function generateOrgComparisonChart(
  frameworks: Array<{ name: string; score: number | null; color: string }>,
): Promise<string> {
  const c = canvasFor(620, 290);
  try {
    return await c.renderToDataURL({
      type: 'bar',
      data: {
        labels: frameworks.map(f => f.name),
        datasets: [{
          data: frameworks.map(f => f.score != null ? Math.round(f.score) : 0),
          backgroundColor: frameworks.map(f => f.color + 'bb'),
          borderColor: frameworks.map(f => f.color),
          borderWidth: 2, borderRadius: 6, barThickness: 48,
        }],
      },
      options: {
        responsive: false,
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: 'Framework Compliance — Fully Compliant Endpoint %',
            font: { size: 13 }, padding: { bottom: 14 },
          },
        },
        scales: {
          y: { min: 0, max: 100, grid: { color: '#efefef' }, ticks: { callback: (v: any) => `${v}%`, stepSize: 25, font: { size: 11 } } },
          x: { grid: { display: false }, ticks: { font: { size: 12 } } },
        },
      } as any,
    });
  } catch (err) {
    logger.error({ err, chart: 'org_comparison' }, 'Failed to render chart');
    throw err;
  }
}

export async function generateSimpleDonut(
  labels: string[], data: number[], colors: string[], title: string,
): Promise<string> {
  return donut(labels, data, colors, title);
}

export async function generateMultiHistoryLine(
  histories: Array<{ name: string; color: string; data: HistPt[] }>,
): Promise<string | undefined> {
  const valid = histories.filter(h => h.data.length >= 2);
  if (valid.length === 0) return undefined;
  const longest = valid.reduce((a, b) => a.data.length >= b.data.length ? a : b);
  const c = canvasFor(700, 300);
  try {
    return await c.renderToDataURL({
      type: 'line',
      data: {
        labels: longest.data.map(d => d.label),
        datasets: valid.map(h => ({
          label: h.name,
          data: h.data.map(d => d.score),
          borderColor: h.color,
          backgroundColor: 'transparent',
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: h.color,
          fill: false,
          tension: 0.35,
        })),
      },
      options: {
        responsive: false,
        plugins: {
          legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 12, boxWidth: 14 } },
          title: {
            display: true,
            text: 'Multi-Framework Compliance Trend (Fully Compliant Endpoint %)',
            font: { size: 12 }, padding: { bottom: 10 },
          },
        },
        scales: {
          y: { min: 0, max: 100, ticks: { callback: (v: any) => `${v}%`, font: { size: 11 } }, grid: { color: '#efefef' } },
          x: { grid: { color: '#efefef' }, ticks: { font: { size: 10 } } },
        },
      } as any,
    });
  } catch (err) {
    logger.error({ err, chart: 'multi_history_line' }, 'Failed to render chart');
    throw err;
  }
}

export async function generateWeeklyAlertsBar(
  days: Array<{ label: string; total: number }>,
): Promise<string> {
  const allZero = days.every(d => d.total === 0);
  const c = canvasFor(680, 280);
  try {
    return await c.renderToDataURL({
      type: 'bar',
      data: {
        labels: days.map(d => d.label),
        datasets: [{
          label: 'Alerts',
          data: days.map(d => d.total),
          backgroundColor: days.map(d => d.total > 0 ? 'rgba(171,52,40,0.78)' : 'rgba(156,163,175,0.35)'),
          borderWidth: 0,
          borderRadius: 4,
          barThickness: 52,
        }],
      },
      options: {
        responsive: false,
        plugins: {
          legend: { display: false },
          title: { display: true, text: 'Weekly Alert Volume — Last 7 Days', font: { size: 12 }, padding: { bottom: 10 } },
        },
        scales: {
          y: {
            beginAtZero: true,
            suggestedMax: allZero ? 10 : undefined,
            ticks: { stepSize: 1, font: { size: 10 } },
            grid: { color: '#efefef' },
            title: { display: true, text: 'Alerts', font: { size: 10 } },
          },
          x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        },
      } as any,
    });
  } catch (err) {
    logger.error({ err, chart: 'weekly_alerts_bar' }, 'Failed to render chart');
    throw err;
  }
}

export async function generateSebiDomainChart(
  controls: any[],
  guidelines: Record<string, { label: string; tooltip: string }>,
): Promise<string | undefined> {
  const domainMap: Record<string, number[]> = {};
  for (const c of controls) {
    if (c.passRatePct == null) continue;
    const tooltip = guidelines[c.key]?.tooltip ?? '';
    const domain  = tooltip.match(/^([A-Z]+)\./)?.[1] ?? 'Other';
    if (!domainMap[domain]) domainMap[domain] = [];
    domainMap[domain].push(c.passRatePct);
  }
  const domainLabels = Object.keys(domainMap).sort();
  if (domainLabels.length === 0) return undefined;

  const avgRates = domainLabels.map(d => {
    const vals = domainMap[d];
    return Math.round(vals.reduce((a, b) => a + b, 0) / vals.length);
  });

  const colorMap: Record<string, string> = {
    ID: 'rgba(26,79,138,0.85)',
    PR: 'rgba(19,111,99,0.85)',
    DE: 'rgba(202,138,4,0.85)',
    RS: 'rgba(171,52,40,0.85)',
  };
  const fullLabels: Record<string, string> = {
    ID: 'Identify (ID)',
    PR: 'Protect (PR)',
    DE: 'Detect (DE)',
    RS: 'Respond (RS)',
  };

  const bc = canvasFor(520, 280);
  try {
    return await bc.renderToDataURL({
      type: 'bar',
      data: {
        labels: domainLabels.map(d => fullLabels[d] ?? d),
        datasets: [{
          data: avgRates,
          backgroundColor: domainLabels.map(d => colorMap[d] ?? 'rgba(100,100,100,0.75)'),
          borderWidth: 0,
          borderRadius: 6,
          barThickness: 52,
        }],
      },
      options: {
        responsive: false,
        plugins: {
          legend: { display: false },
          title: { display: true, text: 'Avg. Pass Rate by SEBI CSF Function', font: { size: 11 }, padding: { bottom: 8 } },
        },
        scales: {
          y: { min: 0, max: 100, ticks: { callback: (v: any) => `${v}%`, font: { size: 10 } }, grid: { color: '#efefef' } },
          x: { grid: { display: false }, ticks: { font: { size: 12 } } },
        },
      } as any,
    });
  } catch (err) {
    logger.error({ err, chart: 'sebi_domain_bar' }, 'Failed to render chart');
    throw err;
  }
}

export async function generateSebiCharts(snapshot: any) {
  return generateFrameworkCharts(snapshot, [], FRAMEWORK_COLORS.sebi);
}
