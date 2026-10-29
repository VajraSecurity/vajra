import path from 'path';
import ejs from 'ejs';
import { getLogger } from '../utils/logger';
import { TEMPLATES_DIR } from '../consts/server';

const logger = getLogger('controllers.generateFrameworkReport');

// Shared headless browser. Chromium is launched lazily, once, and reused; each
// PDF request takes a page instead of spawning its own process. Launching per
// request dominates the request (a cold launch is an order of magnitude more
// than the setContent+pdf work) and, because this is a single Node process with
// no clustering or worker threads (src/index.ts holds the only listen()), the
// spawn stalls every other in-flight request including agent check-ins and the
// WebSocket layer. The browser lifetime does not affect the rendered PDF: two
// renders in the same second are byte-identical across a fresh and a reused
// browser, /CreationDate and /ModDate aside.
//
// This lives here rather than in a new module because this file already owns the
// Chromium interaction for framework reports and reports.ts imports from it.

type ReportBrowser = Awaited<ReturnType<(typeof import('puppeteer'))['default']['launch']>>;
type ReportPage = Awaited<ReturnType<ReportBrowser['newPage']>>;

// The rendered PDF depends on this flag set, so it must not drift.
// `timeout` restates Puppeteer's own default (BrowserLauncher: `timeout = 30000`)
// rather than inheriting it silently: the guarantee that a wedged Chromium — no
// sandbox, exhausted /dev/shm — cannot hold a request open forever is what makes
// a shared browser safe to depend on, so it should be visible here.
const LAUNCH_OPTIONS = {
  headless: true as const,
  args: ['--no-sandbox', '--disable-setuid-sandbox'],
  timeout: 30_000,
};

// An idle Chromium holds several hundred MB RSS across its processes. Compliance
// PDFs are on-demand admin downloads, not a steady stream, so on a box that also
// runs the API, the WebSocket fleet layer and the scan workers, holding that
// resident indefinitely to save one launch is a bad trade. Retire it once nothing
// has needed it for this long; the next report simply relaunches.
const IDLE_SHUTDOWN_MS = 10 * 60_000;

let browserPromise: Promise<ReportBrowser> | null = null;
/** In-flight acquireReportBrowser() calls that have not released yet. */
let leases = 0;
let idleTimer: NodeJS.Timeout | null = null;

function launchSharedBrowser(): Promise<ReportBrowser> {
  if (browserPromise) return browserPromise;

  const startedAt = Date.now();
  // Assigned to `browserPromise` immediately below, so a burst of concurrent
  // report requests coalesces onto one launch instead of racing several.
  const promise: Promise<ReportBrowser> = (async () => {
    const { default: puppeteer } = await import('puppeteer');
    const browser = await puppeteer.launch(LAUNCH_OPTIONS);
    // Chromium can die out from under us — OOM killer, exhausted /dev/shm, an
    // operator killing the process. Drop the cached promise the moment that
    // happens, otherwise every later report inherits the corpse. Puppeteer sets
    // `connected = false` and emits this from the same synchronous close path,
    // so a caller can never observe a disconnected browser that is still cached.
    browser.on('disconnected', () => {
      if (browserPromise !== promise) return; // already retired deliberately
      browserPromise = null;
      logger.warn({}, 'Shared report browser disconnected; the next report will relaunch it');
    });
    logger.debug({ ms: Date.now() - startedAt }, 'Shared report browser launched');
    return browser;
  })();

  browserPromise = promise;
  // A failed launch must not poison the cache: without this, one transient
  // failure (no sandbox, /dev/shm full, disk pressure) would be replayed as the
  // same rejection to every future report until the process restarts.
  promise.catch(() => {
    if (browserPromise === promise) browserPromise = null;
  });
  return promise;
}

/**
 * Take a lease on the shared Chromium, launching it if needed.
 * Every successful call MUST be paired with a releaseReportBrowser() in a
 * finally — the lease count is what keeps the idle reaper from closing a browser
 * that a request is still using. Callers close their own page, never the browser.
 */
export async function acquireReportBrowser(): Promise<ReportBrowser> {
  // Cancel the reaper and take the lease synchronously, before the first await:
  // the event loop is single-threaded, so the timer cannot fire in this gap.
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
  leases++;
  try {
    return await launchSharedBrowser();
  } catch (err) {
    // Launch failed, so the caller gets no browser and will not release.
    leases = Math.max(0, leases - 1);
    throw err;
  }
}

/** Release a lease taken by acquireReportBrowser(). Never throws. */
export function releaseReportBrowser(): void {
  leases = Math.max(0, leases - 1);
  if (leases > 0 || idleTimer || !browserPromise) return;

  idleTimer = setTimeout(() => {
    idleTimer = null;
    if (leases > 0) return; // a request arrived and re-leased; leave it alone

    const retiring = browserPromise;
    // Cleared synchronously so the next acquire starts a fresh launch rather
    // than awaiting a browser we are in the middle of closing. The disconnected
    // handler above sees `browserPromise !== promise` and stays quiet.
    browserPromise = null;
    void retiring
      ?.then((browser) => browser.close())
      .then(() => logger.debug({}, 'Shared report browser closed after idle timeout'))
      .catch((err) => logger.warn({ err }, 'Failed to close idle report browser'));
  }, IDLE_SHUTDOWN_MS);
  // Don't let a 10-minute reaper hold the process open during shutdown.
  // Puppeteer's own handleSIGINT/SIGTERM/SIGHUP defaults kill the Chromium child
  // when this process exits, so an un-reaped browser is not a leak on restart.
  idleTimer.unref();
}

export async function generateFrameworkReport(
  templateData: Record<string, unknown>,
): Promise<Buffer> {
  const templatePath = path.join(TEMPLATES_DIR, 'framework_report1.html');

  let html: string;
  try {
    html = await ejs.renderFile(templatePath, templateData);
  } catch (err) {
    logger.error({ err, templatePath }, 'Failed to render framework compliance report template');
    throw err;
  }

  // Build a Puppeteer headerTemplate so the header lives in the margin area
  // (not the content area), preventing it from overlapping page content.
  const vajraSvg = (templateData.vajra_logo_svg  as string | undefined) ?? '';
  const vajraUri = vajraSvg
    ? `data:image/svg+xml;base64,${Buffer.from(vajraSvg).toString('base64')}`
    : '';

const headerTemplate = `
    <div style="width:100%;height:14mm;box-sizing:border-box;
                display:flex;align-items:center;justify-content:space-between;
                padding:0 16mm;border-bottom:0.75pt solid #d0d0d0;background:#fff;">
      <span></span>
      ${vajraUri ? `<img src="${vajraUri}" style="height:8mm;width:auto;" alt="Vajra"/>`       : '<span></span>'}
    </div>
  `;

  let browser: ReportBrowser | undefined;
  let page: ReportPage | undefined;
  try {
    browser = await acquireReportBrowser();
    page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });

    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate,
      footerTemplate: `
        <div style="width:100%;font-family:'Bookman Old Style','URW Bookman',Bookman,'Palatino Linotype',Palatino,Georgia,serif;font-size:7.5pt;
                    color:#999;display:flex;justify-content:space-between;align-items:center;
                    padding:3pt 16mm 0;border-top:0.5pt solid #e0e0e0;box-sizing:border-box;">
          <span>Vajra &middot; Confidential</span>
          <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        </div>
      `,
      // 24 mm top margin gives the header template room; content starts clean below it
      margin: { top: '28mm', bottom: '20mm', left: '16mm', right: '16mm' },
    });

    return Buffer.from(pdf);
  } catch (err) {
    logger.error({ err }, 'Failed to render framework compliance PDF report');
    throw err;
  } finally {
    // Close the page, not the browser — the browser is shared with every other
    // report request. A close failure is logged rather than thrown so it cannot
    // mask the real error from the try block.
    if (page) {
      await page.close().catch((err) => logger.warn({ err }, 'Failed to close framework report page'));
    }
    if (browser) releaseReportBrowser();
  }
}
