import { Info } from 'lucide-react';

/** Collapsible help: what osquery-based registry FIM cannot see, and what is not verified yet (§4.7). */
export default function RegistryHelp() {
  return (
    <details className="rounded-2xl border border-slate-200 bg-white p-4 text-sm dark:border-white/10 dark:bg-slate-900">
      <summary className="flex cursor-pointer items-center gap-2 font-semibold text-slate-800 dark:text-slate-100"><Info aria-hidden className="h-4 w-4 text-indigo-600" />What registry coverage can and cannot detect</summary>
      <div className="mt-3 space-y-3 text-slate-600 dark:text-slate-300">
        <section>
          <h4 className="font-semibold text-slate-800 dark:text-slate-100">Cannot be detected with osquery alone</h4>
          <ul className="mt-1 list-disc space-y-1 pl-5">
            <li>An attacker with SYSTEM or kernel rights who hooks osqueryd's registry calls, or replaces the agent in a way that keeps its hash (for example through a driver), can forge or suppress results.</li>
            <li>Keys or values with an embedded NUL in their name (hidden through the native API) cannot be read through the Win32 API osquery uses.</li>
            <li>Offline edits (WinPE, a copied hive) that are reverted before boot ends.</li>
            <li>Edits to per-user hives that are never loaded again (the user never logs on again).</li>
          </ul>
          <p className="mt-1">Pair this feature with EDR and with SACL auditing (Security event 4657, registry value modified) on the Essential keys.</p>
        </section>
        <section>
          <h4 className="font-semibold text-slate-800 dark:text-slate-100">Real-time</h4>
          <p>Real-time registry events (<span className="font-mono">win_registry_events</span>) need the plgx agent; stock osquery only scans on schedule. Real-time raises early drift with process and user, but scheduled scans are the source of truth for the baseline. Entries marked "needs real-time" (for example UAC-bypass keys created and removed within seconds) can be missed on nodes without it.</p>
        </section>
        <section>
          <h4 className="font-semibold text-slate-800 dark:text-slate-100">Not yet verified</h4>
          <p>The registry scan SQL (anchor rows, exclusions, value allow-lists, the per-user Classes link) and the real-time key mappings are <b>UNVERIFIED</b> until they are probed on a Windows agent. Entries marked "UNVERIFIED (estimate)" use estimated sizes and behaviour.</p>
        </section>
      </div>
    </details>
  );
}
