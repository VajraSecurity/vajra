import { useEffect, useMemo, useRef, useState } from 'react';
import { Plus, Search, Trash2 } from 'lucide-react';
import { listFimCatalog, type FimCatalogSource, type FimEntryKind, type FimOsPlatform, type FimPolicyPath, type FimSeverity } from '../../api/services/fimApi';
import { KIND_LABEL, SEVERITIES, blankEntry, entryError, errMsg, humanInterval, problemFor, type EntryProblem } from './constants';
import { Dropdown, ErrorBanner, FimModal, KindBadge } from './ui';
import { btnGhost, btnPrimary, inputCls } from './styles';
import { RegText } from './UntrustedText';

const CATEGORIES = ['system', 'auth', 'ssh', 'persistence', 'binaries', 'libraries', 'web', 'drivers', 'startup', 'accounts', 'network', 'kernel', 'software', 'posture', 'registry', 'acl'];
const WIN_NOTE = 'needs Windows agent support - verify';

const KIND_HELP: Record<FimEntryKind, string> = {
  path: 'Tracks files AND directories under the pattern: content hash, permissions and owner for files; permissions and owner for directories. % matches one level, %% is recursive.',
  xattr: 'Tracks extended attributes under the pattern: POSIX ACLs (system.posix_acl_*), file capabilities (security.capability) and SELinux labels. Only files that have one produce an item.',
  registry: `Tracks registry values under a key pattern (type and data). % matches one level of subkeys, %% is recursive. Use HKEY_USERS\\%\\... for per-user keys. Real-time registry changes (with process and user) come from the agent's existing win_registry_events stream and need nothing extra published; the real-time toggle does not gate them, and the scan interval does the baseline comparison. Avoid broad subtrees such as ...\\CurrentControlSet\\Services\\% (thousands of rows). (${WIN_NOTE})`,
  acl: `Tracks NTFS permission entries (principal, access, inheritance) of one exact path. (${WIN_NOTE})`,
  table: 'Tracks a system configuration source (accounts, ports, packages, tasks...) item by item.',
};
const PLACEHOLDER: Record<string, (os: FimOsPlatform) => string> = {
  path: (os) => (os === 'linux' ? '/etc/ssh/%%' : 'C:\\Windows\\System32\\drivers\\etc\\%%'),
  xattr: () => '/etc/%%',
  registry: () => 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  acl: () => 'C:\\Windows\\System32',
};


function CatalogPicker({ os, existing, onPick, onClose }: { os: FimOsPlatform; existing: Set<string>; onPick: (s: FimCatalogSource) => void; onClose: () => void }) {
  const [items, setItems] = useState<FimCatalogSource[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState('');
  useEffect(() => { listFimCatalog(os).then((r) => setItems(r.items ?? [])).catch((e) => setErr(errMsg(e, 'Failed to load the catalog'))); }, [os]);
  const shown = useMemo(() => items.filter((s) => `${s.label} ${s.description} ${s.id} ${s.category}`.toLowerCase().includes(q.toLowerCase())), [items, q]);
  return (
    <FimModal wide title={`System configuration sources (${os})`} onClose={onClose} footer={<button className={btnGhost} onClick={onClose}>Close</button>}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} />}
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input aria-label="Search sources" className={`${inputCls} pl-8`} placeholder="Search sources" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <ul className="space-y-2">
          {shown.map((s) => (
            <li key={s.id} className="rounded-lg border border-slate-200 dark:border-white/10 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-semibold">{s.label} <span className="ml-1 text-xs font-normal text-slate-400">{s.category}</span>
                    {!s.verified && <span className="ml-2 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-700">{WIN_NOTE}</span>}
                    {s.requiresExtension && <span className="ml-2 rounded-full bg-rose-100 px-2 py-0.5 text-[10px] font-semibold text-rose-700">needs an osquery extension</span>}
                  </p>
                  <p className="text-xs text-slate-500">{s.description}</p>
                  <p className="mt-1 text-xs text-slate-500">Identified by <span className="font-mono">{s.keyColumns.join(', ')}</span>{s.valueColumns.length > 0 && <>; changes detected in <span className="font-mono">{s.valueColumns.join(', ')}</span></>} - suggested scan {humanInterval(s.intervalHint).toLowerCase()}.</p>
                  {s.notes && <p className="text-xs text-slate-400">{s.notes}</p>}
                </div>
                <button className={btnPrimary} disabled={existing.has(s.id)} onClick={() => onPick(s)}>{existing.has(s.id) ? 'Added' : 'Add'}</button>
              </div>
            </li>
          ))}
          {shown.length === 0 && <li className="text-sm text-slate-400">No matching sources.</li>}
        </ul>
      </div>
    </FimModal>
  );
}

/** Multi-kind entry editor for the policy form. */
export default function EntriesEditor({ os, paths, setPaths, ignoreText, setIgnoreText, touched, pathsErr, problems }: {
  os: FimOsPlatform; paths: FimPolicyPath[]; setPaths: React.Dispatch<React.SetStateAction<FimPolicyPath[]>>;
  ignoreText: string[]; setIgnoreText: React.Dispatch<React.SetStateAction<string[]>>; touched: boolean; pathsErr: string | null;
  /** Server-reported problems (save / publish error naming an entry, or stored entries that can no longer be built). */
  problems?: EntryProblem[];
}) {
  const [picker, setPicker] = useState(false);
  const firstProblemRef = useRef<HTMLDivElement | null>(null);
  const firstProblemIdx = paths.findIndex((_, i) => !!problemFor(problems, paths, i));
  useEffect(() => { if (firstProblemIdx >= 0) firstProblemRef.current?.scrollIntoView?.({ block: 'center' }); }, [firstProblemIdx, problems]);
  const add = (e: FimPolicyPath) => { setPaths((p) => [...p, e]); setIgnoreText((t) => [...t, '']); };
  const upd = (i: number, patch: Partial<FimPolicyPath>) => setPaths((ps) => ps.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  const remove = (i: number) => { setPaths((ps) => ps.filter((_, j) => j !== i)); setIgnoreText((t) => t.filter((_, j) => j !== i)); };
  const have = new Set(paths.filter((p) => (p.kind ?? 'path') === 'table' && p.source).map((p) => p.source as string));
  const adders: { kind: FimEntryKind; label: string; only?: FimOsPlatform }[] = [
    { kind: 'path', label: 'Files & directories' },
    { kind: 'xattr', label: 'Extended attributes & ACLs', only: 'linux' },
    { kind: 'registry', label: 'Registry keys', only: 'windows' },
    { kind: 'acl', label: 'NTFS ACLs', only: 'windows' },
  ];

  return (
    <section aria-label="Entries" className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Monitored entries</h3>
        <div className="flex flex-wrap gap-2" role="group" aria-label="Add entry">
          {adders.filter((a) => !a.only || a.only === os).map((a) => (
            <button key={a.kind} type="button" className={btnGhost} onClick={() => add(blankEntry(a.kind))}><Plus className="h-4 w-4" /> {a.label}</button>
          ))}
          <button type="button" className={btnGhost} onClick={() => setPicker(true)}><Plus className="h-4 w-4" /> System configuration...</button>
        </div>
      </div>
      <div className="rounded-lg bg-slate-50 dark:bg-white/5 p-3 text-xs text-slate-600 dark:text-slate-300 space-y-1">
        <p>Each entry is scanned by its own query. {KIND_HELP.path}</p>
        <p><code className="font-mono">%%</code> matches <strong>recursively</strong>, <code className="font-mono">%</code> matches <strong>one level</strong>. No single quotes, max 1024 characters.{os === 'linux' ? " Linux paths must start with '/'; '*' and '?' are not supported." : " Windows paths start with a drive letter (C:\\)."} A real directory must come before the first wildcard.</p>
        <p>Keep an entry under ~2,500 files or rows: a larger result exceeds the osquery result line limit and the whole scan of that entry is dropped - narrow it. End a path with {os === 'linux' ? '/' : '\\'} to track that directory&apos;s own permissions and owner (e.g. {os === 'linux' ? '/etc/ssh/' : 'C:\\Windows\\System32\\'}){os === 'windows' ? '; on Windows prefer NTFS ACL entries for directory permissions' : ''}. Ignore patterns are comma-separated globs (for example <code className="font-mono">*.log, *.tmp</code>) applied to file entries.</p>
        {os === 'linux' && <p>Hidden files are scanned for % and %% patterns, but only to a limited depth (three levels below the pattern, and files directly inside hidden directories).</p>}
        <p>Real-time events (file entries only) require the osquery agent to run with --enable_file_events=true. Policy changes reach agents on the agent&apos;s config refresh interval (--config_refresh).</p>
      </div>
      {pathsErr && touched && <p role="alert" className="text-xs text-red-600">{pathsErr}</p>}
      {paths.map((p, i) => {
        const kind = (p.kind ?? 'path') as FimEntryKind;
        const err = entryError(p, os);
        const problem = problemFor(problems, paths, i);
        return (
          <div key={i} ref={i === firstProblemIdx ? firstProblemRef : undefined} data-testid={`fim-entry-${i}`} data-problem={problem ? 'true' : undefined}
            className={`rounded-lg border p-3 space-y-2 ${problem ? 'border-red-500 ring-2 ring-red-400 bg-red-50/60 dark:bg-red-500/10' : 'border-slate-200 dark:border-white/10'}`}>
            {problem && (
              <p role="alert" className="text-xs font-semibold text-red-700 dark:text-red-300">
                Entry #{i}: <RegText value={problem.error} /> - fix this entry or remove it, then save and publish again.
              </p>
            )}
            <div className="flex gap-2 items-start">
              <div className="flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <KindBadge kind={kind} />
                  {kind === 'table' && <span className="text-sm font-semibold">{p.label ?? p.source}</span>}
                  {(kind === 'registry' || kind === 'acl') && <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-700">{WIN_NOTE}</span>}
                </div>
                {kind === 'table' ? (
                  <p className="text-xs text-slate-500">Source <span className="font-mono">{p.source}</span>{p.keyColumns && <> - identified by <span className="font-mono">{p.keyColumns.join(', ')}</span></>}{p.valueColumns && p.valueColumns.length > 0 && <>, compares <span className="font-mono">{p.valueColumns.join(', ')}</span></>}</p>
                ) : (
                  <>
                    <input aria-label={`Path ${i + 1}`} aria-invalid={!!err} className={`${inputCls} font-mono`} value={p.path ?? ''} placeholder={PLACEHOLDER[kind](os)} onChange={(e) => upd(i, { path: e.target.value })} />
                    {(touched || p.path) && err && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{err}</p>}
                    <p className="text-xs text-slate-400">{KIND_HELP[kind]}</p>
                  </>
                )}
              </div>
              <button type="button" aria-label={`Remove entry ${i + 1}`} className="rounded-lg p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10" onClick={() => remove(i)}><Trash2 className="h-4 w-4" /></button>
            </div>
            <div className={`grid gap-2 ${kind === 'path' ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}>
              <Dropdown aria-label={`Severity ${i + 1}`} value={p.severity} onChange={(v) => upd(i, { severity: v as FimSeverity })} options={SEVERITIES.map((s) => ({ value: s, label: `Severity: ${s}` }))} />
              <input aria-label={`Category ${i + 1}`} list="fim-categories" className={inputCls} placeholder="Category" value={p.category} onChange={(e) => upd(i, { category: e.target.value })} />
              {kind === 'path' && <input aria-label={`Ignore globs ${i + 1}`} className={inputCls} placeholder="Ignore: *.log, *.tmp" value={ignoreText[i] ?? ''} onChange={(e) => setIgnoreText((t) => t.map((x, j) => (j === i ? e.target.value : x)))} />}
            </div>
          </div>
        );
      })}
      <datalist id="fim-categories">{CATEGORIES.map((c) => <option key={c} value={c} />)}</datalist>
      {picker && <CatalogPicker os={os} existing={have} onClose={() => setPicker(false)}
        onPick={(s) => add({ kind: 'table', source: s.id, label: s.label, keyColumns: s.keyColumns, valueColumns: s.valueColumns, severity: s.severity, category: s.category, ignore: [], hash: false })} />}
      <p className="text-[11px] text-slate-400">{Object.entries(KIND_LABEL).filter(([k]) => ['path', 'xattr', 'registry', 'acl', 'table'].includes(k)).map(([, v]) => v).join(' | ')}</p>
    </section>
  );
}
