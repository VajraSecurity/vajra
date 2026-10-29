import { useCallback, useEffect, useState } from 'react';
import { Plus, Inbox, Trash2, Eye, Loader2, CheckCircle2, XCircle, Info } from 'lucide-react';
import { Modal, Dropdown, CheckboxMultiSelect, ErrorBanner, StatusToggle } from './ui';
import { InlineSpinner } from '@/components/ui/loading';
import { THREAT_INTEL_FORMATS, THREAT_INTEL_STIX_TYPES, THREAT_INTEL_MAX_ENTRIES_CAP, THREAT_INTEL_MIN_REFRESH_SECONDS } from './constants';
import { listThreatIntelFeeds, createThreatIntelFeed, updateThreatIntelFeed, deleteThreatIntelFeed, previewThreatIntelFeed } from '../../api/api';
import type { ThreatIntelFeed, ThreatIntelPreviewResult } from '../../api/services/ruleEngineApi';
import { useConfirm } from '../../context/useConfirm';
import { getStoredUser } from '../../services/auth';

export default function StixFeedsTab() {
  const [items, setItems] = useState<ThreatIntelFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [previewing, setPreviewing] = useState<string | null>(null);
  const [previewResult, setPreviewResult] = useState<{ name: string; result: ThreatIntelPreviewResult } | null>(null);
  const [busyName, setBusyName] = useState<string | null>(null);
  const confirm = useConfirm();
  // Feeds are shared fleet-wide infra (a credential/URL/subscription, not a
  // per-group resource) — write access is Super Admin only. Preview stays
  // available to everyone since it's non-mutating (see rule-engine.ts).
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listThreatIntelFeeds();
      setItems(resp.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load feeds');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleToggle = async (f: ThreatIntelFeed) => {
    setBusyName(f.name);
    try {
      await updateThreatIntelFeed(f.name, { enabled: !f.enabled });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update feed');
    } finally {
      setBusyName(null);
    }
  };

  const handleDelete = async (f: ThreatIntelFeed) => {
    const ok = await confirm({ title: `Delete feed "${f.name}"?`, confirmLabel: 'Delete', variant: 'danger' });
    if (!ok) return;
    setBusyName(f.name);
    try {
      await deleteThreatIntelFeed(f.name);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete feed');
    } finally {
      setBusyName(null);
    }
  };

  const handlePreview = async (f: ThreatIntelFeed) => {
    setPreviewing(f.name);
    setPreviewResult(null);
    try {
      const result = await previewThreatIntelFeed(f.name);
      setPreviewResult({ name: f.name, result });
    } catch (err) {
      setPreviewResult({ name: f.name, result: { ok: false, message: err instanceof Error ? err.message : 'Preview failed' } });
    } finally {
      setPreviewing(null);
    }
  };

  return (
    <div className="flex flex-col gap-4 h-full min-h-0">
      <div className="flex items-start justify-between gap-3 shrink-0">
        <div className="flex items-start gap-2 max-w-2xl text-xs text-slate-500 dark:text-slate-400">
          <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />
          <p>
            "STIX Feeds" here means a direct HTTPS fetch of a STIX 2.x bundle or an AbuseIPDB blacklist — not TAXII
            (no TAXII discovery/polling protocol is implemented anywhere in the engine). Adding a feed here does{' '}
            <strong>not</strong> automatically make it live on any running engine instance — that still needs a
            manual <code className="text-[11px]">config.json</code> change + restart on whichever instance should
            consume it.
          </p>
        </div>
        {isSuperAdmin && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 shrink-0"
          >
            <Plus className="h-4 w-4" /> Add Feed
          </button>
        )}
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="flex-1 min-h-0 overflow-auto rounded-2xl border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-900">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800 border-b border-slate-200 dark:border-white/10">
            <tr>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Name</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Format</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">URL</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Target List</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Refresh</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Status</th>
              <th className="text-right px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-white/5">
            {loading && items.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-slate-400"><InlineSpinner text="Loading…" size="sm" /></td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-slate-400">
                <Inbox className="h-6 w-6 mx-auto mb-2 text-slate-300" />
                No threat-intel feeds configured
              </td></tr>
            )}
            {items.map((f) => (
              <tr key={f.name} className="hover:bg-slate-50/80 dark:hover:bg-white/5">
                <td className="px-4 py-2.5 font-semibold text-slate-800 dark:text-slate-100">{f.name}</td>
                <td className="px-4 py-2.5"><code className="text-xs bg-slate-100 dark:bg-white/10 rounded px-1.5 py-0.5">{f.format}</code></td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 max-w-xs truncate" title={f.url}>{f.url}</td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-xs">{f.target_list}</td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-xs">{f.refresh_interval_seconds}s</td>
                <td className="px-4 py-2.5">
                  {isSuperAdmin ? (
                    <StatusToggle enabled={f.enabled} busy={busyName === f.name} onToggle={() => handleToggle(f)} />
                  ) : (
                    <span className={`text-xs font-medium ${f.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>
                      {f.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-right">
                  <div className="flex items-center justify-end gap-3">
                    <button
                      onClick={() => handlePreview(f)}
                      disabled={previewing === f.name}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline disabled:opacity-50"
                    >
                      {previewing === f.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Eye className="h-3 w-3" />}
                      Preview
                    </button>
                    {isSuperAdmin && (
                      <button
                        onClick={() => handleDelete(f)}
                        disabled={busyName === f.name}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
                      >
                        <Trash2 className="h-3 w-3" /> Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {previewResult && (
        <div className={`shrink-0 rounded-lg border p-3 text-sm ${previewResult.result.ok ? 'border-emerald-200 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10' : 'border-red-200 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10'}`}>
          <p className="flex items-center gap-2 font-semibold">
            {previewResult.result.ok ? <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-600 dark:text-red-400" />}
            Preview: {previewResult.name}
          </p>
          {previewResult.result.ok && previewResult.result.counts && (
            <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
              {Object.entries(previewResult.result.counts).map(([k, v]) => `${k}: ${v}`).join(' · ')}
            </p>
          )}
          {!previewResult.result.ok && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{previewResult.result.message}</p>}
        </div>
      )}

      {showForm && <AddFeedModal onClose={() => setShowForm(false)} onCreated={load} />}
    </div>
  );
}

function AddFeedModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [format, setFormat] = useState<'abuseipdb' | 'stix'>('stix');
  const [url, setUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [targetList, setTargetList] = useState('');
  const [refreshSeconds, setRefreshSeconds] = useState(3600);
  const [maxEntries, setMaxEntries] = useState(10000);
  const [stixTypes, setStixTypes] = useState<string[]>(['ip']);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    if (!name.trim() || !targetList.trim()) {
      setError('Name and target list are required.');
      return;
    }
    if (!url.trim() || (format === 'stix' && !url.trim().startsWith('https://'))) {
      setError(format === 'stix' ? 'STIX feeds require an https:// URL.' : 'URL is required.');
      return;
    }
    if (refreshSeconds < THREAT_INTEL_MIN_REFRESH_SECONDS) {
      setError(`Refresh interval must be at least ${THREAT_INTEL_MIN_REFRESH_SECONDS} seconds.`);
      return;
    }
    if (maxEntries > THREAT_INTEL_MAX_ENTRIES_CAP) {
      setError(`Max entries is capped at ${THREAT_INTEL_MAX_ENTRIES_CAP.toLocaleString()}.`);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await createThreatIntelFeed({
        name: name.trim(), format, enabled: true, url: url.trim(),
        ...(apiKey.trim() ? { api_key: apiKey.trim() } : {}),
        target_list: targetList.trim(),
        refresh_interval_seconds: refreshSeconds,
        max_entries: maxEntries,
        ...(format === 'stix' ? { stix_types: stixTypes as ThreatIntelFeed['stix_types'] } : {}),
      });
      onCreated();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create feed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Add Threat-Intel Feed" onClose={onClose}>
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Name <span className="text-red-500">*</span></label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)}
              className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Format</label>
            <Dropdown value={format} onChange={(v) => setFormat(v as 'abuseipdb' | 'stix')} options={THREAT_INTEL_FORMATS.map((f) => ({ value: f, label: f }))} aria-label="Format" />
          </div>
        </div>
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
            URL <span className="text-red-500">*</span> {format === 'stix' && <span className="font-normal normal-case text-slate-400">(must be https://)</span>}
          </label>
          <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…"
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">API Key (optional)</label>
            <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
              className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Target List <span className="text-red-500">*</span></label>
            <input type="text" value={targetList} onChange={(e) => setTargetList(e.target.value)} placeholder="e.g. feed:abuse_ips"
              className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Refresh Interval (seconds, ≥60)</label>
            <input type="number" min={THREAT_INTEL_MIN_REFRESH_SECONDS} value={refreshSeconds} onChange={(e) => setRefreshSeconds(Number(e.target.value))}
              className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Max Entries (≤{THREAT_INTEL_MAX_ENTRIES_CAP.toLocaleString()})</label>
            <input type="number" min={1} max={THREAT_INTEL_MAX_ENTRIES_CAP} value={maxEntries} onChange={(e) => setMaxEntries(Number(e.target.value))}
              className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
          </div>
        </div>
        {format === 'stix' && (
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">Indicator Types to Extract</label>
            <CheckboxMultiSelect values={stixTypes} onChange={setStixTypes} options={THREAT_INTEL_STIX_TYPES.map((t) => ({ value: t, label: t }))} columns={3} />
          </div>
        )}
        {error && <ErrorBanner message={error} />}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="rounded-lg border border-slate-200 dark:border-white/10 px-4 py-2 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-white/5">Cancel</button>
          <button onClick={handleSave} disabled={saving} className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50">
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            Create
          </button>
        </div>
      </div>
    </Modal>
  );
}
