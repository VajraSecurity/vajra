import { useCallback, useEffect, useState } from 'react';
import { Plus, Inbox, Upload, Trash2, Network, Loader2, CheckCircle2, XCircle, Info } from 'lucide-react';
import { Modal, CheckboxMultiSelect, TagInput, SeverityBadge, ErrorBanner, StatusToggle } from './ui';
import { InlineSpinner } from '@/components/ui/loading';
import { EVENT_TYPES, DEFAULT_IP_WATCH_EVENT_TYPES } from './constants';
import {
  listIpWatchGroups, createIpWatchGroup, setIpWatchGroupEnabled, deleteIpWatchGroup,
  getIpWatchGroupIps, addIpWatchGroupIps, importIpWatchGroupCsv, deleteIpWatchGroupIp,
} from '../../api/api';
import { fetchEndpointGroups, type EndpointGroup } from '../../api/services/endpointGroupsApi';
import type { IpWatchGroup, CsvImportSummary } from '../../api/services/ruleEngineApi';
import { useConfirm } from '../../context/useConfirm';
import { useToast } from '../../context/useToast';
import { getStoredUser } from '../../services/auth';

export default function IpWatchGroupsTab() {
  const [items, setItems] = useState<IpWatchGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [ipsGroup, setIpsGroup] = useState<IpWatchGroup | null>(null);
  const [busyName, setBusyName] = useState<string | null>(null);
  const confirm = useConfirm();
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listIpWatchGroups();
      setItems(resp.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load IP watch groups');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleToggle = async (g: IpWatchGroup) => {
    setBusyName(g.name);
    try {
      await setIpWatchGroupEnabled(g.name, !g.enabled);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update group');
    } finally {
      setBusyName(null);
    }
  };

  const handleDelete = async (g: IpWatchGroup) => {
    const ok = await confirm({
      title: `Delete "${g.name}"?`,
      description: 'This removes the watch group. Its backing IP list is kept, in case a future group reuses it.',
      confirmLabel: 'Delete',
      variant: 'danger',
    });
    if (!ok) return;
    setBusyName(g.name);
    try {
      await deleteIpWatchGroup(g.name);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete group');
    } finally {
      setBusyName(null);
    }
  };

  return (
    <div className="flex flex-col gap-4 h-full min-h-0">
      <div className="flex items-center justify-between shrink-0">
        <p className="text-xs text-slate-500 dark:text-slate-400 max-w-2xl">
          Alerts on any connection to a monitored set of IPs — synthesizes a real detection rule against{' '}
          <code className="text-[11px]">network.remote_address</code>, scoped to the event types you pick below.
        </p>
        {isSuperAdmin && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 shrink-0"
          >
            <Plus className="h-4 w-4" /> Add Watch Group
          </button>
        )}
      </div>

      <div className="flex items-start gap-2 shrink-0 rounded-lg bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 px-3 py-2 text-xs text-slate-500 dark:text-slate-400">
        <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />
        <p>
          Adding an IP applies fleet-wide once the engine reloads — it is not limited to your own group's endpoints.
          {!isSuperAdmin && ' You can add or remove IPs on watch groups your group has been given access to; creating, deleting, or enabling/disabling a group is Super Administrator only.'}
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="flex-1 min-h-0 overflow-auto rounded-2xl border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-900">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800 border-b border-slate-200 dark:border-white/10">
            <tr>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Name</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Description</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Event Types</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Level</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">IPs</th>
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
                No IP watch groups configured
              </td></tr>
            )}
            {items.map((g) => (
              <tr key={g.name} className="hover:bg-slate-50/80 dark:hover:bg-white/5">
                <td className="px-4 py-2.5 font-semibold text-slate-800 dark:text-slate-100">{g.name}</td>
                <td className="px-4 py-2.5 text-slate-600 dark:text-slate-300 max-w-xs truncate" title={g.description}>{g.description}</td>
                <td className="px-4 py-2.5 text-xs text-slate-500 dark:text-slate-400">{g.event_types.join(', ')}</td>
                <td className="px-4 py-2.5"><SeverityBadge level={g.level} /></td>
                <td className="px-4 py-2.5">
                  {isSuperAdmin || g.canManageIps ? (
                    <button
                      onClick={() => setIpsGroup(g)}
                      title="Add or remove IPs in this group"
                      className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-200 dark:border-indigo-400/30 bg-indigo-50 dark:bg-indigo-500/10 px-2.5 py-1 text-xs font-semibold text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-500/20"
                    >
                      <Network className="h-3 w-3" /> {g.ip_count ?? 0} IP{g.ip_count === 1 ? '' : 's'} · Add / Manage
                    </button>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-xs text-slate-400">
                      <Network className="h-3 w-3" /> {g.ip_count ?? 0} IP{g.ip_count === 1 ? '' : 's'}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5">
                  {isSuperAdmin ? (
                    <StatusToggle enabled={g.enabled} busy={busyName === g.name} onToggle={() => handleToggle(g)} />
                  ) : (
                    <span className={`text-xs font-medium ${g.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>
                      {g.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-right">
                  {isSuperAdmin && (
                    <button
                      onClick={() => handleDelete(g)}
                      disabled={busyName === g.name}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
                    >
                      <Trash2 className="h-3 w-3" /> Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showForm && <AddWatchGroupModal onClose={() => setShowForm(false)} onCreated={load} />}
      {ipsGroup && <WatchGroupIpsModal group={ipsGroup} onClose={() => setIpsGroup(null)} onChanged={load} />}
    </div>
  );
}

function AddWatchGroupModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [level, setLevel] = useState(4);
  const [eventTypes, setEventTypes] = useState<string[]>(DEFAULT_IP_WATCH_EVENT_TYPES);
  const [groups, setGroups] = useState<string[]>([]);
  const [initialIps, setInitialIps] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { showToast } = useToast();

  // Owning team — a real vajranet node-group, distinct from the free-text
  // "Groups" tag field below (an unrelated MITRE-style categorization tag
  // the engine already had; do not confuse the two). Only Super Admin ever
  // sees this modal, but a watch group left unassigned here stays Super-
  // Admin-only to manage IPs on too (see utils/ruleEngineScope.ts — an
  // unowned resource fails closed), so this is worth setting at create time
  // rather than a separate step later.
  const [endpointGroups, setEndpointGroups] = useState<EndpointGroup[]>([]);
  const [ownerGroupId, setOwnerGroupId] = useState('');
  useEffect(() => {
    fetchEndpointGroups().then(setEndpointGroups).catch(() => setEndpointGroups([]));
  }, []);

  const handleSave = async () => {
    if (!name.trim() || !description.trim() || eventTypes.length === 0) {
      setError('Name, description, and at least one event type are required.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const groupName = name.trim();
      await createIpWatchGroup({
        name: groupName,
        description: description.trim(),
        level,
        event_types: eventTypes,
        groups,
        list: `watch:${groupName}`,
        ownerGroupId: ownerGroupId || undefined,
      });
      if (initialIps.length > 0) {
        try {
          await addIpWatchGroupIps(groupName, initialIps);
        } catch (err) {
          // The group itself was created successfully — don't lose that by
          // reporting this as a failure; just toast it so the user knows to
          // add the IPs from the group's own "IPs" modal instead.
          showToast(err instanceof Error ? `Group created, but adding the initial IPs failed: ${err.message}` : 'Group created, but adding the initial IPs failed.', 'warning');
        }
      }
      onCreated();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create watch group — the real engine rejected it (see message above)');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Add IP Watch Group" onClose={onClose}>
      <div className="space-y-4">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Name <span className="text-red-500">*</span></label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. finance_servers"
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
        </div>
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Description <span className="text-red-500">*</span></label>
          <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Connection to a monitored finance-segment IP"
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Level</label>
            <div className="flex items-center gap-3">
              <input type="number" min={0} value={level} onChange={(e) => setLevel(Number(e.target.value))}
                className="w-20 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300" />
              <SeverityBadge level={level} />
            </div>
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Groups (optional)</label>
            <TagInput values={groups} onChange={setGroups} placeholder="e.g. finance" />
          </div>
        </div>
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
            Owning team (optional)
          </label>
          <select
            value={ownerGroupId}
            onChange={(e) => setOwnerGroupId(e.target.value)}
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
          >
            <option value="">Not assigned — Super Administrator only</option>
            {endpointGroups.map((g) => (
              <option key={g.groupId} value={g.groupId}>{g.name}</option>
            ))}
          </select>
          <p className="mt-1 text-[11px] text-slate-400">
            Lets a Group Admin on this team add/remove IPs on this watch group later. Not related to the free-text
            "Groups" tag above — that's an unrelated rule-categorization label.
          </p>
        </div>
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">
            Event Types <span className="text-red-500">*</span>{' '}
            <span className="font-normal normal-case text-slate-400">— real checkboxes, not the sibling console's comma-separated text field</span>
          </label>
          <CheckboxMultiSelect
            values={eventTypes}
            onChange={setEventTypes}
            options={EVENT_TYPES.map((t) => ({ value: t, label: t }))}
            columns={3}
          />
        </div>
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
            Initial IPs (optional)
          </label>
          <TagInput values={initialIps} onChange={setInitialIps} placeholder="e.g. 10.0.0.5 — Enter or comma to add" />
          <p className="mt-1 text-[11px] text-slate-400">More IPs, and CSV bulk import, are available afterward from this group's "IPs" button.</p>
        </div>
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

function WatchGroupIpsModal({ group, onClose, onChanged }: { group: IpWatchGroup; onClose: () => void; onChanged: () => void }) {
  const [ips, setIps] = useState<string[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newIp, setNewIp] = useState('');
  const [adding, setAdding] = useState(false);
  const [csvSummary, setCsvSummary] = useState<CsvImportSummary | null>(null);
  const [importing, setImporting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await getIpWatchGroupIps(group.name, { page_size: 200 });
      setIps(resp.items);
      setTotal(resp.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load IPs');
    } finally {
      setLoading(false);
    }
  }, [group.name]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    if (!newIp.trim()) return;
    setAdding(true);
    setError(null);
    try {
      const result = await addIpWatchGroupIps(group.name, [newIp.trim()]);
      // The backend returns HTTP 200 even when nothing was actually added
      // (duplicate, invalid syntax, or the group's list is at its entry
      // cap) — added: 0 in all of those cases. Without checking this, a
      // rejected add silently looked identical to a successful one (input
      // cleared, no feedback), which is exactly what made this feature
      // read as broken/impossible to use.
      if (result.added === 0) {
        const reason = result.errors[0]?.reason
          ?? (result.duplicates > 0 ? `"${newIp.trim()}" is already in this group` : 'not added');
        setError(reason);
      } else {
        setNewIp('');
      }
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add IP — is it a valid IPv4/IPv6 address?');
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (ip: string) => {
    try {
      await deleteIpWatchGroupIp(group.name, ip);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove IP');
    }
  };

  const handleCsv = async (file: File) => {
    setImporting(true);
    setError(null);
    setCsvSummary(null);
    try {
      const summary = await importIpWatchGroupCsv(group.name, file);
      setCsvSummary(summary);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'CSV import failed');
    } finally {
      setImporting(false);
    }
  };

  return (
    <Modal title={`IPs in "${group.name}"`} onClose={onClose} wide>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleAdd(); }}
            placeholder="Add a single IPv4 or IPv6 address…"
            className="flex-1 min-w-[220px] rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
          />
          <button onClick={handleAdd} disabled={adding || !newIp.trim()} className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50">
            <Plus className="h-4 w-4" /> Add
          </button>
          <label className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-white/10 px-4 py-2 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-white/5 cursor-pointer">
            <Upload className="h-4 w-4" /> Import CSV
            <input
              type="file"
              accept=".csv,.txt"
              className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleCsv(f); e.target.value = ''; }}
              disabled={importing}
            />
          </label>
        </div>

        {importing && <p className="text-sm text-slate-500 dark:text-slate-400 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Importing…</p>}
        {csvSummary && (
          <div className="rounded-lg bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 p-3 text-sm">
            <p className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-semibold"><CheckCircle2 className="h-4 w-4" /> Added {csvSummary.added}, {csvSummary.duplicates} duplicate(s) skipped</p>
            {csvSummary.skipped.length > 0 && (
              <div className="mt-2 max-h-32 overflow-auto text-xs text-slate-500 dark:text-slate-400">
                {csvSummary.skipped.map((s, i) => (
                  <div key={i} className="flex items-center gap-1.5"><XCircle className="h-3 w-3 text-red-500 shrink-0" /> line {s.line}: "{s.value}" — {s.reason}</div>
                ))}
              </div>
            )}
          </div>
        )}
        {error && <ErrorBanner message={error} />}

        <div className="max-h-80 overflow-auto rounded-lg border border-slate-200 dark:border-white/10">
          {loading ? (
            <div className="p-6 text-center"><InlineSpinner text="Loading…" size="sm" /></div>
          ) : ips.length === 0 ? (
            <div className="p-6 text-center text-sm text-slate-400">No IPs in this list yet</div>
          ) : (
            <table className="w-full text-sm">
              <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                {ips.map((ip) => (
                  <tr key={ip}>
                    <td className="px-3 py-1.5 font-mono text-xs text-slate-700 dark:text-slate-300">{ip}</td>
                    <td className="px-3 py-1.5 text-right">
                      <button onClick={() => handleRemove(ip)} aria-label={`Remove ${ip}`} className="text-slate-400 hover:text-red-500">
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <p className="text-xs text-slate-400">{total} IP{total === 1 ? '' : 's'} total{total > ips.length ? ` (showing first ${ips.length})` : ''}</p>
      </div>
    </Modal>
  );
}
