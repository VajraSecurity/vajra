import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { isAxiosError } from 'axios';
import {
  X, ListPlus, Globe2, Network, Clock, AlertCircle, Users,
} from 'lucide-react';
import { Spinner } from '@/components/ui/loading';
import { createDomainReputationTarget, getDomainReputationInventorySuggestions } from '../../api/api';
import type { DomainReputationGroupScopedProviderStatus, DomainReputationTargetType } from '../../api/api';
import { useModalA11y } from '../../hooks/useModalA11y';
import { SegmentedControl, FancySelect, CheckboxChip, SuggestField } from './ui';
import { useDomainReputationMyGroups } from './useMyGroups';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

const ACCENT = 'rgb(4, 34, 119)';

const CRON_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Every 12 hours', value: '0 */12 * * *' },
  { label: 'Daily at midnight', value: '0 0 * * *' },
  { label: 'Weekly (Sunday midnight)', value: '0 0 * * 0' },
  { label: 'Custom...', value: 'custom' },
];

interface WatchlistModalProps {
  virustotalStatus: DomainReputationGroupScopedProviderStatus | undefined;
  abuseipdbStatus: DomainReputationGroupScopedProviderStatus | undefined;
  onClose: () => void;
  onCreated: () => void;
}

const WatchlistModal = ({ virustotalStatus, abuseipdbStatus, onClose, onCreated }: WatchlistModalProps) => {
  const { myGroups, actableGroups } = useDomainReputationMyGroups();
  const [selectedGroupId, setSelectedGroupId] = useState('');

  const showGroupPicker = !!myGroups && (myGroups.unrestricted ? myGroups.groups.length > 0 : actableGroups.length > 1);
  const groupPickerOptions = myGroups?.unrestricted
    ? [{ value: '', label: 'Organization-wide' }, ...myGroups.groups.map((g) => ({ value: g.group_id, label: g.name }))]
    : actableGroups.map((g) => ({ value: g.group_id, label: g.name }));
  const resolvedGroupId: string | null = showGroupPicker
    ? (selectedGroupId || null)
    : (myGroups && !myGroups.unrestricted && actableGroups.length === 1 ? actableGroups[0].group_id : null);
  // Blocks the modal entirely rather than letting the request 403/400 — unlike
  // Check Now, there's no useful partial action here (a watchlist entry must
  // have exactly one owning scope), so failing closed up front is clearer.
  const noUsableGroup = !!myGroups && !myGroups.unrestricted && actableGroups.length === 0;
  const groupUnresolved = showGroupPicker && !myGroups?.unrestricted && !selectedGroupId;

  const configuredFor = (p: 'virustotal' | 'abuseipdb'): boolean => {
    const status = p === 'virustotal' ? virustotalStatus : abuseipdbStatus;
    return !!status?.configs.find((c) => c.group_id === resolvedGroupId)?.configured;
  };

  const [value, setValue] = useState('');
  const [type, setType] = useState<DomainReputationTargetType>('domain');
  const [providers, setProviders] = useState<string[]>([]);
  const [cronPreset, setCronPreset] = useState(CRON_PRESETS[3].value);
  const [customCron, setCustomCron] = useState('0 0 * * *');
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const modalRef = useModalA11y<HTMLDivElement>(true, onClose);

  useEffect(() => {
    getDomainReputationInventorySuggestions().then((r) => setSuggestions(r.data)).catch(() => setSuggestions([]));
  }, []);

  const toggleProvider = (p: string) => {
    setProviders((prev) => (prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]));
  };

  const handleSubmit = async () => {
    setError(null);
    if (!value.trim()) return setError('Domain or IP is required');
    if (providers.length === 0) return setError('Select at least one provider');
    if (groupUnresolved) return setError('Choose which group this watchlist entry belongs to');
    const cronExpression = cronPreset === 'custom' ? customCron.trim() : cronPreset;
    if (!cronExpression) return setError('Cron expression is required');

    setSaving(true);
    try {
      await createDomainReputationTarget({
        value: value.trim(), type, providers, cronExpression, group_id: resolvedGroupId,
      });
      onCreated();
      onClose();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to add watchlist entry'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <motion.div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="watchlist-modal-title"
        tabIndex={-1}
        initial={{ opacity: 0, y: 12, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: 'spring', bounce: 0.25, duration: 0.4 }}
        className="bg-white rounded-2xl shadow-2xl shadow-slate-900/20 ring-1 ring-black/5 w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto outline-none"
      >
        <div className="flex items-start justify-between mb-5">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-white shadow-sm" style={{ background: ACCENT }}>
              <ListPlus className="h-4 w-4" />
            </div>
            <h3 id="watchlist-modal-title" className="text-lg font-bold text-slate-800">Add to Watchlist</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 rounded-lg p-1 hover:bg-slate-100 transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1">Domain or IP</label>
            <SuggestField
              value={value}
              onChange={setValue}
              items={type === 'domain' ? suggestions : []}
              placeholder={type === 'domain' ? 'example.com' : '8.8.8.8'}
              focusRing="focus-visible:ring-emerald-200"
              icon={type === 'domain' ? <Globe2 className="h-4 w-4" /> : <Network className="h-4 w-4" />}
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1">Type</label>
            <SegmentedControl
              value={type}
              onChange={setType}
              layoutId="watchlistTargetType"
              accent={ACCENT}
              size="sm"
              options={[
                { value: 'domain', label: 'Domain', icon: <Globe2 className="h-3.5 w-3.5" /> },
                { value: 'ip', label: 'IP Address', icon: <Network className="h-3.5 w-3.5" /> },
              ]}
            />
          </div>

          {showGroupPicker && (
            <div>
              <label className="flex items-center gap-1.5 text-xs font-semibold text-slate-600 mb-1">
                <Users className="h-3.5 w-3.5" /> Group
              </label>
              <FancySelect
                value={selectedGroupId}
                onChange={setSelectedGroupId}
                placeholder="Choose a group…"
                focusRing="focus-visible:ring-emerald-200"
                items={groupPickerOptions}
              />
            </div>
          )}

          {noUsableGroup && (
            <div className="flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg px-3 py-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              You don't administer any group, so you can't add a watchlist entry.
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1">Providers</label>
            <div className="flex flex-wrap gap-2.5">
              {(['virustotal', 'abuseipdb'] as const).map((p) => {
                const configured = configuredFor(p);
                return (
                  <CheckboxChip
                    key={p}
                    checked={providers.includes(p)}
                    disabled={!configured}
                    onChange={() => toggleProvider(p)}
                    label={p}
                    hint={!configured ? '(not configured)' : undefined}
                    accent={ACCENT}
                  />
                );
              })}
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1">Check Frequency</label>
            <FancySelect
              value={cronPreset}
              onChange={setCronPreset}
              focusRing="focus-visible:ring-emerald-200"
              items={CRON_PRESETS.map((p) => ({ value: p.value, label: p.label, adornment: <Clock className="h-3.5 w-3.5 text-slate-400" /> }))}
            />
            {cronPreset === 'custom' && (
              <input
                type="text"
                value={customCron}
                onChange={(e) => setCustomCron(e.target.value)}
                placeholder="* * * * *"
                className="mt-2 w-full text-sm border border-slate-200 rounded-lg px-3 py-2 font-mono focus:outline-none focus:ring-2 focus:ring-emerald-200 focus:border-transparent"
              />
            )}
          </div>

          {error && (
            <div className="flex items-center gap-2 text-sm text-red-600 bg-red-50 rounded-lg px-3 py-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {error}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 text-sm font-semibold rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 transition-colors">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving || noUsableGroup}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg text-white shadow-sm disabled:opacity-50 transition-transform hover:-translate-y-0.5 active:translate-y-0"
            style={{ background: ACCENT }}
          >
            {saving ? <Spinner size="sm" /> : <ListPlus className="h-4 w-4" />}
            {saving ? 'Adding…' : 'Add to Watchlist'}
          </button>
        </div>
      </motion.div>
    </div>
  );
};

export default WatchlistModal;
