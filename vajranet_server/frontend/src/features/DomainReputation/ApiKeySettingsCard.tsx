import { useEffect, useState } from 'react';
import { isAxiosError } from 'axios';
import { ShieldCheck, ShieldAlert, KeyRound, Eye, EyeOff, PlugZap, Save, Trash2, CheckCircle2, Circle } from 'lucide-react';
import { DuoSpinner, Spinner } from '@/components/ui/loading';
import {
  saveDomainReputationProviderConfig, testDomainReputationProviderConnection, deleteDomainReputationProviderConfig,
} from '../../api/api';
import type { DomainReputationGroupConfigEntry } from '../../api/api';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

const ACCENT = 'rgb(9, 121, 112)';
const PROVIDER_ICON: Record<'virustotal' | 'abuseipdb', typeof ShieldCheck> = {
  virustotal: ShieldCheck,
  abuseipdb: ShieldAlert,
};

interface ApiKeySettingsCardProps {
  provider: 'virustotal' | 'abuseipdb';
  title: string;
  description: string;
  /** null = this card is the Super Admin org-wide default; otherwise the group this config slot belongs to. */
  groupId: string | null;
  /** Shown under the title — "Organization Default" or the group's name. */
  groupLabel: string;
  status: DomainReputationGroupConfigEntry | null;
  onConfigChange: () => void;
}

const ApiKeySettingsCard = ({ provider, title, description, groupId, groupLabel, status, onConfigChange }: ApiKeySettingsCardProps) => {
  const { showToast } = useToast();
  const confirm = useConfirm();
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const Icon = PROVIDER_ICON[provider];

  // handleSave clears the key on a successful save, but a successful *test*
  // intentionally leaves it in place so the same value can be saved right
  // after without retyping it. To avoid the typed secret lingering in state
  // (and thus the DOM) indefinitely if the user never saves, wipe it when
  // this card unmounts (e.g. the user switches away from the Settings tab).
  useEffect(() => () => setApiKey(''), []);

  const handleTest = async () => {
    const trimmedKey = apiKey.trim();
    if (!trimmedKey && !status?.configured) {
      showToast('Enter an API key to test', 'error');
      return;
    }
    setTesting(true);
    try {
      const result = await testDomainReputationProviderConnection(provider, { ...(trimmedKey ? { api_key: trimmedKey } : {}), group_id: groupId });
      showToast(result.message, result.success ? 'success' : 'error');
    } catch (err) {
      showToast(getErrorMessage(err, 'Connection test failed'), 'error');
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!apiKey) {
      showToast('API key is required', 'error');
      return;
    }
    setSaving(true);
    try {
      await saveDomainReputationProviderConfig(provider, { api_key: apiKey, group_id: groupId });
      setApiKey('');
      onConfigChange();
      showToast(`${title} configuration saved for ${groupLabel}`, 'success');
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to save configuration'), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    const confirmed = await confirm({
      title: `Remove the ${title} configuration for ${groupLabel}?`,
      description: 'The stored API key will be deleted and this scope will no longer be available for reputation checks until reconfigured.',
      confirmLabel: 'Remove',
      variant: 'danger',
    });
    if (!confirmed) return;
    await deleteDomainReputationProviderConfig(provider, groupId);
    onConfigChange();
  };

  return (
    <div className="group relative flex h-full flex-col overflow-hidden bg-white rounded-2xl border border-slate-200 shadow-sm hover:shadow-md hover:border-slate-300 transition-all duration-200 p-5">
      <div
        className="pointer-events-none absolute -top-14 -right-14 h-32 w-32 rounded-full opacity-[0.06] blur-2xl transition-opacity duration-200 group-hover:opacity-[0.1]"
        style={{ background: ACCENT }}
      />

      {/* The status badge only needs to share width with the title, not the
          description below it — putting all three in one flex row reserved
          the badge's width for the description's full height too, choking it
          down to a narrow column even on rows the badge doesn't occupy. So
          the badge shares a row with just the icon+title, and the group
          label + description sit on their own full-width row underneath. */}
      <div className="relative pb-3.5 mb-3.5 border-b border-slate-100">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-white shadow-md ring-4 ring-black/[0.02]"
              style={{ background: `linear-gradient(145deg, ${ACCENT}` }}
            >
              <Icon className="h-4 w-4" strokeWidth={2.25} />
            </div>
            <h3 className="text-sm font-bold text-slate-800 leading-tight truncate">{title}</h3>
          </div>
          <span
            className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
              status?.configured ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-100' : 'bg-slate-100 text-slate-500 ring-1 ring-slate-200'
            }`}
          >
            {status?.configured ? <CheckCircle2 className="h-2.5 w-2.5" /> : <Circle className="h-2.5 w-2.5" />}
            {status?.configured ? 'Configured' : 'Not configured'}
          </span>
        </div>
        <div className="mt-2">
          <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: ACCENT }}>{groupLabel}</p>
          <p className="text-xs text-slate-500 leading-snug mt-0.5">{description}</p>
        </div>
      </div>

      <div className="relative flex flex-1 flex-col justify-between gap-3">
        <div>
          <label className="block text-[11px] font-semibold uppercase tracking-wide text-black dark:text-slate-400 mb-1">
            API Key {status?.api_key_masked ? <span className="normal-case font-normal tracking-normal text-slate-400">(current: {status.api_key_masked})</span> : ''}
          </label>
          <div className="relative">
            <KeyRound className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
            <input
              type={showKey ? 'text' : 'password'}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={status?.api_key_masked ? 'Leave blank to keep current key' : 'Enter API key'}
              className="w-full text-sm border border-slate-200 rounded-lg pl-8 pr-8 py-1.5 transition-shadow focus:outline-none focus:ring-2 focus:ring-emerald-200 focus:border-transparent"
            />
            <button
              type="button"
              onClick={() => setShowKey((v) => !v)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
              tabIndex={-1}
            >
              {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        <div className="flex gap-1.5">
          <button
            onClick={handleTest}
            disabled={testing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 bg-white text-slate-700 shadow-sm hover:bg-slate-50 hover:border-slate-300 disabled:opacity-50 transition-all hover:-translate-y-0.5 active:translate-y-0"
          >
            {testing ? <DuoSpinner size="xs" /> : <PlugZap className="h-3.5 w-3.5" />}
            {testing ? 'Testing…' : 'Test'}
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg text-white shadow-sm disabled:opacity-50 transition-transform hover:-translate-y-0.5 active:translate-y-0"
            style={{ background: ACCENT }}
          >
            {saving ? <Spinner size="xs" /> : <Save className="h-3.5 w-3.5" />}
            {saving ? 'Saving…' : 'Save'}
          </button>
          {status?.configured && (
            <button onClick={handleRemove} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg text-red-600 hover:bg-red-50 ml-auto transition-colors">
              <Trash2 className="h-3.5 w-3.5" />
              Remove
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ApiKeySettingsCard;
