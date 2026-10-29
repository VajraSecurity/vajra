import { useEffect, useState } from 'react';
import { isAxiosError } from 'axios';
import {
  ServerCog, Link2, KeyRound, Eye, EyeOff, PlugZap, Save, Trash2,
} from 'lucide-react';
import { Spinner } from '@/components/ui/loading';
import {
  saveDomainReputationProviderConfig, testDomainReputationProviderConnection, deleteDomainReputationProviderConfig,
} from '../../api/api';
import type { DomainReputationGlobalProviderStatus } from '../../api/api';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

const NAVY = 'rgb(4, 34, 119)';

interface ManualServerSettingsProps {
  status: DomainReputationGlobalProviderStatus | null;
  onConfigChange: () => void;
}

const ManualServerSettings = ({ status, onConfigChange }: ManualServerSettingsProps) => {
  const { showToast } = useToast();
  const confirm = useConfirm();
  const [baseUrl, setBaseUrl] = useState(status?.base_url ?? '');
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  // The useState initializer above only runs once at mount, but this card is
  // never unmounted when the config changes (e.g. after Remove) — only its
  // `status` prop updates. Re-sync baseUrl whenever the underlying base_url
  // changes so a Remove (or an external config change) clears the field
  // instead of leaving a stale, re-saveable URL displayed.
  useEffect(() => {
    setBaseUrl(status?.base_url ?? '');
  }, [status?.base_url]);

  // handleSave clears the key on a successful save, but a successful *test*
  // intentionally leaves it in place so the same value can be saved right
  // after without retyping it. To avoid the typed secret lingering in state
  // (and thus the DOM) indefinitely if the user never saves, wipe it when
  // this card unmounts (e.g. the user switches away from the Settings tab).
  useEffect(() => () => setApiKey(''), []);

  // The API key is optional — the manual server doesn't require auth. If a
  // key is entered it's sent as `Authorization: Bearer <token>`; if the field
  // is left blank no auth header is sent at all.
  //
  // api_key is trimmed because that server rejects a token containing
  // whitespace, and a token pasted from a terminal very often carries a
  // trailing newline — which would otherwise be a permanent, unexplained 401.
  const buildPayload = () => {
    const trimmedKey = apiKey.trim();
    const hasStoredKey = Boolean(status?.api_key_masked);
    const authMode: 'bearer' | 'none' = trimmedKey || hasStoredKey ? 'bearer' : 'none';
    return {
      base_url: baseUrl.trim(),
      api_key: trimmedKey || undefined,
      auth_mode: authMode,
    };
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      const result = await testDomainReputationProviderConnection('manual', buildPayload());
      showToast(result.message, result.success ? 'success' : 'error');
    } catch (err) {
      showToast(getErrorMessage(err, 'Connection test failed'), 'error');
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!baseUrl.trim()) {
      showToast('Base URL is required', 'error');
      return;
    }
    setSaving(true);
    try {
      await saveDomainReputationProviderConfig('manual', buildPayload());
      setApiKey('');
      onConfigChange();
      showToast('Vajra Reputation Engine configuration saved', 'success');
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to save configuration'), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    const confirmed = await confirm({
      title: 'Remove the Vajra Reputation Engine configuration?',
      description: 'The stored base URL and API key will be deleted. Vajra Reputation Engine will no longer be available in Check Now until reconfigured.',
      confirmLabel: 'Remove',
      variant: 'danger',
    });
    if (!confirmed) return;
    await deleteDomainReputationProviderConfig('manual');
    onConfigChange();
  };

  return (
    <div className="group relative flex h-full flex-col overflow-hidden bg-white rounded-2xl border border-slate-200 shadow-sm hover:shadow-md hover:border-slate-300 transition-all duration-200 p-5">
      <div
        className="pointer-events-none absolute -top-14 -right-14 h-32 w-32 rounded-full opacity-[0.06] blur-2xl transition-opacity duration-200 group-hover:opacity-[0.1]"
        style={{ background: NAVY }}
      />

      <div className="relative flex items-start gap-3 pb-3.5 mb-3.5 border-b border-slate-100">
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-white shadow-md ring-4 ring-black/[0.02]"
          style={{ background: `linear-gradient(145deg, ${NAVY} 0%, rgb(3, 22, 78) 100%)` }}
        >
          <ServerCog className="h-4 w-4" strokeWidth={2.25} />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-bold text-slate-800 leading-tight">Vajra Reputation Engine</h3>
          <p className="text-xs text-slate-500 leading-snug mt-0.5">
            Self-hosted server, available in Check Now alongside VirusTotal &amp; AbuseIPDB.
          </p>
        </div>
      </div>

      <div className="relative flex flex-1 flex-col justify-between gap-3">
        <div className="space-y-3">
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Server Base URL</label>
            <div className="relative">
              <Link2 className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://manual-server.internal.example.com"
                className="w-full text-sm border border-slate-200 rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-transparent"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">
              API Key <span className="normal-case font-normal tracking-normal text-slate-400">(optional{status?.api_key_masked ? ` — current: ${status.api_key_masked}` : ''})</span>
            </label>
            <div className="relative">
              <KeyRound className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input
                type={showKey ? 'text' : 'password'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={status?.api_key_masked ? 'Leave blank to keep current key' : 'Enter API key (optional)'}
                className="w-full text-sm border border-slate-200 rounded-lg pl-8 pr-8 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-transparent"
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
        </div>

        <div className="flex gap-1.5">
          <button
            onClick={handleTest}
            disabled={testing || !baseUrl.trim()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 bg-white text-slate-700 shadow-sm hover:bg-slate-50 hover:border-slate-300 disabled:opacity-50 transition-all hover:-translate-y-0.5 active:translate-y-0"
          >
            {testing ? <Spinner size="xs" /> : <PlugZap className="h-3.5 w-3.5" />}
            {testing ? 'Testing…' : 'Test'}
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg text-white shadow-sm disabled:opacity-50 transition-transform hover:-translate-y-0.5 active:translate-y-0"
            style={{ background: NAVY }}
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

export default ManualServerSettings;
