import { useEffect, useState } from 'react';
import { isAxiosError } from 'axios';
import {
  getAiProviderConfig,
  saveAiProviderConfig,
  testAiProviderConfig,
  deleteAiProviderConfig,
  type AiProvider,
  type AiProviderConfigData,
} from '../../api/api';
import { useConfirm } from '../../context/useConfirm';

interface AiProviderSettingsProps {
  onClose: () => void;
}

const PROVIDERS: { value: AiProvider; label: string }[] = [
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'openai', label: 'OpenAI' },
];

const MODEL_OPTIONS: Record<AiProvider, { value: string; label: string }[]> = {
  anthropic: [
    { value: 'claude-opus-4-8', label: 'Claude Opus 4.8 — most capable' },
    { value: 'claude-sonnet-5', label: 'Claude Sonnet 5 — balanced (default)' },
    { value: 'claude-haiku-4-5', label: 'Claude Haiku 4.5 — fastest' },
    { value: 'claude-opus-4-7', label: 'Claude Opus 4.7' },
    { value: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6' },
  ],
  openai: [
    { value: 'gpt-5.6-sol', label: 'GPT-5.6 Sol — frontier, complex professional work' },
    { value: 'gpt-5.6-terra', label: 'GPT-5.6 Terra — balanced intelligence/cost (default)' },
    { value: 'gpt-5.6-luna', label: 'GPT-5.6 Luna — cost-optimized' },
    { value: 'gpt-5.5', label: 'GPT-5.5' },
    { value: 'gpt-5.5-pro', label: 'GPT-5.5 Pro' },
    { value: 'gpt-5.4', label: 'GPT-5.4' },
    { value: 'gpt-5.4-mini', label: 'GPT-5.4 mini' },
    { value: 'gpt-5.4-nano', label: 'GPT-5.4 nano — cheapest, high-volume' },
    { value: 'gpt-5.3-codex', label: 'GPT-5.3 Codex — agentic coding' },
    { value: 'gpt-4o-mini', label: 'GPT-4o mini — legacy' },
  ],
};

const CUSTOM_MODEL = '__custom__';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  return fallback;
}

function inputClass() {
  return 'w-full px-3 py-2 rounded-lg text-sm text-white placeholder-white/30 focus:outline-none focus:ring-2 transition-all';
}

const inputStyle = {
  background: 'rgba(255,255,255,0.06)',
  border: '1px solid rgba(255,255,255,0.12)',
};

const selectStyle = {
  ...inputStyle,
  colorScheme: 'dark' as const,
};

export default function AiProviderSettings({ onClose }: AiProviderSettingsProps) {
  const confirm = useConfirm();
  const [loading, setLoading] = useState(true);
  const [active, setActive] = useState<AiProviderConfigData | null>(null);
  const [editing, setEditing] = useState(false);

  const [provider, setProvider] = useState<AiProvider>('anthropic');
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [model, setModel] = useState('');
  const [customModelMode, setCustomModelMode] = useState(false);
  const [baseUrl, setBaseUrl] = useState('');
  const [organization, setOrganization] = useState('');
  const [maxOutputTokens, setMaxOutputTokens] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAiProviderConfig();
      setActive(res.data);
      setEditing(!res.data);
    } catch {
      setError('Failed to load AI provider configuration.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const startReconfigure = () => {
    const p = active?.provider ?? 'anthropic';
    const m = active?.model ?? '';
    setProvider(p);
    setApiKey('');
    setModel(m);
    setCustomModelMode(!!m && !MODEL_OPTIONS[p].some((o) => o.value === m));
    setBaseUrl(active?.base_url ?? '');
    setOrganization(active?.organization ?? '');
    setMaxOutputTokens(active?.max_output_tokens ? String(active.max_output_tokens) : '');
    setTestResult(null);
    setError(null);
    setSuccess(null);
    setEditing(true);
  };

  const handleProviderChange = (p: AiProvider) => {
    setProvider(p);
    setModel('');
    setCustomModelMode(false);
  };

  const handleModelSelectChange = (value: string) => {
    if (value === CUSTOM_MODEL) {
      setCustomModelMode(true);
      setModel('');
    } else {
      setCustomModelMode(false);
      setModel(value);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    setError(null);
    try {
      const payload = apiKey
        ? { provider, api_key: apiKey, model: model || undefined, base_url: baseUrl || undefined, organization: organization || undefined }
        : undefined; // no raw key entered — test the currently stored config
      const res = await testAiProviderConfig(payload);
      setTestResult(res);
    } catch (err) {
      setTestResult({ success: false, message: getErrorMessage(err, 'Test failed') });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!apiKey) {
      setError('API key is required.');
      return;
    }
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const maxTokensNum = maxOutputTokens ? Number(maxOutputTokens) : undefined;
      await saveAiProviderConfig({
        provider,
        api_key: apiKey,
        model: model || undefined,
        base_url: baseUrl || undefined,
        organization: organization || undefined,
        max_output_tokens: maxTokensNum,
      });
      setSuccess('AI provider configuration saved.');
      await load();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to save configuration.'));
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    const confirmed = await confirm({
      title: 'Remove the AI provider configuration?',
      description: 'The stored API key will be deleted and the AI Assistant will be unavailable for the whole organization until it is reconfigured.',
      confirmLabel: 'Remove',
      variant: 'danger',
    });
    if (!confirmed) return;
    setRemoving(true);
    setError(null);
    try {
      await deleteAiProviderConfig();
      await load();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to remove configuration.'));
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" style={{ background: 'rgba(4,4,10,0.6)', backdropFilter: 'blur(4px)' }}>
      <div
        className="w-full max-w-lg rounded-2xl overflow-hidden"
        style={{ background: 'linear-gradient(160deg, rgba(18,14,38,0.97), rgba(10,8,22,0.97))', border: '1px solid rgba(255,255,255,0.12)', boxShadow: '0 20px 60px rgba(0,0,0,0.5)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
          <div>
            <h2 className="text-sm font-bold text-white">AI Assistant Settings</h2>
            <p className="text-xs text-white/40 mt-0.5">Configure the LLM provider used by the AI Assistant</p>
          </div>
          <button onClick={onClose} className="text-white/40 hover:text-white/80 transition-colors p-1 rounded-lg hover:bg-white/5">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="px-6 py-5 space-y-4 max-h-[70vh] overflow-y-auto">
          {loading ? (
            <div className="text-sm text-white/50 py-6 text-center">Loading…</div>
          ) : !editing && active ? (
            // Read view
            <div className="space-y-4">
              <div className="rounded-xl p-4 space-y-2" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-white/40 uppercase tracking-wide">Provider</span>
                  <span className="text-sm font-semibold text-white capitalize">{active.provider}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-white/40 uppercase tracking-wide">API Key</span>
                  <span className="text-sm font-mono text-white/80">{active.api_key_masked}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-white/40 uppercase tracking-wide">Model</span>
                  <span className="text-sm text-white/80">{active.model || 'Provider default'}</span>
                </div>
                {active.base_url && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-white/40 uppercase tracking-wide">Base URL</span>
                    <span className="text-sm text-white/80 truncate ml-4">{active.base_url}</span>
                  </div>
                )}
                {active.organization && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-white/40 uppercase tracking-wide">Organization</span>
                    <span className="text-sm text-white/80">{active.organization}</span>
                  </div>
                )}
                {active.max_output_tokens && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-white/40 uppercase tracking-wide">Max Output Tokens</span>
                    <span className="text-sm text-white/80">{active.max_output_tokens}</span>
                  </div>
                )}
                {active.created_by_name && (
                  <div className="flex items-center justify-between pt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                    <span className="text-xs text-white/30">Configured by</span>
                    <span className="text-xs text-white/50">{active.created_by_name}</span>
                  </div>
                )}
              </div>

              {error && <div className="text-xs px-3 py-2 rounded-lg bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>}

              <div className="flex gap-2">
                <button
                  onClick={startReconfigure}
                  className="flex-1 text-sm font-semibold px-4 py-2 rounded-lg text-white transition-all"
                  style={{ background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.15)' }}
                >
                  Reconfigure
                </button>
                <button
                  onClick={handleRemove}
                  disabled={removing}
                  className="text-sm font-semibold px-4 py-2 rounded-lg text-red-300 hover:text-red-200 transition-all disabled:opacity-50"
                  style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}
                >
                  {removing ? 'Removing…' : 'Remove'}
                </button>
              </div>
            </div>
          ) : (
            // Edit / setup form
            <div className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-white/50 uppercase tracking-wide mb-1.5 block">Provider</label>
                <div className="flex gap-2">
                  {PROVIDERS.map((p) => (
                    <button
                      key={p.value}
                      onClick={() => handleProviderChange(p.value)}
                      className="flex-1 text-sm font-semibold px-3 py-2 rounded-lg transition-all"
                      style={
                        provider === p.value
                          ? { background: 'rgba(192,132,252,0.2)', border: '1px solid rgba(192,132,252,0.5)', color: 'white' }
                          : { background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.6)' }
                      }
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
<label className="text-xs font-semibold text-white/50 uppercase tracking-wide mb-1.5 block">
  API Key <span className="normal-case font-normal text-white/30">(required)</span>
</label>
                <div className="relative">
                  <input
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={provider === 'anthropic' ? 'sk-ant-...' : 'sk-...'}
                    className={inputClass() + ' pr-16 font-mono'}
                    style={inputStyle}
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey((v) => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg text-xs text-white/40 hover:text-white/70 px-2 py-1"
                  >
                    {showKey ? 'Hide' : 'Show'}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-white/50 uppercase tracking-wide mb-1.5 block">Model <span className="normal-case font-normal text-white/30">(optional)</span></label>
                <select
                  value={customModelMode ? CUSTOM_MODEL : model}
                  onChange={(e) => handleModelSelectChange(e.target.value)}
                  className={inputClass()}
                  style={selectStyle}
                >
                  <option value="" style={{ background: '#1a1430' }}>Provider default</option>
                  {MODEL_OPTIONS[provider].map((o) => (
                    <option key={o.value} value={o.value} style={{ background: '#1a1430' }}>{o.label}</option>
                  ))}
                  <option value={CUSTOM_MODEL} style={{ background: '#1a1430' }}>Custom…</option>
                </select>
                {customModelMode && (
                  <input
                    type="text"
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    placeholder="Enter exact model ID"
                    className={inputClass() + ' mt-2 font-mono'}
                    style={inputStyle}
                    autoFocus
                  />
                )}
              </div>

              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="rounded-lg text-xs text-white/40 hover:text-white/70 transition-colors flex items-center gap-1"
              >
                <svg className={`w-3 h-3 transition-transform ${showAdvanced ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
                Advanced options
              </button>

              {showAdvanced && (
                <div className="space-y-4 pl-3" style={{ borderLeft: '2px solid rgba(255,255,255,0.08)' }}>
                  <div>
                    <label className="text-xs font-semibold text-white/50 uppercase tracking-wide mb-1.5 block">
                      Base URL <span className="normal-case font-normal text-white/30">(custom endpoint / proxy)</span>
                    </label>
                    <input
                      type="text"
                      value={baseUrl}
                      onChange={(e) => setBaseUrl(e.target.value)}
                      placeholder="https://api.example.com/v1"
                      className={inputClass()}
                      style={inputStyle}
                    />
                  </div>

                  {provider === 'openai' && (
                    <div>
                      <label className="text-xs font-semibold text-white/50 uppercase tracking-wide mb-1.5 block">Organization ID</label>
                      <input
                        type="text"
                        value={organization}
                        onChange={(e) => setOrganization(e.target.value)}
                        placeholder="org-..."
                        className={inputClass()}
                        style={inputStyle}
                      />
                    </div>
                  )}

                  <div>
                    <label className="text-xs font-semibold text-white/50 uppercase tracking-wide mb-1.5 block">Max Output Tokens</label>
                    <input
                      type="number"
                      min={1}
                      max={128000}
                      value={maxOutputTokens}
                      onChange={(e) => setMaxOutputTokens(e.target.value)}
                      placeholder="4096 (default)"
                      className={inputClass()}
                      style={inputStyle}
                    />
                  </div>
                </div>
              )}

              {testResult && (
                <div className={`text-xs px-3 py-2 rounded-lg border ${testResult.success ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20' : 'bg-red-500/10 text-red-300 border-red-500/20'}`}>
                  {testResult.message}
                </div>
              )}
              {error && <div className="text-xs px-3 py-2 rounded-lg bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>}
              {success && <div className="text-xs px-3 py-2 rounded-lg bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">{success}</div>}

              <div className="flex gap-2 pt-1">
                {active && (
                  <button
                    onClick={() => { setEditing(false); setError(null); setTestResult(null); }}
                    className="text-sm font-semibold px-4 py-2 rounded-lg text-white/60 hover:text-white transition-all"
                    style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}
                  >
                    Cancel
                  </button>
                )}
                <button
                  onClick={handleTest}
                  disabled={testing || (!apiKey && !active)}
                  className="flex-1 text-sm font-semibold px-4 py-2 rounded-lg text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{ background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.15)' }}
                >
                  {testing ? 'Testing…' : 'Test Connection'}
                </button>
                <button
                  onClick={handleSave}
                  disabled={saving || !apiKey}
                  className="flex-1 text-sm font-semibold px-4 py-2 rounded-lg text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{ background: 'linear-gradient(135deg, #c084fc, #818cf8)' }}
                >
                  {saving ? 'Saving…' : 'Save'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
