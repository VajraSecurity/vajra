import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { isAxiosError } from 'axios';
import {
  listPolicies,
  createPolicyRecord,
  updatePolicyRecord,
  assignPolicyTargets,
  deletePolicyRecord,
  fetchEndpointGroups,
  type PolicyRecord,
  type PolicyTarget,
  type EndpointGroup,
} from '../../../api/api';
import { useToast } from '../../../context/useToast';
import { useModalA11y } from '../../../hooks/useModalA11y';
import { fetchNodesList, type NodeRow } from '../../Responsive/responsiveNodeUtils';
import { getStoredUser } from '../../../services/auth';
import { DuoSpinner } from '@/components/ui/loading';
import { AlertCircle, AlertTriangle, Check, ChevronLeft, ChevronsUpDown, FileText, Lock, Monitor, Plus, Search, SquarePen, Trash2, Users, X } from 'lucide-react';

// Local types

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  return fallback;
}

type PolicyType = 'device-control' | 'network' | 'compliance' | 'custom';
type WizardStep = 'basic' | 'config' | 'targets';

interface PortRuleConfig {
  enabled: boolean;
  action: 'block' | 'allow';
  protocol: 'tcp' | 'udp' | 'both';
  ports: string[];
}

interface IpRuleConfig {
  enabled: boolean;
  action: 'block' | 'allow';
  direction: 'inbound' | 'outbound' | 'both';
  ips: string[];
}

interface UsbConfig {
  enabled: boolean;
  action: 'block' | 'allow';
  scope: 'all' | 'storage-only';
}

interface BluetoothConfig {
  enabled: boolean;
  action: 'block' | 'allow';
}

// Defaults

const defaultPortRules  = (): PortRuleConfig   => ({ enabled: false, action: 'block', protocol: 'tcp',  ports: [] });
const defaultIpRules    = (): IpRuleConfig     => ({ enabled: false, action: 'block', direction: 'both', ips: []  });
const defaultUsb        = (): UsbConfig        => ({ enabled: false, action: 'block', scope: 'all'               });
const defaultBluetooth  = (): BluetoothConfig  => ({ enabled: false, action: 'block'                             });
const defaultTarget     = (): PolicyTarget     => ({ mode: 'none', nodeIds: [], groupIds: []                     });

// Validators

const validatePort = (v: string): string | null => {
  const singleRe = /^([1-9]\d{0,4})$/;
  const rangeRe  = /^([1-9]\d{0,4})-([1-9]\d{0,4})$/;
  const single = singleRe.exec(v);
  if (single) {
    const n = parseInt(v, 10);
    if (n >= 1 && n <= 65535) return null;
    return 'Port must be between 1 and 65535';
  }
  const range = rangeRe.exec(v);
  if (range) {
    const a = parseInt(range[1], 10);
    const b = parseInt(range[2], 10);
    if (a < 1 || b > 65535) return 'Port range must be within 1–65535';
    if (a >= b)              return 'Range start must be less than end (e.g. 8000-9000)';
    return null;
  }
  return 'Enter a port (443) or range (8000-9000)';
};

const validateIp = (v: string): string | null => {
  const oct    = '(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])';
  const ipv4   = `${oct}\\.${oct}\\.${oct}\\.${oct}`;
  const prefix = '([0-9]|[12][0-9]|3[0-2])';
  if (new RegExp(`^${ipv4}$`).test(v))               return null;
  if (new RegExp(`^${ipv4}\\/${prefix}$`).test(v))   return null;
  return 'Enter a valid IP (10.0.0.1) or CIDR range (192.168.1.0/24)';
};

// Display constants

const TYPE_LABELS: Record<PolicyType, string> = {
  'device-control': 'Device Control',
  network:          'Network',
  compliance:       'Compliance',
  custom:           'Custom',
};

const TYPE_COLORS: Record<PolicyType, string> = {
  'device-control': 'bg-purple-100 text-purple-700',
  network:          'bg-teal-100 text-teal-700',
  compliance:       'bg-emerald-100 text-emerald-700',
  custom:           'bg-slate-100 text-slate-600',
};

// Unused constants removed

const WIZARD_STEPS = [
  { key: 'basic'  as WizardStep, label: 'Basic'         },
  { key: 'config' as WizardStep, label: 'Configuration' },
  { key: 'targets'as WizardStep, label: 'Targets'       },
];

// Summary helpers

const getConfigSummary = (p: PolicyRecord): string => {
  if (p.type === 'network') {
    const parts: string[] = [];
    if (p.portRules?.enabled && p.portRules.ports.length > 0) {
      const preview = p.portRules.ports.slice(0, 3).join(', ');
      parts.push(`${p.portRules.action} ports: ${preview}${p.portRules.ports.length > 3 ? '…' : ''}`);
    }
    if (p.ipRules?.enabled && p.ipRules.ips.length > 0) {
      const preview = p.ipRules.ips.slice(0, 2).join(', ');
      parts.push(`${p.ipRules.action} IPs: ${preview}${p.ipRules.ips.length > 2 ? '…' : ''}`);
    }
    return parts.join(' · ') || 'No rules defined';
  }
  if (p.type === 'device-control') {
    const parts: string[] = [];
    if (p.usb?.enabled)       parts.push(`USB: ${p.usb.action} (${p.usb.scope === 'all' ? 'all' : 'storage only'})`);
    if (p.bluetooth?.enabled) parts.push(`Bluetooth: ${p.bluetooth.action}`);
    return parts.join(' · ') || 'No controls configured';
  }
  if (p.type === 'compliance') return p.complianceChecks?.length > 0 ? `${p.complianceChecks.length} check${p.complianceChecks.length === 1 ? '' : 's'} enforced` : 'No checks selected';
  if (p.type === 'custom')     return p.customQuery ? 'Custom rule defined' : 'No query defined';
  return '';
};

const TARGET_ICONS: Record<string, string> = { all: '🌐', nodes: '🖥', groups: '👥', mixed: '🔀', none: '—' };

const getTargetLabel = (t: PolicyTarget) => {
  if (t.mode === 'none') return 'No target';
  if (t.mode === 'all')  return 'All endpoints';
  if (t.mode === 'mixed') return `${t.groupIds.length} group(s) · ${t.nodeIds.length} node(s)`;
  if (t.mode === 'nodes') return `${t.nodeIds.length} node(s)`;
  return `${t.groupIds.length} group(s)`;
};

const isTargetAssigned = (t: PolicyTarget): boolean =>
  t.mode === 'all' || t.nodeIds.length > 0 || t.groupIds.length > 0;

const deriveMode = (nodeIds: string[], groupIds: string[]): PolicyTarget['mode'] => {
  const hasNodes  = nodeIds.length > 0;
  const hasGroups = groupIds.length > 0;
  if (hasNodes && hasGroups) return 'mixed';
  if (hasNodes)              return 'nodes';
  if (hasGroups)             return 'groups';
  return 'none';
};

// TagInput

const TagInput = ({ values, onChange, placeholder, validate }: {
  values: string[];
  onChange: (v: string[]) => void;
  placeholder: string;
  validate?: (v: string) => string | null;
}) => {
  const [input, setInput] = useState('');
  const [err, setErr]     = useState<string | null>(null);

  const add = () => {
    const v = input.trim();
    if (!v) return;
    if (values.includes(v)) { setErr('Already added'); return; }
    if (validate) {
      const msg = validate(v);
      if (msg) { setErr(msg); return; }
    }
    onChange([...values, v]);
    setInput('');
    setErr(null);
  };

  return (
    <div>
      {values.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-2">
          {values.map((v) => (
            <span key={v} className="inline-flex items-center gap-1 text-xs bg-slate-100 text-slate-700 rounded-full px-2.5 py-0.5 font-semibold">
              {v}
              <button type="button" onClick={() => onChange(values.filter((x) => x !== v))} className="rounded-lg text-slate-400 hover:text-slate-600 ml-0.5 leading-none">×</button>
            </span>
          ))}
        </div>
      )}
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => { setInput(e.target.value); setErr(null); }}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
          placeholder={placeholder}
          className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
        />
        <button type="button" onClick={add}
          className="px-3 py-2 text-sm font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 hover:border-slate-400 rounded-lg transition-colors shrink-0">
          Add
        </button>
      </div>
      {err && <p className="mt-1 text-xs text-red-600 font-medium">{err}</p>}
    </div>
  );
};

// Toggle + RadioGroup

const Toggle = ({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    disabled={disabled}
    onClick={() => onChange(!checked)}
    className={`relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${checked ? 'bg-teal-600' : 'bg-slate-200'} ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
  >
    <span className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-4' : 'translate-x-0'}`} />
  </button>
);

const RadioGroup = ({ label, value, onChange, options }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) => (
  <div>
    <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">{label}</p>
    <div className="flex gap-2 flex-wrap">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => onChange(opt.value)}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
            value === opt.value
              ? 'border-slate-700 bg-slate-800 text-white'
              : 'border-slate-200 text-slate-600 hover:border-slate-300 hover:bg-slate-50'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  </div>
);

// AssignmentDrawer — Fortinet-style with sub-panels for groups / nodes

type SubPanel = 'groups' | 'nodes' | null;

interface AssignmentDrawerProps {
  policy: PolicyRecord;
  nodes: NodeRow[];
  groups: EndpointGroup[];
  /** Group Admin can only target their own group's nodes/groups — never "all". */
  allowAllEndpoints: boolean;
  onClose: () => void;
  onSave: (target: PolicyTarget) => Promise<void>;
}

const AssignmentDrawer = ({ policy, nodes, groups, allowAllEndpoints, onClose, onSave }: AssignmentDrawerProps) => {
  const saved       = policy.target ?? defaultTarget();
  const [selNodes,  setSelNodes]  = useState<string[]>(saved.nodeIds);
  const [selGroups, setSelGroups] = useState<string[]>(saved.groupIds);
  const [allMode,   setAllMode]   = useState(saved.mode === 'all');
  const [panel,     setPanel]     = useState<SubPanel>(null);
  const [saving,    setSaving]    = useState(false);

  const [draftNodes,  setDraftNodes]  = useState<string[]>([]);
  const [draftGroups, setDraftGroups] = useState<string[]>([]);
  const [nodeSearch,  setNodeSearch]  = useState('');
  const [groupSearch, setGroupSearch] = useState('');

  useEffect(() => {
    const s = policy.target ?? defaultTarget();
    setSelNodes(s.nodeIds);
    setSelGroups(s.groupIds);
    setAllMode(s.mode === 'all');
    setPanel(null);
    // Intentionally keyed to policy.id only: this resets the drawer's local
    // draft state when the drawer is opened for a *different* policy. Adding
    // policy.target would re-run on every reference change of the same
    // policy's target (e.g. an unrelated parent re-render) and wipe the
    // user's in-progress selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy.id]);

  const openPanel = (p: SubPanel) => {
    if (p === 'nodes')  { setDraftNodes([...selNodes]);  setNodeSearch('');  }
    if (p === 'groups') { setDraftGroups([...selGroups]); setGroupSearch(''); }
    setPanel(p);
  };

  const commitPanel = (p: SubPanel) => {
    if (p === 'nodes')  setSelNodes(draftNodes);
    if (p === 'groups') setSelGroups(draftGroups);
    setPanel(null);
  };

  const removeNode  = (id: string) => setSelNodes((prev) => prev.filter((x) => x !== id));
  const removeGroup = (g: string)  => setSelGroups((prev) => prev.filter((x) => x !== g));

  // The needle is lowercased once instead of once (twice, for nodes) per row —
  // on a large fleet that was two throwaway string allocations per node on
  // every keystroke in the search box.
  const filteredNodes  = useMemo(() => {
    const q = nodeSearch.toLowerCase();
    return nodes.filter((n) =>
      n.hostname?.toLowerCase().includes(q) ||
      n.host_identifier?.toLowerCase().includes(q),
    );
  }, [nodes, nodeSearch]);

  const filteredGroups = useMemo(() => {
    const q = groupSearch.toLowerCase();
    return groups.filter((g) => g.name.toLowerCase().includes(q));
  }, [groups, groupSearch]);

  // Membership sets for the picker rows. Each rendered row tested its id
  // against the draft array twice (checkbox `checked` + the trailing tick), so
  // ticking one box cost O(rows x selected) string compares — the same cost
  // pattern fixed in Management/EndpointManagementTab.tsx.
  const draftNodeSet  = useMemo(() => new Set(draftNodes),  [draftNodes]);
  const draftGroupSet = useMemo(() => new Set(draftGroups), [draftGroups]);

  const handleSave = async () => {
    setSaving(true);
    const nodeIds  = allMode ? [] : selNodes;
    const groupIds = allMode ? [] : selGroups;
    const mode: PolicyTarget['mode'] = allMode ? 'all' : deriveMode(nodeIds, groupIds);
    try { await onSave({ mode, nodeIds, groupIds }); } finally { setSaving(false); }
  };

  const nodeMap = useMemo(() => {
    const m: Record<string, string> = {};
    nodes.forEach((n) => { m[n.host_identifier] = n.hostname || n.host_identifier; });
    return m;
  }, [nodes]);

  const groupIdToName = useMemo(() => {
    const m: Record<string, string> = {};
    groups.forEach((g) => { m[g.groupId] = g.name; });
    return m;
  }, [groups]);

  const hasAssignment = allMode || selNodes.length > 0 || selGroups.length > 0;

  const drawerRef = useModalA11y<HTMLDivElement>(true, onClose);

  return (
    <>
      {/* Backdrop — closes drawer */}
      <div className="fixed inset-0 bg-slate-900/25 z-40" onClick={onClose} />

      {/* Right-side drawer */}
      <motion.div
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="assignment-drawer-title"
        tabIndex={-1}
        initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 28, stiffness: 280 }}
        className="fixed right-0 top-0 h-screen w-full max-w-[420px] bg-white shadow-2xl border-l border-slate-200 z-50 flex flex-col outline-none"
      >
        <div className="flex items-start justify-between px-5 py-4 border-b border-slate-100 shrink-0">
          <div className="min-w-0 pr-3">
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-0.5">Assign Targets</p>
            <h3 id="assignment-drawer-title" className="text-base font-bold text-slate-900 truncate">{policy.name}</h3>
            <span className={`inline-block text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-0.5 mt-1 ${TYPE_COLORS[policy.type as PolicyType]}`}>
              {TYPE_LABELS[policy.type as PolicyType]}
            </span>
          </div>
          <button type="button" onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0 mt-0.5">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* All endpoints toggle — Group Admin can only target their own group */}
          {allowAllEndpoints && (
            <div className={`flex items-center justify-between px-4 py-3 rounded-xl border transition-all ${allMode ? 'border-teal-300 bg-teal-50' : 'border-slate-200 bg-slate-50'}`}>
              <div>
                <p className="text-sm font-semibold text-slate-800">All Endpoints</p>
                <p className="text-xs font-medium text-slate-500 mt-0.5">Apply to every node matching the selected platforms</p>
              </div>
              <Toggle checked={allMode} onChange={(v) => { setAllMode(v); if (v) { setSelNodes([]); setSelGroups([]); } }} />
            </div>
          )}

          {!allMode && (
            <>
              {/* Groups */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Groups</p>
                  <button type="button" onClick={() => openPanel('groups')}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-teal-600 hover:text-teal-700 px-2.5 py-1 rounded-lg hover:bg-teal-50 border border-teal-200 transition-colors">
                    <Plus className="w-3 h-3" strokeWidth={2.5} />
                    Add Groups
                  </button>
                </div>
                {selGroups.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-slate-200 px-4 py-5 text-center">
                    <p className="text-xs font-medium text-slate-400">No groups selected — click Add Groups</p>
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {selGroups.map((g) => (
                      <button key={g} type="button" onClick={() => removeGroup(g)} title="Click to remove"
                        className="inline-flex items-center gap-1.5 text-xs font-semibold bg-slate-800 text-white rounded-full px-3 py-1 hover:bg-red-600 transition-colors group">
                        <Users className="w-3 h-3 opacity-50 group-hover:opacity-100" />
                        {groupIdToName[g] ?? g}
                        <X className="w-2.5 h-2.5 opacity-50 group-hover:opacity-100" strokeWidth={3} />
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Nodes */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Individual Nodes</p>
                  <button type="button" onClick={() => openPanel('nodes')}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-teal-600 hover:text-teal-700 px-2.5 py-1 rounded-lg hover:bg-teal-50 border border-teal-200 transition-colors">
                    <Plus className="w-3 h-3" strokeWidth={2.5} />
                    Add Nodes
                  </button>
                </div>
                {selNodes.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-slate-200 px-4 py-5 text-center">
                    <p className="text-xs font-medium text-slate-400">No nodes selected — click Add Nodes</p>
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {selNodes.map((id) => (
                      <button key={id} type="button" onClick={() => removeNode(id)} title="Click to remove"
                        className="inline-flex items-center gap-1.5 text-xs font-semibold bg-slate-800 text-white rounded-full px-3 py-1 hover:bg-red-600 transition-colors group">
                        <Monitor className="w-3 h-3 opacity-50 group-hover:opacity-100" />
                        {nodeMap[id] ?? id}
                        <X className="w-2.5 h-2.5 opacity-50 group-hover:opacity-100" strokeWidth={3} />
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {(selGroups.length > 0 || selNodes.length > 0) && (
                <div className="rounded-lg bg-slate-50 border border-slate-200 px-3 py-2 text-xs font-medium text-slate-500">
                  {[selGroups.length > 0 && `${selGroups.length} group(s)`, selNodes.length > 0 && `${selNodes.length} node(s)`].filter(Boolean).join(' + ')} selected
                </div>
              )}

              {!hasAssignment && (
                <div className="rounded-lg bg-amber-50 border border-amber-200 px-4 py-3 flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                  <p className="text-xs font-medium text-amber-700">No targets assigned — policy will be saved but cannot be enabled until at least one group or node is assigned.</p>
                </div>
              )}
            </>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 px-5 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
          <button type="button" onClick={onClose} className="px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-200 rounded-lg transition-colors">
            Cancel
          </button>
          <button type="button" onClick={handleSave} disabled={saving}
            className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed">
            {saving ? <><DuoSpinner size="sm" />Saving…</> : 'Save'}
          </button>
        </div>
      </motion.div>

      {/* Groups picker — centered modal above everything */}
      <AnimatePresence>
        {panel === 'groups' && (
          <>
            <div className="fixed inset-0 bg-slate-900/40 z-[60]" onClick={() => setPanel(null)} />
            <motion.div className="fixed inset-0 z-[61] flex items-center justify-center p-6 pointer-events-none">
              <motion.div
                key="groups-modal"
                initial={{ opacity: 0, scale: 0.95, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 8 }}
                transition={{ type: 'spring', damping: 28, stiffness: 320 }}
                className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-lg max-h-[80vh] flex flex-col pointer-events-auto"
              >
                <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 shrink-0">
                  <div className="w-8 h-8 rounded-lg bg-teal-100 text-teal-600 flex items-center justify-center shrink-0">
                    <Users className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-bold text-slate-900">Select Groups</p>
                    <p className="text-xs font-medium text-slate-400">{draftGroups.length} selected</p>
                  </div>
                  <button type="button" onClick={() => setPanel(null)} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="px-5 pt-3 pb-2 shrink-0">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input autoFocus type="text" placeholder="Search groups…" value={groupSearch} onChange={(e) => setGroupSearch(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500" />
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
                  {groups.length === 0 ? (
                    <div className="py-12 text-center"><p className="text-sm font-semibold text-slate-500">No groups available</p></div>
                  ) : filteredGroups.length === 0 ? (
                    <div className="py-8 text-center text-sm font-medium text-slate-400">No groups match</div>
                  ) : filteredGroups.map((g) => (
                    <label key={g.groupId} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 cursor-pointer transition-colors">
                      <input type="checkbox" checked={draftGroupSet.has(g.groupId)} onChange={() => setDraftGroups((p) => p.includes(g.groupId) ? p.filter((x) => x !== g.groupId) : [...p, g.groupId])} className="w-4 h-4 accent-teal-600 shrink-0" />
                      <span className="flex-1 text-sm font-semibold text-slate-800 truncate">{g.name}</span>
                      {draftGroupSet.has(g.groupId) && <Check className="w-4 h-4 text-teal-500 shrink-0" strokeWidth={2.5} />}
                    </label>
                  ))}
                </div>
                <div className="px-5 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
                  <button type="button" onClick={() => commitPanel('groups')}
                    className="w-full py-2.5 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors">
                    Done — {draftGroups.length} group{draftGroups.length !== 1 ? 's' : ''} selected
                  </button>
                </div>
              </motion.div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Nodes picker — centered modal above everything */}
      <AnimatePresence>
        {panel === 'nodes' && (
          <>
            <div className="fixed inset-0 bg-slate-900/40 z-[60]" onClick={() => setPanel(null)} />
            <motion.div className="fixed inset-0 z-[61] flex items-center justify-center p-6 pointer-events-none">
              <motion.div
                key="nodes-modal"
                initial={{ opacity: 0, scale: 0.95, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 8 }}
                transition={{ type: 'spring', damping: 28, stiffness: 320 }}
                className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-lg max-h-[80vh] flex flex-col pointer-events-auto"
              >
                <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 shrink-0">
                  <div className="w-8 h-8 rounded-lg bg-teal-100 text-teal-600 flex items-center justify-center shrink-0">
                    <Monitor className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-bold text-slate-900">Select Nodes</p>
                    <p className="text-xs font-medium text-slate-400">{draftNodes.length} of {nodes.length} selected</p>
                  </div>
                  <button type="button" onClick={() => setPanel(null)} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="px-5 pt-3 pb-2 shrink-0">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input autoFocus type="text" placeholder="Search by hostname or host ID…" value={nodeSearch} onChange={(e) => setNodeSearch(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500" />
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
                  {nodes.length === 0 ? (
                    <div className="py-12 text-center"><p className="text-sm font-semibold text-slate-500">No nodes available</p></div>
                  ) : filteredNodes.length === 0 ? (
                    <div className="py-8 text-center text-sm font-medium text-slate-400">No nodes match</div>
                  ) : filteredNodes.slice(0, 100).map((n) => (
                    <label key={n.host_identifier} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 cursor-pointer transition-colors">
                      <input type="checkbox" checked={draftNodeSet.has(n.host_identifier)} onChange={() => setDraftNodes((p) => p.includes(n.host_identifier) ? p.filter((x) => x !== n.host_identifier) : [...p, n.host_identifier])} className="w-4 h-4 accent-teal-600 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-slate-800 truncate">{n.hostname || n.host_identifier}</p>
                        {n.hostname && <p className="text-xs font-medium text-slate-400 truncate">{n.host_identifier}</p>}
                      </div>
                      {draftNodeSet.has(n.host_identifier) && <Check className="w-4 h-4 text-teal-500 shrink-0" strokeWidth={2.5} />}
                    </label>
                  ))}
                  {filteredNodes.length > 100 && (
                    <p className="text-xs font-medium text-slate-400 text-center py-3">Showing 100 of {filteredNodes.length} — refine search</p>
                  )}
                </div>
                <div className="px-5 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
                  <button type="button" onClick={() => commitPanel('nodes')}
                    className="w-full py-2.5 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors">
                    Done — {draftNodes.length} node{draftNodes.length !== 1 ? 's' : ''} selected
                  </button>
                </div>
              </motion.div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
};

// EditPolicyModal

type PolicyConfigUpdate = Partial<Pick<PolicyRecord, 'name' | 'description' | 'platforms' | 'portRules' | 'ipRules' | 'usb' | 'bluetooth' | 'complianceChecks' | 'customQuery'>>;

interface EditPolicyModalProps {
  policy: PolicyRecord | null;
  isOpen: boolean;
  onClose: () => void;
  onSaved: (id: string, update: PolicyConfigUpdate) => Promise<void>;
}

const EditPolicyModal = ({ policy, isOpen, onClose, onSaved }: EditPolicyModalProps) => {
  const [submitting,       setSubmitting]       = useState(false);
  const [name,             setName]             = useState('');
  const [description,      setDescription]      = useState('');
  const [platforms,        setPlatforms]        = useState<string[]>([]);
  const [portRules,        setPortRules]        = useState<PortRuleConfig>(defaultPortRules());
  const [ipRules,          setIpRules]          = useState<IpRuleConfig>(defaultIpRules());
  const [usb,              setUsb]              = useState<UsbConfig>(defaultUsb());
  const [bluetooth,        setBluetooth]        = useState<BluetoothConfig>(defaultBluetooth());
  const [complianceChecks, setComplianceChecks] = useState<string[]>([]);
  const [customQuery,      setCustomQuery]      = useState('');

  useEffect(() => {
    if (policy) {
      setName(policy.name);
      setDescription(policy.description ?? '');
      setPlatforms(policy.platforms ?? []);
      setPortRules(policy.portRules  ?? defaultPortRules());
      setIpRules(policy.ipRules      ?? defaultIpRules());
      setUsb(policy.usb              ?? defaultUsb());
      setBluetooth(policy.bluetooth  ?? defaultBluetooth());
      setComplianceChecks(policy.complianceChecks ?? []);
      setCustomQuery(policy.customQuery ?? '');
    }
    // Intentionally keyed to policy?.id only: this seeds the form's local
    // state when the modal opens for a *different* policy. Adding the full
    // policy object would re-run on every reference change (e.g. an
    // unrelated parent re-render) and wipe the user's in-progress edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy?.id]);

  useEffect(() => { if (!isOpen) setSubmitting(false); }, [isOpen]);

  // useModalA11y's Escape handler only (re)runs when `isOpen` changes, not on
  // every render (see useModalA11y.ts) — a plain `if (!submitting) onClose()`
  // closure here would close over the stale `submitting` from mount and let
  // Escape close the modal mid-save even though the X/Cancel buttons block it.
  // Mirror it in a ref so the callback always reads the live value.
  const submittingRef = useRef(submitting);
  useEffect(() => { submittingRef.current = submitting; }, [submitting]);

  const modalRef = useModalA11y<HTMLDivElement>(isOpen, () => { if (!submittingRef.current) onClose(); });

  const togglePlatform = (p: string) =>
    setPlatforms((prev) => prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]);

  const handleSave = async () => {
    if (!policy || !name.trim()) return;
    const { type } = policy;
    setSubmitting(true);
    try {
      await onSaved(policy.id, {
        name:        name.trim(),
        description: description.trim(),
        platforms,
        ...(type === 'network'        ? { portRules, ipRules }              : {}),
        ...(type === 'device-control' ? { usb, bluetooth }                  : {}),
        ...(type === 'compliance'     ? { complianceChecks }                : {}),
        ...(type === 'custom'         ? { customQuery: customQuery.trim() } : {}),
      });
      onClose();
    } catch {
      // error toasted by caller — keep modal open
    } finally {
      setSubmitting(false);
    }
  };

  if (!policy) return null;
  const { type } = policy;

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <motion.div
            ref={modalRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="edit-policy-modal-title"
            tabIndex={-1}
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            className="bg-white rounded-2xl shadow-xl border border-slate-200 w-full max-w-2xl flex flex-col max-h-[90vh] overflow-hidden outline-none"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-amber-100 text-amber-600 flex items-center justify-center shrink-0">
                  <SquarePen className="w-5 h-5" />
                </div>
                <div>
                  <h2 id="edit-policy-modal-title" className="text-lg font-bold text-slate-900">Edit Policy</h2>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span className={`text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-0.5 ${TYPE_COLORS[type as PolicyType]}`}>
                      {TYPE_LABELS[type as PolicyType]}
                    </span>
                    <span className="text-[10px] font-medium text-slate-400">· type is locked after creation</span>
                  </div>
                </div>
              </div>
              <button type="button" onClick={() => { if (!submitting) onClose(); }} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5">
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1.5">Policy name *</label>
                <input autoFocus type="text"
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                  value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1.5">Target platforms</label>
                <div className="flex gap-2">
                  {(['windows', 'linux', 'macos'] as const).map((p) => (
                    <button key={p} type="button" onClick={() => togglePlatform(p)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all capitalize ${
                        platforms.includes(p)
                          ? 'border-slate-700 bg-slate-800 text-white'
                          : 'border-slate-200 text-slate-500 hover:border-slate-300'
                      }`}>
                      {p}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1.5">Description</label>
                <textarea rows={2}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500 resize-none"
                  value={description} onChange={(e) => setDescription(e.target.value)} />
              </div>

              {type === 'network' && (
                <div className="space-y-4">
                  <p className="text-xs font-bold uppercase tracking-widest text-slate-400">Network Rules</p>
                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">Port Rules</p>
                        <p className="text-xs font-medium text-slate-400">Block or allow specific TCP/UDP ports</p>
                      </div>
                      <Toggle checked={portRules.enabled} onChange={(v) => setPortRules((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {portRules.enabled && (
                      <div className="p-4 space-y-4">
                        <RadioGroup label="Action"   value={portRules.action}   onChange={(v) => setPortRules((p) => ({ ...p, action: v as PortRuleConfig['action'] }))}   options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                        <RadioGroup label="Protocol" value={portRules.protocol} onChange={(v) => setPortRules((p) => ({ ...p, protocol: v as PortRuleConfig['protocol'] }))} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'both', label: 'Both' }]} />
                        <div>
                          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Ports / Ranges</p>
                          <TagInput values={portRules.ports} onChange={(v) => setPortRules((p) => ({ ...p, ports: v }))} placeholder="80, 443, 8000-9000…" validate={validatePort} />
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">IP Rules</p>
                        <p className="text-xs font-medium text-slate-400">Block or allow IP addresses and CIDR ranges</p>
                      </div>
                      <Toggle checked={ipRules.enabled} onChange={(v) => setIpRules((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {ipRules.enabled && (
                      <div className="p-4 space-y-4">
                        <RadioGroup label="Action"    value={ipRules.action}    onChange={(v) => setIpRules((p) => ({ ...p, action: v as IpRuleConfig['action'] }))}       options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                        <RadioGroup label="Direction" value={ipRules.direction} onChange={(v) => setIpRules((p) => ({ ...p, direction: v as IpRuleConfig['direction'] }))} options={[{ value: 'inbound', label: 'Inbound' }, { value: 'outbound', label: 'Outbound' }, { value: 'both', label: 'Both' }]} />
                        <div>
                          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">IP Addresses / CIDR Ranges</p>
                          <TagInput values={ipRules.ips} onChange={(v) => setIpRules((p) => ({ ...p, ips: v }))} placeholder="10.0.0.1, 192.168.1.0/24…" validate={validateIp} />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {type === 'device-control' && (
                <div className="space-y-4">
                  <p className="text-xs font-bold uppercase tracking-widest text-slate-400">Device Control</p>
                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">USB Control</p>
                        <p className="text-xs font-medium text-slate-400">Control USB device access on endpoints</p>
                      </div>
                      <Toggle checked={usb.enabled} onChange={(v) => setUsb((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {usb.enabled && (
                      <div className="p-4 space-y-4">
                        <RadioGroup label="Action" value={usb.action} onChange={(v) => setUsb((p) => ({ ...p, action: v as UsbConfig['action'] }))} options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                        <RadioGroup label="Scope"  value={usb.scope}  onChange={(v) => setUsb((p) => ({ ...p, scope: v as UsbConfig['scope'] }))}   options={[{ value: 'all', label: 'All USB devices' }, { value: 'storage-only', label: 'Storage devices only' }]} />
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">Bluetooth Control</p>
                        <p className="text-xs font-medium text-slate-400">Enable or disable Bluetooth on endpoints</p>
                      </div>
                      <Toggle checked={bluetooth.enabled} onChange={(v) => setBluetooth((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {bluetooth.enabled && (
                      <div className="p-4">
                        <RadioGroup label="Action" value={bluetooth.action} onChange={(v) => setBluetooth((p) => ({ ...p, action: v as BluetoothConfig['action'] }))} options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                      </div>
                    )}
                  </div>
                </div>
              )}

            </div>

            {/* Footer */}
            <div className="flex items-center justify-between px-6 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
              <button type="button" onClick={() => { if (!submitting) onClose(); }}
                className="px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-200 rounded-lg transition-colors">
                Cancel
              </button>
              <button type="button" onClick={handleSave} disabled={submitting || !name.trim()}
                className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed">
                {submitting ? (
                  <><DuoSpinner size="sm" />Saving…</>
                ) : 'Save Changes'}
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

// CreatePolicyModal — 3-step wizard

interface CreatePolicyModalProps {
  isOpen: boolean;
  nodes: NodeRow[];
  groups: EndpointGroup[];
  /** Group Admin can only target their own group's nodes/groups — never "all". */
  allowAllEndpoints: boolean;
  onClose: () => void;
  onCreated: (draft: Omit<PolicyRecord, 'id' | 'createdAt' | 'updatedAt' | 'createdBy' | 'canManage'>) => Promise<void>;
}

const CreatePolicyModal = ({ isOpen, nodes, groups, allowAllEndpoints, onClose, onCreated }: CreatePolicyModalProps) => {
  const [step,       setStep]       = useState<WizardStep>('basic');
  const [submitting, setSubmitting] = useState(false);

  // Step 1
  const [name,        setName]        = useState('');
  const [description, setDescription] = useState('');
  const [platforms,   setPlatforms]   = useState<string[]>(['windows', 'linux']);

  // Step 2 — network + device-control rules
  const [portRules,  setPortRules]  = useState<PortRuleConfig>(defaultPortRules());
  const [ipRules,    setIpRules]    = useState<IpRuleConfig>(defaultIpRules());
  const [usb,        setUsb]        = useState<UsbConfig>(defaultUsb());
  const [bluetooth,  setBluetooth]  = useState<BluetoothConfig>(defaultBluetooth());

  // Step 3 — target selection (Fortinet-style sub-panels)
  const [tAllMode,     setTAllMode]     = useState(false);
  const [tSelNodes,    setTSelNodes]    = useState<string[]>([]);
  const [tSelGroups,   setTSelGroups]   = useState<string[]>([]);
  const [tPanel,       setTPanel]       = useState<SubPanel>(null);
  const [tDraftNodes,  setTDraftNodes]  = useState<string[]>([]);
  const [tDraftGroups, setTDraftGroups] = useState<string[]>([]);
  const [tNodeSearch,  setTNodeSearch]  = useState('');
  const [tGroupSearch, setTGroupSearch] = useState('');

  const tNodeMap = useMemo(() => {
    const m: Record<string, string> = {};
    nodes.forEach((n) => { m[n.host_identifier] = n.hostname || n.host_identifier; });
    return m;
  }, [nodes]);

  const tGroupIdToName = useMemo(() => {
    const m: Record<string, string> = {};
    groups.forEach((g) => { m[g.groupId] = g.name; });
    return m;
  }, [groups]);

  const tFilteredNodes  = useMemo(() =>
    nodes.filter((n) =>
      n.hostname?.toLowerCase().includes(tNodeSearch.toLowerCase()) ||
      n.host_identifier?.toLowerCase().includes(tNodeSearch.toLowerCase()),
    ), [nodes, tNodeSearch]);

  const tFilteredGroups = useMemo(() =>
    groups.filter((g) => g.name.toLowerCase().includes(tGroupSearch.toLowerCase())),
    [groups, tGroupSearch]);

  const reset = useCallback(() => {
    setStep('basic');
    setName(''); setDescription(''); setPlatforms(['windows', 'linux']);
    setPortRules(defaultPortRules()); setIpRules(defaultIpRules());
    setUsb(defaultUsb()); setBluetooth(defaultBluetooth());
    setTAllMode(allowAllEndpoints); setTSelNodes([]); setTSelGroups([]);
    setTPanel(null); setTDraftNodes([]); setTDraftGroups([]);
    setTNodeSearch(''); setTGroupSearch('');
    setSubmitting(false);
  }, [allowAllEndpoints]);

  useEffect(() => { if (!isOpen) reset(); }, [isOpen, reset]);

  const modalRef = useModalA11y<HTMLDivElement>(isOpen, () => { reset(); onClose(); });

  const togglePlatform = (p: string) =>
    setPlatforms((prev) => prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]);

  // Enabled toggles must also have at least one entry; USB/Bluetooth just need the toggle on
  const canProceedFromConfig = (): boolean => {
    const portOk = portRules.enabled && portRules.ports.length > 0;
    const ipOk   = ipRules.enabled   && ipRules.ips.length   > 0;
    const usbOk  = usb.enabled;
    const btOk   = bluetooth.enabled;
    return portOk || ipOk || usbOk || btOk;
  };

  // Auto-determine type from what's configured (network takes priority)
  const computeType = (): PolicyType => {
    const portOk = portRules.enabled && portRules.ports.length > 0;
    const ipOk   = ipRules.enabled   && ipRules.ips.length   > 0;
    if (portOk || ipOk) return 'network';
    return 'device-control';
  };

  const handleCreate = async () => {
    setSubmitting(true);
    const targetNodeIds  = tAllMode ? [] : tSelNodes;
    const targetGroupIds = tAllMode ? [] : tSelGroups;
    const targetMode     = tAllMode ? 'all' : deriveMode(targetNodeIds, targetGroupIds);
    const targetObj      = { mode: targetMode, nodeIds: targetNodeIds, groupIds: targetGroupIds };
    try {
      await onCreated({
        name:             name.trim(),
        type:             computeType(),
        description:      description.trim(),
        enabled:          isTargetAssigned(targetObj),
        platforms,
        portRules,
        ipRules,
        usb,
        bluetooth,
        complianceChecks: [],
        customQuery:      '',
        target:           targetObj,
      });
      reset();
      onClose();
    } catch {
      // error toasted by caller
    } finally {
      setSubmitting(false);
    }
  };

  const stepIndex = WIZARD_STEPS.findIndex((s) => s.key === step);

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <motion.div
            ref={modalRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-policy-modal-title"
            tabIndex={-1}
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            className="relative bg-white rounded-2xl shadow-xl border border-slate-200 w-full max-w-2xl flex flex-col max-h-[90vh] overflow-hidden outline-none"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-teal-100 text-teal-600 flex items-center justify-center shrink-0">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <h2 id="create-policy-modal-title" className="text-lg font-bold text-slate-900">Create Policy</h2>
                  <p className="text-xs font-medium text-slate-500">Define an enforcement rule for your endpoints</p>
                </div>
              </div>
              <button type="button" onClick={() => { reset(); onClose(); }} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Step indicator */}
            <div className="flex items-center gap-2 px-6 py-3 border-b border-slate-100 shrink-0">
              {WIZARD_STEPS.map((s, i) => {
                const isCurrent = step === s.key;
                const isDone    = i < stepIndex;
                return (
                  <div key={s.key} className="flex items-center gap-2">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${isDone ? 'bg-emerald-500 text-white' : isCurrent ? 'bg-teal-600 text-white' : 'bg-slate-100 text-slate-400'}`}>
                      {isDone ? (
                        <Check className="w-3 h-3" strokeWidth={3} />
                      ) : i + 1}
                    </div>
                    <span className={`text-xs font-semibold ${isCurrent ? 'text-slate-900' : 'text-slate-400'}`}>{s.label}</span>
                    {i < WIZARD_STEPS.length - 1 && <span className="text-slate-200 ml-1">›</span>}
                  </div>
                );
              })}
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5">

              {/* Step 1 — Basic */}
              {step === 'basic' && (
                <>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5">Policy name *</label>
                    <input autoFocus type="text" placeholder="e.g. Block USB Storage on Finance Laptops"
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                      value={name} onChange={(e) => setName(e.target.value)} />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5">Target platforms</label>
                    <div className="flex gap-2">
                      {['windows', 'linux', 'macos'].map((p) => (
                        <button key={p} type="button" onClick={() => togglePlatform(p)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all capitalize ${
                            platforms.includes(p) ? 'border-slate-700 bg-slate-800 text-white' : 'border-slate-200 text-slate-500 hover:border-slate-300'
                          }`}>
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5">Description</label>
                    <textarea rows={2} placeholder="Optional description…"
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500 resize-none"
                      value={description} onChange={(e) => setDescription(e.target.value)} />
                  </div>
                </>
              )}

              {/* Step 2 — Configuration (all rule types on one page) */}
              {step === 'config' && (
                <div className="space-y-4">
                  <p className="text-xs font-medium text-slate-400">Enable at least one rule and add entries (for port/IP rules) to proceed.</p>

                  {/* ─ Network ─ */}
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 pt-1">Network</p>

                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">Port Rules</p>
                        <p className="text-xs font-medium text-slate-400">Block or allow specific TCP/UDP ports</p>
                      </div>
                      <Toggle checked={portRules.enabled} onChange={(v) => setPortRules((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {portRules.enabled && (
                      <div className="p-4 space-y-4">
                        <RadioGroup label="Action"   value={portRules.action}   onChange={(v) => setPortRules((p) => ({ ...p, action: v as PortRuleConfig['action'] }))}   options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                        <RadioGroup label="Protocol" value={portRules.protocol} onChange={(v) => setPortRules((p) => ({ ...p, protocol: v as PortRuleConfig['protocol'] }))} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'both', label: 'Both' }]} />
                        <div>
                          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Ports / Ranges</p>
                          <TagInput values={portRules.ports} onChange={(v) => setPortRules((p) => ({ ...p, ports: v }))} placeholder="80, 443, 8000-9000…" validate={validatePort} />
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">IP Rules</p>
                        <p className="text-xs font-medium text-slate-400">Block or allow IP addresses and CIDR ranges</p>
                      </div>
                      <Toggle checked={ipRules.enabled} onChange={(v) => setIpRules((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {ipRules.enabled && (
                      <div className="p-4 space-y-4">
                        <RadioGroup label="Action"    value={ipRules.action}    onChange={(v) => setIpRules((p) => ({ ...p, action: v as IpRuleConfig['action'] }))}       options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                        <RadioGroup label="Direction" value={ipRules.direction} onChange={(v) => setIpRules((p) => ({ ...p, direction: v as IpRuleConfig['direction'] }))} options={[{ value: 'inbound', label: 'Inbound' }, { value: 'outbound', label: 'Outbound' }, { value: 'both', label: 'Both' }]} />
                        <div>
                          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">IP Addresses / CIDR Ranges</p>
                          <TagInput values={ipRules.ips} onChange={(v) => setIpRules((p) => ({ ...p, ips: v }))} placeholder="10.0.0.1, 192.168.1.0/24…" validate={validateIp} />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* ─ Device Control ─ */}
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 pt-2">Device Control</p>

                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">USB Control</p>
                        <p className="text-xs font-medium text-slate-400">Control USB device access on endpoints</p>
                      </div>
                      <Toggle checked={usb.enabled} onChange={(v) => setUsb((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {usb.enabled && (
                      <div className="p-4 space-y-4">
                        <RadioGroup label="Action" value={usb.action} onChange={(v) => setUsb((p) => ({ ...p, action: v as UsbConfig['action'] }))} options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                        <RadioGroup label="Scope"  value={usb.scope}  onChange={(v) => setUsb((p) => ({ ...p, scope: v as UsbConfig['scope'] }))}   options={[{ value: 'all', label: 'All USB devices' }, { value: 'storage-only', label: 'Storage devices only' }]} />
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-100">
                      <div>
                        <p className="text-sm font-semibold text-slate-800">Bluetooth Control</p>
                        <p className="text-xs font-medium text-slate-400">Enable or disable Bluetooth on endpoints</p>
                      </div>
                      <Toggle checked={bluetooth.enabled} onChange={(v) => setBluetooth((p) => ({ ...p, enabled: v }))} />
                    </div>
                    {bluetooth.enabled && (
                      <div className="p-4">
                        <RadioGroup label="Action" value={bluetooth.action} onChange={(v) => setBluetooth((p) => ({ ...p, action: v as BluetoothConfig['action'] }))} options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
                      </div>
                    )}
                  </div>

                </div>
              )}

              {/* Step 3 — Targets */}
              {step === 'targets' && (
                <div className="space-y-6">
                  {/* All endpoints toggle — Group Admin can only target their own group */}
                  {allowAllEndpoints && (
                    <div className={`flex items-center justify-between px-4 py-3 rounded-xl border transition-all ${tAllMode ? 'border-teal-300 bg-teal-50' : 'border-slate-200 bg-slate-50'}`}>
                      <div>
                        <p className="text-sm font-semibold text-slate-800">All Endpoints</p>
                        <p className="text-xs font-medium text-slate-500 mt-0.5">Apply to every node matching the selected platforms</p>
                      </div>
                      <Toggle checked={tAllMode} onChange={(v) => { setTAllMode(v); if (v) { setTSelNodes([]); setTSelGroups([]); } }} />
                    </div>
                  )}

                  {!tAllMode && (
                    <>
                      {/* Groups */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Groups</p>
                          <button type="button" onClick={() => { setTDraftGroups([...tSelGroups]); setTGroupSearch(''); setTPanel('groups'); }}
                            className="inline-flex items-center gap-1 text-xs font-semibold text-teal-600 hover:text-teal-700 px-2.5 py-1 rounded-lg hover:bg-teal-50 border border-teal-200 transition-colors">
                            <Plus className="w-3 h-3" strokeWidth={2.5} />
                            Add Groups
                          </button>
                        </div>
                        {tSelGroups.length === 0 ? (
                          <div className="rounded-lg border border-dashed border-slate-200 px-4 py-5 text-center">
                            <p className="text-xs font-medium text-slate-400">No groups selected — click Add Groups</p>
                          </div>
                        ) : (
                          <div className="flex flex-wrap gap-1.5">
                            {tSelGroups.map((g) => (
                              <button key={g} type="button" onClick={() => setTSelGroups((p) => p.filter((x) => x !== g))} title="Click to remove"
                                className="inline-flex items-center gap-1.5 text-xs font-semibold bg-slate-800 text-white rounded-full px-3 py-1 hover:bg-red-600 transition-colors group">
                                <Users className="w-3 h-3 opacity-50 group-hover:opacity-100" />
                                {tGroupIdToName[g] ?? g}
                                <X className="w-2.5 h-2.5 opacity-50 group-hover:opacity-100" strokeWidth={3} />
                              </button>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Nodes */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Individual Nodes</p>
                          <button type="button" onClick={() => { setTDraftNodes([...tSelNodes]); setTNodeSearch(''); setTPanel('nodes'); }}
                            className="inline-flex items-center gap-1 text-xs font-semibold text-teal-600 hover:text-teal-700 px-2.5 py-1 rounded-lg hover:bg-teal-50 border border-teal-200 transition-colors">
                            <Plus className="w-3 h-3" strokeWidth={2.5} />
                            Add Nodes
                          </button>
                        </div>
                        {tSelNodes.length === 0 ? (
                          <div className="rounded-lg border border-dashed border-slate-200 px-4 py-5 text-center">
                            <p className="text-xs font-medium text-slate-400">No nodes selected — click Add Nodes</p>
                          </div>
                        ) : (
                          <div className="flex flex-wrap gap-1.5">
                            {tSelNodes.map((id) => (
                              <button key={id} type="button" onClick={() => setTSelNodes((p) => p.filter((x) => x !== id))} title="Click to remove"
                                className="inline-flex items-center gap-1.5 text-xs font-semibold bg-slate-800 text-white rounded-full px-3 py-1 hover:bg-red-600 transition-colors group">
                                <Monitor className="w-3 h-3 opacity-50 group-hover:opacity-100" />
                                {tNodeMap[id] ?? id}
                                <X className="w-2.5 h-2.5 opacity-50 group-hover:opacity-100" strokeWidth={3} />
                              </button>
                            ))}
                          </div>
                        )}
                      </div>

                      {(tSelGroups.length > 0 || tSelNodes.length > 0) && (
                        <div className="rounded-lg bg-slate-50 border border-slate-200 px-3 py-2 text-xs font-medium text-slate-500">
                          {[tSelGroups.length > 0 && `${tSelGroups.length} group(s)`, tSelNodes.length > 0 && `${tSelNodes.length} node(s)`].filter(Boolean).join(' + ')} selected
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between px-6 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
              <button type="button"
                onClick={() => {
                  if (step === 'basic')         { reset(); onClose(); }
                  else if (step === 'config')   setStep('basic');
                  else                          setStep('config');
                }}
                className="px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-200 rounded-lg transition-colors"
              >
                {step === 'basic' ? 'Cancel' : '← Back'}
              </button>

              {step === 'basic' && (
                <button type="button" disabled={!name.trim() || platforms.length === 0} onClick={() => setStep('config')}
                  className="px-4 py-2 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                  Next →
                </button>
              )}
              {step === 'config' && (
                <button type="button" disabled={!canProceedFromConfig()} onClick={() => setStep('targets')}
                  className="px-4 py-2 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                  Next →
                </button>
              )}
              {step === 'targets' && (
                <button type="button" onClick={handleCreate} disabled={submitting}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                  style={{ background: 'linear-gradient(135deg, rgb(9, 121, 112) 0%, rgb(13, 148, 136) 100%)' }}
                >
                  {submitting ? (
                    <><DuoSpinner size="sm" />Creating…</>
                  ) : 'Create Policy'}
                </button>
              )}
            </div>

            {/* Sub-panel: Groups picker (slides over entire modal) */}
            <AnimatePresence>
              {tPanel === 'groups' && (
                <motion.div key="t-groups" initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
                  transition={{ type: 'spring', damping: 30, stiffness: 300 }}
                  className="absolute inset-0 z-20 bg-white rounded-2xl flex flex-col">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 shrink-0">
                    <button type="button" onClick={() => setTPanel(null)} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0">
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-bold text-slate-900">Select Groups</p>
                      <p className="text-xs font-medium text-slate-400">{tDraftGroups.length} selected</p>
                    </div>
                    <button type="button" onClick={() => setTPanel(null)} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="px-5 pt-3 pb-2 shrink-0">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                      <input type="text" placeholder="Search groups…" value={tGroupSearch} onChange={(e) => setTGroupSearch(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500" />
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
                    {groups.length === 0 ? (
                      <div className="py-12 text-center"><p className="text-sm font-semibold text-slate-500">No groups available</p></div>
                    ) : tFilteredGroups.length === 0 ? (
                      <div className="py-8 text-center text-sm font-medium text-slate-400">No groups match</div>
                    ) : tFilteredGroups.map((g) => (
                      <label key={g.groupId} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 cursor-pointer transition-colors">
                        <input type="checkbox" checked={tDraftGroups.includes(g.groupId)} onChange={() => setTDraftGroups((p) => p.includes(g.groupId) ? p.filter((x) => x !== g.groupId) : [...p, g.groupId])} className="w-4 h-4 accent-teal-600 shrink-0" />
                        <span className="flex-1 text-sm font-semibold text-slate-800 truncate">{g.name}</span>
                        {tDraftGroups.includes(g.groupId) && <Check className="w-4 h-4 text-teal-500 shrink-0" strokeWidth={2.5} />}
                      </label>
                    ))}
                  </div>
                  <div className="px-5 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
                    <button type="button" onClick={() => { setTSelGroups(tDraftGroups); setTPanel(null); }}
                      className="w-full py-2.5 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors">
                      Done — {tDraftGroups.length} group{tDraftGroups.length !== 1 ? 's' : ''} selected
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Sub-panel: Nodes picker (slides over entire modal) */}
            <AnimatePresence>
              {tPanel === 'nodes' && (
                <motion.div key="t-nodes" initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
                  transition={{ type: 'spring', damping: 30, stiffness: 300 }}
                  className="absolute inset-0 z-20 bg-white rounded-2xl flex flex-col">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 shrink-0">
                    <button type="button" onClick={() => setTPanel(null)} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0">
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-bold text-slate-900">Select Nodes</p>
                      <p className="text-xs font-medium text-slate-400">{tDraftNodes.length} selected</p>
                    </div>
                    <button type="button" onClick={() => setTPanel(null)} className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 transition-colors shrink-0">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="px-5 pt-3 pb-2 shrink-0">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                      <input type="text" placeholder="Search by hostname or host ID…" value={tNodeSearch} onChange={(e) => setTNodeSearch(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-teal-500" />
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
                    {nodes.length === 0 ? (
                      <div className="py-12 text-center"><p className="text-sm font-semibold text-slate-500">No nodes available</p></div>
                    ) : tFilteredNodes.length === 0 ? (
                      <div className="py-8 text-center text-sm font-medium text-slate-400">No nodes match</div>
                    ) : tFilteredNodes.slice(0, 100).map((n) => (
                      <label key={n.host_identifier} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50 cursor-pointer transition-colors">
                        <input type="checkbox" checked={tDraftNodes.includes(n.host_identifier)} onChange={() => setTDraftNodes((p) => p.includes(n.host_identifier) ? p.filter((x) => x !== n.host_identifier) : [...p, n.host_identifier])} className="w-4 h-4 accent-teal-600 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-semibold text-slate-800 truncate">{n.hostname || n.host_identifier}</p>
                          {n.hostname && <p className="text-xs font-medium text-slate-400 truncate">{n.host_identifier}</p>}
                        </div>
                        {tDraftNodes.includes(n.host_identifier) && <Check className="w-4 h-4 text-teal-500 shrink-0" strokeWidth={2.5} />}
                      </label>
                    ))}
                    {tFilteredNodes.length > 100 && (
                      <p className="text-xs font-medium text-slate-400 text-center py-3">Showing 100 of {tFilteredNodes.length} — refine search</p>
                    )}
                  </div>
                  <div className="px-5 py-4 border-t border-slate-100 bg-slate-50 shrink-0">
                    <button type="button" onClick={() => { setTSelNodes(tDraftNodes); setTPanel(null); }}
                      className="w-full py-2.5 text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 rounded-lg transition-colors">
                      Done — {tDraftNodes.length} node{tDraftNodes.length !== 1 ? 's' : ''} selected
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

// Main PolicyLibrary panel

const PolicyLibrary = () => {
  const { showToast } = useToast();
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';
  const [policies,        setPolicies]        = useState<PolicyRecord[]>([]);
  const [loading,         setLoading]         = useState(true);
  const [loadError,       setLoadError]       = useState(false);
  const [nodes,           setNodes]           = useState<NodeRow[]>([]);
  const [groups,          setGroups]          = useState<EndpointGroup[]>([]);
  const [showCreate,      setShowCreate]      = useState(false);
  const [filterType,      setFilterType]      = useState<PolicyType | 'all'>('all');
  const [assigningPolicy, setAssigningPolicy] = useState<PolicyRecord | null>(null);
  const [pendingDelete,   setPendingDelete]   = useState<PolicyRecord | null>(null);
  const [deleting,        setDeleting]        = useState(false);
  const [editingPolicy,   setEditingPolicy]   = useState<PolicyRecord | null>(null);
  const [togglingIds,     setTogglingIds]     = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    try {
      const res = await listPolicies({ limit: 100 });
      setPolicies(res.policies);
    } catch {
      setLoadError(true);
      showToast('Failed to load policies', 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    load();
    fetchNodesList().then((r) => setNodes(r.nodes)).catch(() => {});
    fetchEndpointGroups().then(setGroups).catch(() => {});
  }, [load]);

  const filtered = useMemo(() => filterType === 'all' ? policies : policies.filter((p) => p.type === filterType), [policies, filterType]);

  const handleCreated = async (draft: Omit<PolicyRecord, 'id' | 'createdAt' | 'updatedAt' | 'createdBy' | 'canManage'>) => {
    try {
      const res = await createPolicyRecord(draft);
      setPolicies((prev) => [res.policy, ...prev]);
      showToast('Policy created', 'success');
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to create policy'), 'error');
      throw err;
    }
  };

  const handleToggleEnabled = async (policy: PolicyRecord) => {
    if (togglingIds.has(policy.id)) return;
    const nextEnabled = !policy.enabled;
    if (nextEnabled && !isTargetAssigned(policy.target ?? defaultTarget())) {
      showToast('Assign at least one group or node before enabling this policy', 'error');
      return;
    }
    setPolicies((prev) => prev.map((p) => p.id === policy.id ? { ...p, enabled: nextEnabled } : p));
    setTogglingIds((prev) => new Set([...prev, policy.id]));
    try {
      const res = await updatePolicyRecord(policy.id, { enabled: nextEnabled });
      setPolicies((prev) => prev.map((p) => p.id === policy.id ? res.policy : p));
    } catch {
      setPolicies((prev) => prev.map((p) => p.id === policy.id ? { ...p, enabled: policy.enabled } : p));
      showToast('Failed to update policy', 'error');
    } finally {
      setTogglingIds((prev) => { const s = new Set(prev); s.delete(policy.id); return s; });
    }
  };

  const handleDelete = async (policy: PolicyRecord) => {
    setDeleting(true);
    try {
      await deletePolicyRecord(policy.id);
      setPolicies((prev) => prev.filter((p) => p.id !== policy.id));
      if (assigningPolicy?.id === policy.id) setAssigningPolicy(null);
      showToast('Policy deleted', 'success');
    } catch {
      showToast('Failed to delete policy', 'error');
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  };

  const handleAssignTargets = async (target: PolicyTarget) => {
    if (!assigningPolicy) return;
    const policyId = assigningPolicy.id;
    try {
      const res = await assignPolicyTargets(policyId, target);
      setPolicies((prev) => prev.map((p) => (p.id === policyId ? res.policy : p)));
      showToast('Assignment saved', 'success');
      setAssigningPolicy(null);
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to save assignment'), 'error');
    }
  };

  const handleEditSaved = async (id: string, update: PolicyConfigUpdate) => {
    try {
      const res = await updatePolicyRecord(id, update);
      setPolicies((prev) => prev.map((p) => (p.id === id ? res.policy : p)));
      showToast('Policy updated', 'success');
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to update policy'), 'error');
      throw err;
    }
  };

  // Same stale-closure hazard as EditPolicyModal above: useModalA11y's Escape
  // handler is captured once when `!!pendingDelete` flips to true and won't
  // see later `deleting` updates, so it needs a ref instead of the state value.
  const deletingRef = useRef(deleting);
  useEffect(() => { deletingRef.current = deleting; }, [deleting]);

  const deleteDialogRef = useModalA11y<HTMLDivElement>(!!pendingDelete, () => { if (!deletingRef.current) setPendingDelete(null); });

  return (
    <>
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-lg font-bold text-slate-900">Policy Library</h2>
          <p className="text-sm font-medium text-slate-500 mt-0.5">Define and manage enforcement policies.</p>
        </div>
        <motion.button
          whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.97 }}
          type="button" onClick={() => setShowCreate(true)}
          className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold text-white rounded-xl shadow-sm"
          style={{ background: 'linear-gradient(135deg, rgb(9, 121, 112) 0%, rgb(13, 148, 136) 100%)' }}
        >
          <Plus className="w-4 h-4" />
          Create Policy
        </motion.button>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2 mb-5 overflow-x-auto pb-1">
        {(['all', 'device-control', 'network', 'compliance', 'custom'] as const).map((t) => (
          <button key={t} type="button" onClick={() => setFilterType(t)}
            className={`shrink-0 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${filterType === t ? 'bg-teal-600 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}>
            {t === 'all' ? 'All' : TYPE_LABELS[t]}
          </button>
        ))}
      </div>

      {/* Content */}
      {loading ? (
        <div className="py-20 text-center">
          <DuoSpinner size="md" className="text-teal-500 mx-auto" />
          <p className="mt-3 text-sm font-medium text-slate-400">Loading policies…</p>
        </div>
      ) : loadError ? (
        <div className="py-20 text-center">
          <p className="text-sm font-semibold text-slate-700">Failed to load policies</p>
          <button type="button" onClick={load} className="rounded-lg mt-2 text-xs font-semibold text-teal-600 hover:underline">Retry</button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 py-16 text-center">
          <div className="w-12 h-12 rounded-xl bg-white border border-slate-200 text-slate-300 flex items-center justify-center mx-auto mb-3 shadow-sm">
            <FileText className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-slate-600">
            {filterType !== 'all' && policies.length > 0 ? `No ${TYPE_LABELS[filterType as PolicyType]} policies` : 'No policies yet'}
          </p>
          <p className="text-xs font-medium text-slate-400 mt-1 mb-4">
            {filterType !== 'all' && policies.length > 0
              ? `Switch to "All" to see your ${policies.length} other polic${policies.length === 1 ? 'y' : 'ies'}.`
              : 'Create your first policy to start enforcing controls.'}
          </p>
          {filterType !== 'all' && policies.length > 0 ? (
            <button type="button" onClick={() => setFilterType('all')}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors">
              View all policies
            </button>
          ) : (
            <button type="button" onClick={() => setShowCreate(true)}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-teal-700 bg-teal-50 hover:bg-teal-100 rounded-lg transition-colors border border-teal-200">
              <Plus className="w-4 h-4" />
              Create Policy
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((p) => {
            // Computed once per row: the card below reads the target in several
            // places, defaultTarget() allocates a fresh object plus two arrays per
            // call, and isTargetAssigned() rescans it. Both are pure reads.
            const target = p.target ?? defaultTarget();
            const targetAssigned = isTargetAssigned(target);
            const isAssigningThis = assigningPolicy?.id === p.id;
            return (
            <motion.div
              key={p.id} layout initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
              className={`rounded-xl border bg-white px-5 py-3.5 shadow-sm transition-all ${isAssigningThis ? 'border-teal-400 ring-1 ring-teal-200' : 'border-slate-200 hover:shadow-md'}`}
            >
              <div className="flex items-center gap-4">
                {/* Left — policy info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <p className="text-sm font-semibold text-slate-900 truncate">{p.name}</p>
                    <span className={`shrink-0 text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-0.5 ${TYPE_COLORS[p.type as PolicyType]}`}>
                      {TYPE_LABELS[p.type as PolicyType]}
                    </span>
                  </div>
                  <p className="text-xs font-medium text-slate-500 truncate">{getConfigSummary(p)}</p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {p.platforms.map((pl) => (
                      <span key={pl} className="text-[10px] font-semibold uppercase text-slate-400 bg-slate-100 px-2 py-0.5 rounded capitalize">{pl}</span>
                    ))}
                  </div>
                </div>

                {/* Center — target assignment button (read-only label if caller can't manage this policy) */}
                <div className="flex-1 flex justify-center">
                  {p.canManage ? (
                    <button
                      type="button"
                      onClick={() => setAssigningPolicy(isAssigningThis ? null : p)}
                      title="Assign to nodes / groups"
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                        isAssigningThis
                          ? 'border-teal-500 bg-teal-600 text-white'
                          : 'border-slate-200 bg-slate-50 text-slate-600 hover:border-teal-300 hover:bg-teal-50 hover:text-teal-700'
                      }`}
                    >
                      <span>{TARGET_ICONS[target.mode]}</span>
                      <span>{getTargetLabel(target)}</span>
                      <ChevronsUpDown className="w-3 h-3 ml-0.5" />
                    </button>
                  ) : (
                    <span
                      title="Org-wide policy — managed by a Super Administrator"
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 bg-slate-50 text-slate-500"
                    >
                      <span>{TARGET_ICONS[target.mode]}</span>
                      <span>{getTargetLabel(target)}</span>
                    </span>
                  )}
                </div>

                {/* Right — actions (read-only for policies outside the caller's group) */}
                <div className="flex items-center gap-2 shrink-0">
                  {!p.canManage ? (
                    <span
                      title="Org-wide policy — managed by a Super Administrator"
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold uppercase tracking-wide text-slate-400 bg-slate-100"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      Read-only
                    </span>
                  ) : (
                    <>
                  <div className="flex items-center gap-1.5" title={!targetAssigned ? 'Assign targets to enable' : undefined}>
                    {!targetAssigned && !p.enabled && (
                      <Lock className="w-3.5 h-3.5 text-slate-300" />
                    )}
                    <Toggle
                      checked={p.enabled}
                      onChange={() => handleToggleEnabled(p)}
                      disabled={togglingIds.has(p.id) || (!p.enabled && !targetAssigned)}
                    />
                  </div>

                  <button type="button" onClick={() => setEditingPolicy(p)} title="Edit policy"
                    className="p-1.5 rounded-lg text-slate-300 hover:text-amber-500 hover:bg-amber-50 transition-colors">
                    <SquarePen className="w-4 h-4" />
                  </button>

                  <button type="button" onClick={() => setPendingDelete(p)} title="Delete policy"
                    className="p-1.5 rounded-lg text-slate-300 hover:text-red-500 hover:bg-red-50 transition-colors">
                    <Trash2 className="w-4 h-4" />
                  </button>
                    </>
                  )}
                </div>
              </div>
            </motion.div>
            );
          })}
        </div>
      )}

      <EditPolicyModal
        policy={editingPolicy}
        isOpen={editingPolicy !== null}
        onClose={() => setEditingPolicy(null)}
        onSaved={handleEditSaved}
      />

      <CreatePolicyModal
        isOpen={showCreate}
        nodes={nodes}
        groups={groups}
        allowAllEndpoints={isSuperAdmin}
        onClose={() => setShowCreate(false)}
        onCreated={handleCreated}
      />

      <AnimatePresence>
        {assigningPolicy && (
          <AssignmentDrawer
            key={assigningPolicy.id}
            policy={assigningPolicy}
            nodes={nodes}
            groups={groups}
            allowAllEndpoints={isSuperAdmin}
            onClose={() => setAssigningPolicy(null)}
            onSave={handleAssignTargets}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {pendingDelete && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
            <motion.div
              ref={deleteDialogRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="delete-policy-dialog-title"
              tabIndex={-1}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-2xl shadow-xl border border-slate-200 w-full max-w-sm p-6 outline-none"
            >
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center shrink-0">
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                </div>
                <div className="min-w-0">
                  <h3 id="delete-policy-dialog-title" className="text-base font-bold text-slate-900">Delete policy?</h3>
                  <p className="mt-1 text-sm font-medium text-slate-500">
                    <span className="font-semibold text-slate-700">"{pendingDelete.name}"</span> will be permanently deleted and cannot be recovered.
                  </p>
                </div>
              </div>
              <div className="flex gap-3 mt-5 justify-end">
                <button type="button" onClick={() => setPendingDelete(null)}
                  className="px-4 py-2 text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors">
                  Cancel
                </button>
                <button type="button" onClick={() => handleDelete(pendingDelete)} disabled={deleting}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed">
                  {deleting ? (
                    <><DuoSpinner size="sm" />Deleting…</>
                  ) : 'Delete'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};

export default PolicyLibrary;
