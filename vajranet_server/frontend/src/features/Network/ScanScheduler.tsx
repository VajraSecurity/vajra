import { useState, useEffect, useCallback, useMemo, memo } from 'react';
import type { FormEvent } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { isAxiosError } from 'axios';
import { Clock, X, Play, ChevronDown, ChevronUp, Pencil, Trash2, Loader2, Users } from 'lucide-react';
import {
  getScanSchedules, createScanSchedule, updateScanSchedule, deleteScanSchedule,
  runScanScheduleNow, getScanScheduleRuns,
} from '../../api/api';
import type { ScanSchedule, ScanScheduleRequest, NetworkScanHistory } from '../../api/api';
import { parseSessionOutput } from './utils/parseNmapOutput';
import { AdvancedScanCard } from './NetworkHistoryModal';
import { FancySelect, CIDR_OPTIONS } from './ui';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';
import { useModalA11y } from '../../hooks/useModalA11y';
import { useGroupScope } from '../../hooks/useGroupScope';

/** Sentinel FancySelect value standing in for `groupId: null` ("My Own
 *  (Super Admin)") — FancySelect's item values must be strings, and null
 *  can't be one. Mapped back to null before it ever reaches selectedGroupId. */
const SELF_GROUP_OPTION = '__self__';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

const UNIT_OPTIONS = [
  { value: 'minutes', label: 'Minutes' },
  { value: 'hours', label: 'Hours' },
  { value: 'days', label: 'Days' },
];

const FREQUENCY_OPTIONS: { value: ScanSchedule['frequencyPreset']; label: string }[] = [
  { value: '5min', label: 'Every 5 minutes' },
  { value: '1h', label: 'Every hour' },
  { value: '1d', label: 'Every day' },
  { value: 'custom', label: 'Custom interval' },
];

const REFRESH_INTERVAL_MS = 15000;

/**
 * One expanded schedule run. Extracted and memoised because the schedule list polls every
 * REFRESH_INTERVAL_MS, and without the memo each tick re-runs parseSessionOutput() (a
 * ~15-regex line scan over the whole nmap session) once for the run plus once per child
 * scan, for every run of every expanded schedule. Run objects are fetched once and never
 * replaced, so each output is parsed exactly once.
 */
const ScheduleRunCard = memo<{ run: NetworkScanHistory }>(({ run }) => {
  const parsed = useMemo(() => parseSessionOutput(run.output || ''), [run.output]);
  const parsedChildScans = useMemo(
    () => (run.childScans || []).map((child) => ({ child, result: parseSessionOutput(child.output || '').baseScan })),
    [run.childScans],
  );

  return (
    <div className="bg-slate-50/60 border border-slate-200 rounded-lg p-3">
      <div className="flex items-center justify-between text-xs text-slate-600 mb-2">
        <span className="font-mono">{run.target}</span>
        <span>{new Date(run.created_at).toLocaleString()}</span>
      </div>
      <div className="text-xs text-slate-500 mb-2">
        {parsed.baseScan.discoveredHosts.length} host(s) discovered
        {run.childScans && run.childScans.length > 0 && ` · ${run.childScans.length} auto advanced scan(s)`}
      </div>
      {parsedChildScans.map(({ child, result }) => (
        <div key={child.id} className="mt-2">
          <AdvancedScanCard targetIp={child.target} result={result} />
        </div>
      ))}
    </div>
  );
});
ScheduleRunCard.displayName = 'ScheduleRunCard';

function formatRelativeTime(iso: string | null): string {
  if (!iso) return 'Never';
  const diffSec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diffSec < 60) return `${Math.max(diffSec, 0)}s ago`;
  const min = Math.floor(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

const emptyForm: ScanScheduleRequest = {
  name: '', target: '', frequencyPreset: '1h', cronExpression: '', reason: '', enabled: true,
};

const STATUS_STYLES: Record<string, string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-red-50 text-red-700 border-red-200',
  running: 'bg-amber-50 text-amber-700 border-amber-200',
};

const ScanScheduler = () => {
  const { showToast } = useToast();
  const confirm = useConfirm();
  const { isSuperAdmin, groups, selectedGroupId, setSelectedGroupId, showPicker } = useGroupScope();
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState<ScanScheduleRequest>(emptyForm);
  const [editingId, setEditingId] = useState<number | null>(null);
  // The schedule's own group, captured when entering edit mode — sent back
  // unchanged on update purely so the server can disambiguate scope for a
  // caller who acts on more than one group (the group picker itself is
  // hidden while editing; group_id never changes on update).
  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const modalRef = useModalA11y<HTMLDivElement>(isModalOpen, () => setIsModalOpen(false));
  const [submitting, setSubmitting] = useState(false);
  const [expandedRunsId, setExpandedRunsId] = useState<number | null>(null);
  const [runsByScheduleId, setRunsByScheduleId] = useState<Record<number, NetworkScanHistory[]>>({});
  const [runsLoading, setRunsLoading] = useState<Record<number, boolean>>({});
  const [knownIpsList, setKnownIpsList] = useState<string[]>([]);
  const [knownIpInput, setKnownIpInput] = useState('');
  const [targetIp, setTargetIp] = useState('');
  const [targetCidr, setTargetCidr] = useState('');
  const [customNum, setCustomNum] = useState(1);
  const [customUnit, setCustomUnit] = useState('days');

  const fetchSchedules = useCallback(async () => {
    try {
      const res = await getScanSchedules();
      if (res.success) setSchedules(res.schedules || []);
    } catch (err) {
      console.error('Failed to fetch scan schedules:', err);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchSchedules().finally(() => setLoading(false));
    const interval = setInterval(fetchSchedules, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchSchedules]);

  // Group Admin of more than one group: there's no safe default group among
  // several, so they must explicitly pick one before a new schedule can be
  // created. A Super Admin always has a valid default (their own/null scope),
  // and a single-group admin is silently scoped with no picker to begin with.
  const mustPickGroupToCreate = !editingId && showPicker && !isSuperAdmin && !selectedGroupId;

  const groupLabel = (groupId: string | null): string => {
    if (groupId === null) return 'Super Admin';
    return groups.find((g) => g.groupId === groupId)?.name || groupId;
  };

  const resetForm = () => {
    setForm(emptyForm);
    setKnownIpsList([]);
    setKnownIpInput('');
    setTargetIp('');
    setTargetCidr('');
    setCustomNum(1);
    setCustomUnit('days');
    setEditingId(null);
    setEditingGroupId(null);
  };
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (mustPickGroupToCreate) return;
    setSubmitting(true);
    try {
      let finalCron = form.cronExpression;
      if (form.frequencyPreset === 'custom') {
        if (customUnit === 'minutes') finalCron = `*/${customNum} * * * *`;
        else if (customUnit === 'hours') finalCron = `0 */${customNum} * * *`;
        else if (customUnit === 'days') finalCron = `0 0 */${customNum} * *`;
      }

      const payload: ScanScheduleRequest = {
        ...form,
        target: targetCidr ? `${targetIp}${targetCidr}` : targetIp,
        cronExpression: form.frequencyPreset === 'custom' ? finalCron : undefined,
        knownIps: knownIpsList,
        // Create: the group picked above. Edit: the schedule's own group,
        // unchanged — the server ignores this field for reassignment anyway.
        groupId: editingId ? editingGroupId : selectedGroupId,
      };
      const res = editingId ? await updateScanSchedule(editingId, payload) : await createScanSchedule(payload);
      if (res.success) {
        showToast(editingId ? 'Schedule updated' : 'Schedule created', 'success');
        resetForm();
        fetchSchedules();
        setIsModalOpen(false);
      } else {
        const message = res.message || 'Failed to save schedule.';
        showToast(message, 'error');
      }
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to save schedule.');
      showToast(message, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleEdit = (schedule: ScanSchedule) => {
    setEditingId(schedule.id);
    setEditingGroupId(schedule.groupId);
    setForm({
      name: schedule.name,
      target: schedule.target,
      frequencyPreset: schedule.frequencyPreset,
      cronExpression: schedule.cronExpression,
      reason: schedule.reason,
      enabled: schedule.enabled,
    });
    setKnownIpsList(schedule.knownIps || []);
    setKnownIpInput('');
    
    let ip = schedule.target || '';
    let cidr = '';
    if (ip.includes('/')) {
      const parts = ip.split('/');
      ip = parts[0];
      cidr = '/' + parts[1];
    }
    setTargetIp(ip);
    setTargetCidr(cidr);
    
    let cNum = 1;
    let cUnit = 'days';
    if (schedule.frequencyPreset === 'custom' && schedule.cronExpression) {
       const minMatch = schedule.cronExpression.match(/^\*\/(\d+) \* \* \* \*$/);
       const hrMatch = schedule.cronExpression.match(/^0 \*\/(\d+) \* \* \*$/);
       const dayMatch = schedule.cronExpression.match(/^0 0 \*\/(\d+) \* \*$/);
       
       if (minMatch) {
         cNum = parseInt(minMatch[1], 10);
         cUnit = 'minutes';
       } else if (hrMatch) {
         cNum = parseInt(hrMatch[1], 10);
         cUnit = 'hours';
       } else if (dayMatch) {
         cNum = parseInt(dayMatch[1], 10);
         cUnit = 'days';
       }
    }
    setCustomNum(cNum);
    setCustomUnit(cUnit);

    setIsModalOpen(true);
  };

  const handleToggleEnabled = async (schedule: ScanSchedule) => {
    try {
      await updateScanSchedule(schedule.id, {
        name: schedule.name,
        target: schedule.target,
        frequencyPreset: schedule.frequencyPreset,
        cronExpression: schedule.cronExpression,
        reason: schedule.reason,
        knownIps: schedule.knownIps,
        enabled: !schedule.enabled,
        groupId: schedule.groupId,
      });
      showToast(!schedule.enabled ? 'Schedule enabled' : 'Schedule paused', 'success');
      fetchSchedules();
    } catch (err) {
      console.error('Failed to toggle schedule:', err);
      showToast(getErrorMessage(err, 'Failed to update schedule'), 'error');
    }
  };

  const handleDelete = async (schedule: ScanSchedule) => {
    const confirmed = await confirm({
      title: `Delete schedule "${schedule.name}"?`,
      description: 'This cannot be undone.',
      confirmLabel: 'Delete',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      await deleteScanSchedule(schedule.id, schedule.groupId);
      showToast('Schedule deleted', 'success');
      fetchSchedules();
    } catch (err) {
      console.error('Failed to delete schedule:', err);
      showToast(getErrorMessage(err, 'Failed to delete schedule'), 'error');
    }
  };

  const handleRunNow = async (schedule: ScanSchedule) => {
    try {
      await runScanScheduleNow(schedule.id, schedule.groupId);
      showToast('Scan triggered', 'success');
      fetchSchedules();
    } catch (err) {
      console.error('Failed to trigger schedule run:', err);
      showToast(getErrorMessage(err, 'Failed to trigger scan'), 'error');
    }
  };

  const toggleRuns = async (schedule: ScanSchedule) => {
    if (expandedRunsId === schedule.id) {
      setExpandedRunsId(null);
      return;
    }
    setExpandedRunsId(schedule.id);
    if (!runsByScheduleId[schedule.id]) {
      setRunsLoading((prev) => ({ ...prev, [schedule.id]: true }));
      try {
        const res = await getScanScheduleRuns(schedule.id, schedule.groupId);
        setRunsByScheduleId((prev) => ({ ...prev, [schedule.id]: res.runs || [] }));
      } catch (err) {
        console.error('Failed to fetch schedule runs:', err);
        showToast(getErrorMessage(err, 'Failed to fetch schedule runs'), 'error');
      } finally {
        setRunsLoading((prev) => ({ ...prev, [schedule.id]: false }));
      }
    }
  };

  const renderStatusBadge = (status: ScanSchedule['lastRunStatus']) => {
    const label = status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Never run';
    const style = status ? STATUS_STYLES[status] : 'bg-slate-50 text-slate-500 border-slate-200';
    return <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${style}`}>{label}</span>;
  };

  return (
    <div className="pb-6 flex flex-col gap-6">
      {/* Page Header */}
      <div
        className="px-5 py-4 rounded-xl lg:rounded-2xl border border-violet-100 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 shadow-sm"
        style={{ background: 'linear-gradient(135deg, rgb(76, 29, 149) 0%, rgb(124, 58, 237) 100%)' }}
      >
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white/15 rounded-lg">
            <Clock className="w-5 h-5 text-violet-100" strokeWidth={2} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Scan Scheduler</h1>
            <p className="text-sm text-violet-100">Continuously watch a subnet and auto-scan new unmanaged hosts.</p>
          </div>
        </div>
        <button
          onClick={() => {
            resetForm();
            setIsModalOpen(true);
          }}
          className="px-4 py-2 bg-white text-violet-700 text-sm font-bold rounded-lg shadow-sm hover:bg-violet-50 transition-colors shrink-0"
        >
          New Schedule
        </button>
      </div>

      {/* Create / Edit Form Modal */}
      <AnimatePresence>
        {isModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-slate-900/40 backdrop-blur-sm">
            <motion.div
              ref={modalRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="scan-scheduler-modal-title"
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              transition={{ type: "spring", bounce: 0, duration: 0.4 }}
              className="bg-white rounded-xl lg:rounded-2xl shadow-2xl border border-violet-100 w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden relative"
            >
              <div className="flex justify-between items-center p-5 border-b border-slate-100" style={{ background: 'linear-gradient(135deg, rgb(76, 29, 149) 0%, rgb(124, 58, 237) 100%)' }}>
                <h2 id="scan-scheduler-modal-title" className="text-lg font-bold text-white flex items-center gap-2">
                  <Clock className="w-5 h-5 text-violet-200" />
                  {editingId ? 'Edit Schedule' : 'New Schedule'}
                </h2>
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  aria-label="Close"
                  className="p-1.5 text-violet-200 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-5 sm:p-6 overflow-y-auto table-scrollbar">
                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Name</label>
                      <input
                        type="text"
                        required
                        placeholder="e.g., Office subnet watch"
                        value={form.name}
                        onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-400"
                      />
                    </div>
                    {showPicker && (
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Group</label>
                        {editingId ? (
                          <div className="w-full px-3 py-2 border border-slate-200 bg-slate-50 rounded-lg text-sm text-slate-500 flex items-center gap-1.5">
                            <Users className="w-3.5 h-3.5 shrink-0" />
                            {groupLabel(editingGroupId)}
                          </div>
                        ) : (
                          <>
                            <FancySelect
                              value={selectedGroupId ?? SELF_GROUP_OPTION}
                              onChange={(v) => setSelectedGroupId(v === SELF_GROUP_OPTION ? null : v)}
                              items={[
                                ...(isSuperAdmin ? [{ value: SELF_GROUP_OPTION, label: 'My Own (Super Admin)' }] : []),
                                ...groups.map((g) => ({ value: g.groupId, label: g.name })),
                              ]}
                            />
                            {mustPickGroupToCreate && (
                              <p className="mt-1 text-[11px] text-red-500">Select a group before creating a schedule.</p>
                            )}
                          </>
                        )}
                      </div>
                    )}
                    <div className="flex gap-3">
                      <div className="flex-[3]">
                        <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Target IP</label>
                        <input
                          type="text"
                          required
                          placeholder="e.g., 10.0.5.0"
                          value={targetIp}
                          onChange={(e) => setTargetIp(e.target.value)}
                          className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-400"
                        />
                      </div>
                      <div className="flex-[2]">
                        <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">CIDR</label>
                        <FancySelect
                          value={targetCidr}
                          onChange={setTargetCidr}
                          items={CIDR_OPTIONS}
                          mono
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Frequency</label>
                      <FancySelect
                        value={form.frequencyPreset}
                        onChange={(v) => setForm((f) => ({ ...f, frequencyPreset: v as ScanSchedule['frequencyPreset'] }))}
                        items={FREQUENCY_OPTIONS}
                      />
                    </div>
                    {form.frequencyPreset === 'custom' && (
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Every...</label>
                        <div className="flex gap-3">
                          <input
                            type="number"
                            min="1"
                            value={customNum}
                            onChange={(e) => setCustomNum(parseInt(e.target.value) || 1)}
                            className="w-24 px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-400"
                          />
                          <FancySelect
                            value={customUnit}
                            onChange={setCustomUnit}
                            items={UNIT_OPTIONS}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Reason</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g., Continuous monitoring of the office subnet"
                      value={form.reason}
                      onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
                      className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-400"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">
                      Known IPs <span className="normal-case font-normal text-slate-400">(optional — devices that can never run the Vajra agent, e.g. routers/printers)</span>
                    </label>
                    <div className="flex flex-col gap-2">
                      <div className="flex gap-2">
                        <input
                          type="text"
                          placeholder="e.g., 10.0.0.1"
                          value={knownIpInput}
                          onChange={(e) => setKnownIpInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              e.preventDefault();
                              const trimmed = knownIpInput.trim();
                              if (trimmed && !knownIpsList.includes(trimmed)) {
                                setKnownIpsList([...knownIpsList, trimmed]);
                                setKnownIpInput('');
                              }
                            }
                          }}
                          className="flex-1 px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-400"
                        />
                        <button
                          type="button"
                          onClick={() => {
                            const trimmed = knownIpInput.trim();
                            if (trimmed && !knownIpsList.includes(trimmed)) {
                              setKnownIpsList([...knownIpsList, trimmed]);
                              setKnownIpInput('');
                            }
                          }}
                          className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-semibold rounded-lg transition-colors border border-slate-200 shrink-0"
                        >
                          Add IP
                        </button>
                      </div>
                      {knownIpsList.length > 0 && (
                        <div className="flex flex-wrap gap-2 mt-1">
                          {knownIpsList.map((ip) => (
                            <span key={ip} className="flex items-center gap-1.5 px-2.5 py-1 bg-violet-50 text-violet-700 border border-violet-200 rounded-md text-xs font-mono">
                              {ip}
                              <button
                                type="button"
                                onClick={() => setKnownIpsList(knownIpsList.filter(i => i !== ip))}
                                className="rounded-lg text-violet-400 hover:text-violet-700 focus:outline-none"
                              >
                                <X className="w-3.5 h-3.5" />
                              </button>
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <p className="mt-1 text-[11px] text-slate-400">These IPs are never flagged as a new unmanaged host and never advanced-scanned by this schedule, even though they'll never have a Vajra agent.</p>
                  </div>

                  <div className="flex items-center gap-3 pt-2">
                    <button
                      type="submit"
                      disabled={submitting || mustPickGroupToCreate}
                      title={mustPickGroupToCreate ? 'Select a group before creating a schedule.' : undefined}
                      className="px-4 py-2 text-white text-sm font-semibold rounded-lg shadow-sm disabled:opacity-50"
                      style={{ background: 'rgb(109, 40, 217)' }}
                    >
                      {submitting ? 'Saving...' : editingId ? 'Save Changes' : 'Create Schedule'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setIsModalOpen(false)}
                      className="px-4 py-2 text-sm font-semibold rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Schedule List */}
      <div className="bg-white rounded-xl lg:rounded-2xl border border-violet-100 shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-700">Schedules</h2>
          <span className="text-xs text-slate-400">{schedules.length} schedule(s)</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-slate-400 flex items-center justify-center gap-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading schedules...
          </div>
        ) : schedules.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-400">
            No scan schedules yet. Create one above to start continuously watching a subnet.
          </div>
        ) : (
          <ul className="divide-y divide-slate-100">
            {schedules.map((schedule) => (
              <li key={schedule.id} className="p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <button
                      onClick={() => handleToggleEnabled(schedule)}
                      role="switch"
                      aria-checked={schedule.enabled}
                      aria-label={schedule.enabled ? 'Disable schedule' : 'Enable schedule'}
                      title={schedule.enabled ? 'Disable schedule' : 'Enable schedule'}
                      className={`w-9 h-5 rounded-full relative transition-colors shrink-0 ${schedule.enabled ? 'bg-violet-600' : 'bg-slate-300'}`}
                    >
                      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${schedule.enabled ? 'translate-x-4' : ''}`} />
                    </button>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-sm text-slate-800 truncate">{schedule.name}</span>
                        {renderStatusBadge(schedule.lastRunStatus)}
                        {isSuperAdmin && (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border bg-slate-50 text-slate-500 border-slate-200"
                            title={schedule.groupId === null ? 'Owned by a Super Administrator, not tied to any group' : `Owned by group: ${groupLabel(schedule.groupId)}`}
                          >
                            <Users className="w-3 h-3" />
                            {groupLabel(schedule.groupId)}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-500 font-mono mt-0.5">
                        {schedule.target} &middot; {FREQUENCY_OPTIONS.find((o) => o.value === schedule.frequencyPreset)?.label || schedule.cronExpression}
                        {schedule.knownIps && schedule.knownIps.length > 0 && (
                          <span className="ml-2 font-sans text-slate-400" title={schedule.knownIps.join(', ')}>
                            &middot; {schedule.knownIps.length} known IP(s) excluded
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-slate-500">
                    <div className="text-right">
                      <div>Last run: {formatRelativeTime(schedule.lastRunAt)}</div>
                      <div>
                        New hosts: <span className="font-semibold text-slate-700">{schedule.lastNewIpCount ?? '—'}</span>
                        {!!schedule.lastPendingIpCount && (
                          <span className="ml-1 text-amber-600" title="Unmanaged hosts still queued past this run's per-tick cap — picked up on a future run">
                            (+{schedule.lastPendingIpCount} pending)
                          </span>
                        )}
                      </div>
                      {!!schedule.lastReusedIpCount && (
                        <div className="mt-0.5">
                          <span
                            className="text-amber-600 font-semibold"
                            title="IPs that matched a registered Vajra device which is currently offline — the device may be off and DHCP may have handed its IP to a different, unmanaged machine"
                          >
                            Possible reuse: {schedule.lastReusedIpCount}
                          </span>
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => handleRunNow(schedule)} className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-violet-50 text-violet-700 rounded-md border border-violet-200 hover:bg-violet-100 font-medium transition-all hover:-translate-y-0.5 active:translate-y-0">
                        <Play className="w-3.5 h-3.5" />
                        Run Now
                      </button>
                      <button onClick={() => toggleRuns(schedule)} className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-50 text-slate-700 rounded-md border border-slate-200 hover:bg-slate-100 font-medium transition-all hover:-translate-y-0.5 active:translate-y-0">
                        {expandedRunsId === schedule.id ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        {expandedRunsId === schedule.id ? 'Hide Runs' : 'View Runs'}
                      </button>
                      <button onClick={() => handleEdit(schedule)} className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-50 text-slate-700 rounded-md border border-slate-200 hover:bg-slate-100 font-medium transition-all hover:-translate-y-0.5 active:translate-y-0">
                        <Pencil className="w-3.5 h-3.5" />
                        Edit
                      </button>
                      <button onClick={() => handleDelete(schedule)} className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-red-50 text-red-700 rounded-md border border-red-200 hover:bg-red-100 font-medium transition-all hover:-translate-y-0.5 active:translate-y-0">
                        <Trash2 className="w-3.5 h-3.5" />
                        Delete
                      </button>
                    </div>
                  </div>
                </div>

                <AnimatePresence>
                  {expandedRunsId === schedule.id && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 overflow-hidden"
                    >
                      {runsLoading[schedule.id] ? (
                        <div className="text-xs text-slate-400 p-3">Loading runs...</div>
                      ) : (runsByScheduleId[schedule.id] || []).length === 0 ? (
                        <div className="text-xs text-slate-400 p-3">No runs yet.</div>
                      ) : (
                        <div className="flex flex-col gap-3">
                          {(runsByScheduleId[schedule.id] || []).map((run) => (
                            <ScheduleRunCard key={run.id} run={run} />
                          ))}
                        </div>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default ScanScheduler;
