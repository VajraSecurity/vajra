import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';

import { runBulkNodeUiCommands, type NodeUiOutbound } from '../../services/nodeUiBulkSend';
import { useLiveData } from '../../context/useLiveData';
import { useToast } from '../../context/useToast';
import { parsePortInput, expandPortRanges } from './portSpecParser';
import { fetchNodesList, MAX_BULK_OPERATIONS, type NodeRow } from './responsiveNodeUtils';
import { DuoSpinner } from '@/components/ui/loading';

const INITIAL_VISIBLE_NODES = 120;
const LOAD_MORE_CHUNK = 120;

const ResponsivePortTab = () => {
  const { showToast } = useToast();
  const { nodeStatus } = useLiveData();
  const onlineSet = useMemo(() => new Set(nodeStatus?.agentOnline ?? []), [nodeStatus?.agentOnline]);

  const [portInput, setPortInput] = useState('');
  const [nodeSearch, setNodeSearch] = useState('');
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [showSelectedOnly, setShowSelectedOnly] = useState(false);
  const [nodes, setNodes] = useState<NodeRow[]>([]);
  const [nodesLoading, setNodesLoading] = useState(true);
  const [, setNodesError] = useState<string | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState('');
  const [protocol, setProtocol] = useState<'tcp' | 'udp' | 'both'>('tcp');
  const [trafficType, setTrafficType] = useState<'all' | 'in' | 'out'>('all');
  const [submitting, setSubmitting] = useState(false);
  const [visibleNodeCount, setVisibleNodeCount] = useState(INITIAL_VISIBLE_NODES);

  // Wizard state
  const [currentStep, setCurrentStep] = useState(1);
  const [direction, setDirection] = useState(1);

  const fetchNodes = useCallback(async () => {
    setNodesLoading(true);
    setNodesError(null);
    const { nodes: list, error } = await fetchNodesList();
    setNodes(list);
    setNodesError(error);
    setNodesLoading(false);
  }, []);

  useEffect(() => {
    void fetchNodes();
  }, [fetchNodes]);

  const parsedPorts = useMemo(() => parsePortInput(portInput), [portInput]);

  const filteredNodes = useMemo(() => {
    const q = nodeSearch.trim().toLowerCase();
    const base = q
      ? nodes.filter(
        (n) =>
          n.hostname?.toLowerCase().includes(q) ||
          n.host_identifier?.toLowerCase().includes(q),
      )
      : nodes;

    const onlineFiltered = onlineOnly ? base.filter((n) => onlineSet.has(n.host_identifier)) : base;
    const selectedFiltered = showSelectedOnly
      ? onlineFiltered.filter((n) => selectedHosts.has(n.host_identifier))
      : onlineFiltered;
    return selectedFiltered;
  }, [nodeSearch, nodes, onlineOnly, onlineSet, showSelectedOnly, selectedHosts]);

  // Reset the revealed chunk whenever the filters change so a new, smaller
  // result set doesn't inherit a large already-expanded reveal count.
  useEffect(() => {
    setVisibleNodeCount(INITIAL_VISIBLE_NODES);
  }, [nodeSearch, onlineOnly, showSelectedOnly]);

  const visibleNodes = useMemo(
    () => filteredNodes.slice(0, visibleNodeCount),
    [filteredNodes, visibleNodeCount],
  );
  const remainingNodeCount = filteredNodes.length - visibleNodes.length;

  const toggleHost = (host: string) => {
    setSelectedHosts((prev) => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host);
      else next.add(host);
      return next;
    });
  };

  const selectAllFiltered = () => {
    setSelectedHosts((prev) => {
      const next = new Set(prev);
      for (const n of filteredNodes) next.add(n.host_identifier);
      return next;
    });
  };

  const clearSelection = () => setSelectedHosts(new Set());

  const portsOk = parsedPorts.ok;
  const portTokens = portsOk ? parsedPorts.tokens : [];
  const expandedPorts = portsOk ? expandPortRanges(portTokens) : [];
  const selectedCount = selectedHosts.size;
  const totalOps = portsOk ? expandedPorts.length * selectedCount : 0;
  const overLimit = portsOk && selectedCount > 0 && totalOps > MAX_BULK_OPERATIONS;
  const nearLimit = portsOk && selectedCount > 0 && totalOps >= Math.floor(MAX_BULK_OPERATIONS * 0.85);

  const step1Valid = portsOk && portTokens.length > 0;
  const step2Valid = selectedCount > 0;
  const step3Valid = !!reason.trim() && !overLimit && !submitting;

  const canSubmit = step1Valid && step2Valid && step3Valid;

  const nextStep = () => {
    if (currentStep === 1 && !step1Valid) return;
    if (currentStep === 2 && !step2Valid) return;
    setDirection(1);
    setCurrentStep((p) => Math.min(p + 1, 3));
  };

  const prevStep = () => {
    setDirection(-1);
    setCurrentStep((p) => Math.max(p - 1, 1));
  };

  const stepVariants = {
    initial: (dir: number) => ({ x: dir > 0 ? 50 : -50, opacity: 0 }),
    animate: { x: 0, opacity: 1 },
    exit: (dir: number) => ({ x: dir < 0 ? 50 : -50, opacity: 0 }),
  };

  const applyRules = async (action: 'block' | 'allow') => {
    if (!canSubmit) return;

    setSubmitting(true);
    try {
      const commands: NodeUiOutbound[] = [];
      const hosts = [...selectedHosts];
      for (const host of hosts) {
        for (const port of expandedPorts) {
          commands.push({
            type: 'agent',
            host_identifier: host,
            params: {
              agent: 'port',
              action,
              arg1: port,
              arg2: trafficType,
              arg3: reason.trim(),
              reason: reason.trim(),
            },
          });
        }
      }

      const results = await runBulkNodeUiCommands(commands, { timeoutMs: 30_000 });
      const failed = results.filter((r) => !r.ok);
      const okCount = results.length - failed.length;

      if (failed.length === 0) {
        showToast(`${action === 'block' ? 'Blocked' : 'Allowed'} ${expandedPorts.length} port rule(s) on ${hosts.length} node(s).`, 'success');
        // Reset after success
        setPortInput('');
        setReason('');
        clearSelection();
        setCurrentStep(1);
      } else if (okCount === 0) {
        showToast(`All ${failed.length} operations failed. First error: ${failed[0]?.message ?? 'Unknown'}`, 'error');
      } else {
        showToast(`Partial success: ${okCount} applied, ${failed.length} failed. Example: ${failed[0]?.message ?? ''}`, 'error');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      role="tabpanel"
      id="responsive-panel-port"
      aria-labelledby="responsive-tab-port"
      className="flex flex-col h-full items-center justify-start pt-4 pb-8"
    >
      {/* Wizard Stepper Header */}
      <div className="w-full max-w-3xl mb-16 px-4">
        <div className="flex items-center justify-between relative">
          <div className="absolute left-0 top-1/2 -translate-y-1/2 w-full h-1 bg-slate-200 rounded-full z-0"></div>
          <div
            className="absolute left-0 top-1/2 -translate-y-1/2 h-1 bg-blue-500 rounded-full z-0 transition-all duration-500"
            style={{ width: `${((currentStep - 1) / 2) * 100}%` }}
          ></div>
          
          {[1, 2, 3].map((step) => {
            const stepLabel = step === 1 ? 'Define Rule' : step === 2 ? 'Select Nodes' : 'Execute';
            const clickable =
              step < currentStep ||
              (step === 2 && step1Valid && currentStep < 2) ||
              (step === 3 && step1Valid && step2Valid && currentStep < 3);
            const goToStep = () => {
              if (step < currentStep) {
                setDirection(-1);
                setCurrentStep(step);
              } else if (step === 2 && step1Valid && currentStep < 2) {
                setDirection(1);
                setCurrentStep(step);
              } else if (step === 3 && step1Valid && step2Valid && currentStep < 3) {
                setDirection(1);
                setCurrentStep(step);
              }
            };
            return (
              <div
                key={step}
                role="button"
                tabIndex={clickable ? 0 : -1}
                aria-disabled={!clickable}
                aria-current={currentStep === step ? 'step' : undefined}
                aria-label={`Step ${step}: ${stepLabel}`}
                onClick={goToStep}
                onKeyDown={(e) => {
                  if (!clickable) return;
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    goToStep();
                  }
                }}
                className={`relative z-10 flex flex-col items-center justify-center w-10 h-10 rounded-full border-4 transition-all duration-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 ${
                  currentStep === step
                    ? 'bg-blue-600 border-blue-100 text-white shadow-lg shadow-blue-500/40 scale-110 cursor-default'
                    : currentStep > step
                    ? 'bg-blue-500 border-white text-white cursor-pointer hover:bg-blue-600'
                    : 'bg-white border-slate-200 text-slate-400'
                }`}
              >
                <span className="text-sm font-bold">{step}</span>
                <span className={`absolute -bottom-6 whitespace-nowrap text-xs font-bold ${currentStep === step ? 'text-blue-600' : 'text-slate-500'}`}>
                  {stepLabel}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Wizard Content Container */}
      <div className="w-full max-w-3xl relative min-h-[30rem]">
        <AnimatePresence mode="wait" custom={direction}>
          {currentStep === 1 && (
            <motion.div
              key="step1"
              custom={direction}
              variants={stepVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={{ type: 'spring', bounce: 0.1, duration: 0.5 }}
              className="absolute inset-0 flex flex-col"
            >
              <div className="flex flex-col flex-1 rounded-2xl border border-slate-200/70 bg-white/80 backdrop-blur-xl shadow-xl shadow-slate-200/40 overflow-hidden relative p-6">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-indigo-500"></div>
                <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-800 to-slate-600 mb-6 text-center">Configure Port Rule</h2>
                
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5" htmlFor="bulk-ports">
                      Target Port(s)
                    </label>
                    <div className="relative">
                      <textarea
                        id="bulk-ports"
                        value={portInput}
                        onChange={(e) => setPortInput(e.target.value)}
                        rows={2}
                        placeholder="e.g. 443, 8080, 1-100"
                        className="w-full rounded-xl border border-slate-200 bg-white/90 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/50 shadow-inner transition-all resize-none"
                      />
                      {portInput && (
                        <div className="absolute top-3 right-3">
                          {portsOk ? (
                            <svg className="w-5 h-5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                          ) : (
                            <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="mt-2 text-xs text-slate-500 flex justify-between font-medium">
                      <span>Supports ranges (1-100) and commas (80, 443)</span>
                      {portsOk && <span className="text-emerald-600">Valid ({portTokens.length} set{portTokens.length !== 1 ? 's' : ''})</span>}
                      {!portsOk && portInput.trim() && <span className="text-red-500">{parsedPorts.error}</span>}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-semibold text-slate-700 mb-1.5">Protocol</label>
                      <div className="flex rounded-xl border border-slate-200/80 bg-slate-50/50 p-1 shadow-inner">
                        {(['tcp', 'udp', 'both'] as const).map((p) => {
                          const active = protocol === p;
                          const disabled = p !== 'tcp';
                          return (
                            <button
                              key={p}
                              type="button"
                              onClick={() => !disabled && setProtocol(p)}
                              disabled={disabled}
                              className={`flex-1 rounded-lg px-2 py-2.5 text-xs font-semibold transition-all duration-200 ${disabled ? 'opacity-40 cursor-not-allowed' : active ? 'bg-white text-blue-700 shadow-md ring-1 ring-slate-200/50' : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'}`}
                            >
                              {p === 'both' ? 'Both' : p.toUpperCase()}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-semibold text-slate-700 mb-1.5">Traffic Direction</label>
                      <div className="flex rounded-xl border border-slate-200/80 bg-slate-50/50 p-1 shadow-inner">
                        {(['all', 'in', 'out'] as const).map((t) => {
                          const active = trafficType === t;
                          const label = t === 'all' ? 'All' : t === 'in' ? 'Inbound' : 'Outbound';
                          return (
                            <button
                              key={t}
                              type="button"
                              onClick={() => setTrafficType(t)}
                              className={`flex-1 rounded-lg px-2 py-2.5 text-xs font-semibold transition-all duration-200 ${active ? 'bg-white text-blue-700 shadow-md ring-1 ring-slate-200/50' : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'}`}
                            >
                              {label}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="mt-auto pt-8 flex justify-end">
                  <button
                    type="button"
                    disabled={!step1Valid}
                    onClick={nextStep}
                    className="flex items-center gap-2 rounded-xl bg-blue-600 px-6 py-2.5 text-sm font-bold text-white shadow-lg shadow-blue-500/30 transition-all hover:bg-blue-700 disabled:opacity-50 disabled:shadow-none disabled:cursor-not-allowed"
                  >
                    Next Step
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {currentStep === 2 && (
            <motion.div
              key="step2"
              custom={direction}
              variants={stepVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={{ type: 'spring', bounce: 0.1, duration: 0.5 }}
              className="absolute inset-0 flex flex-col"
            >
              <div className="flex flex-col flex-1 rounded-2xl border border-slate-200/70 bg-white/80 backdrop-blur-xl shadow-xl shadow-slate-200/40 overflow-hidden relative">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-500 to-purple-500"></div>
                <div className="p-5 border-b border-slate-100/80 bg-white/60">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-800 to-slate-600">Select Target Nodes</h2>
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <svg className="h-4 w-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                        </div>
                        <input
                          type="search"
                          value={nodeSearch}
                          onChange={(e) => setNodeSearch(e.target.value)}
                          placeholder="Search hostname..."
                          className="w-full sm:w-52 pl-9 pr-3 py-2 rounded-xl border border-slate-200 bg-white/90 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 shadow-inner transition-all"
                        />
                      </div>
                      <div className="flex gap-2">
                        <button type="button" onClick={selectAllFiltered} className="rounded-xl bg-slate-800 px-3 py-2 text-xs font-bold text-white hover:bg-slate-700 shadow-md transition-all active:scale-[0.98]">
                          Select All
                        </button>
                        {selectedCount > 0 && (
                          <button type="button" onClick={clearSelection} className="rounded-xl bg-white border border-slate-200 px-3 py-2 text-xs font-bold text-slate-600 hover:bg-slate-50 hover:text-slate-900 shadow-sm transition-all active:scale-[0.98]">
                            Clear All
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setOnlineOnly(!onlineOnly)}
                      className={`px-3 py-1.5 rounded-full text-xs font-bold transition-all border ${onlineOnly ? 'bg-blue-100 text-blue-700 border-blue-200' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'}`}
                    >
                      {onlineOnly && <span className="mr-1.5 inline-block w-2 h-2 rounded-full bg-blue-600"></span>}
                      Online Only
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowSelectedOnly(!showSelectedOnly)}
                      className={`px-3 py-1.5 rounded-full text-xs font-bold transition-all border ${showSelectedOnly ? 'bg-blue-100 text-blue-700 border-blue-200' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'}`}
                    >
                      {showSelectedOnly && <span className="mr-1.5 inline-block w-2 h-2 rounded-full bg-blue-600"></span>}
                      Selected ({selectedCount})
                    </button>
                  </div>
                </div>

                <div className="flex-1 overflow-auto bg-slate-50/50 min-h-[250px] max-h-[350px]">
                  {nodesLoading ? (
                    <div className="flex flex-col items-center justify-center h-full gap-2 text-slate-400">
                      <DuoSpinner size="md" className="text-blue-500" />
                      <p className="text-sm">Loading nodes…</p>
                    </div>
                  ) : filteredNodes.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full gap-2 text-slate-400">
                      <p className="text-sm font-medium">No nodes match filters.</p>
                    </div>
                  ) : (
                    <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 p-4">
                      {visibleNodes.map((n) => {
                        const checked = selectedHosts.has(n.host_identifier);
                        const online = onlineSet.has(n.host_identifier);
                        return (
                          <div
                            key={n.host_identifier}
                            role="button"
                            tabIndex={0}
                            aria-pressed={checked}
                            aria-label={`${n.hostname || n.host_identifier} (${online ? 'online' : 'offline'})${checked ? ', selected' : ''}`}
                            onClick={() => toggleHost(n.host_identifier)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                toggleHost(n.host_identifier);
                              }
                            }}
                            className={`group relative flex flex-col p-4 rounded-xl border transition-all duration-200 cursor-pointer shadow-sm hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 ${checked ? 'bg-blue-50/80 border-blue-300 ring-1 ring-blue-500/30' : 'bg-white border-slate-200 hover:border-blue-300 hover:bg-slate-50'}`}
                          >
                            <div className="absolute top-3 right-3">
                              <div className={`w-5 h-5 rounded-md border flex items-center justify-center transition-all shadow-sm ${checked ? 'bg-blue-600 border-blue-600 text-white' : 'border-slate-300 bg-white group-hover:border-blue-400'}`}>
                                {checked && <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>}
                              </div>
                            </div>
                            <div className="flex items-start gap-3 mb-3">
                              <div className={`mt-1 h-2 w-2 rounded-full shrink-0 shadow-sm ${online ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 'bg-slate-400'}`} />
                              <div className="flex-1 min-w-0 pr-6">
                                <div className="font-bold text-sm text-slate-900 group-hover:text-blue-700 truncate">{n.hostname}</div>
                                <div className="text-xs text-slate-500 font-mono mt-1 truncate">{n.host_identifier}</div>
                              </div>
                            </div>
                            <div className="mt-auto pt-2 border-t border-slate-100/80 flex items-center justify-between">
                              <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${online ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-50 text-slate-600'}`}>
                                {online ? 'Online' : 'Offline'}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {remainingNodeCount > 0 && (
                      <div className="flex justify-center pb-4">
                        <button
                          type="button"
                          onClick={() => setVisibleNodeCount((c) => c + LOAD_MORE_CHUNK)}
                          className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-xs font-bold text-blue-700 hover:bg-blue-50 hover:border-blue-300 shadow-sm transition-all active:scale-[0.98]"
                        >
                          Load {Math.min(LOAD_MORE_CHUNK, remainingNodeCount)} more ({remainingNodeCount} remaining)
                        </button>
                      </div>
                    )}
                    </>
                  )}
                </div>

                <div className="p-4 border-t border-slate-100/80 bg-white/60 flex justify-between items-center mt-auto">
                  <button type="button" onClick={prevStep} className="rounded-lg px-4 py-2 text-sm font-bold text-slate-600 hover:text-slate-900 transition-colors">
                    Back
                  </button>
                  <button
                    type="button"
                    disabled={!step2Valid}
                    onClick={nextStep}
                    className="flex items-center gap-2 rounded-xl bg-blue-600 px-6 py-2.5 text-sm font-bold text-white shadow-lg shadow-blue-500/30 transition-all hover:bg-blue-700 disabled:opacity-50 disabled:shadow-none disabled:cursor-not-allowed"
                  >
                    Next Step
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {currentStep === 3 && (
            <motion.div
              key="step3"
              custom={direction}
              variants={stepVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={{ type: 'spring', bounce: 0.1, duration: 0.5 }}
              className="absolute inset-0 flex flex-col"
            >
              <div className="flex flex-col flex-1 rounded-2xl border border-slate-200/70 bg-white/80 backdrop-blur-xl shadow-xl shadow-slate-200/40 overflow-hidden relative p-6">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 to-teal-400"></div>
                <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-800 to-slate-600 mb-2 text-center">Confirm & Execute</h2>
                <p className="text-center text-sm text-slate-500 mb-6">You are applying rules to {expandedPorts.length} port{expandedPorts.length !== 1 ? 's' : ''} across {selectedCount} node{selectedCount !== 1 ? 's' : ''}.</p>

                <div className="space-y-6 flex-1">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5" htmlFor="bulk-port-reason">
                      Audit Reason <span className="text-red-500">*</span>
                    </label>
                    <textarea
                      id="bulk-port-reason"
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      rows={3}
                      placeholder="Required for compliance logging."
                      className="w-full rounded-xl border border-slate-200 bg-white/90 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 shadow-inner transition-all resize-none"
                    />
                  </div>

                  {overLimit ? (
                    <div className="rounded-xl border border-red-200 bg-red-50/80 p-3.5 text-sm font-medium text-red-700 flex items-center gap-2 shadow-sm">
                      <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                      Max ops exceeded ({totalOps}/{MAX_BULK_OPERATIONS}). Reduce selection.
                    </div>
                  ) : nearLimit ? (
                    <div className="rounded-xl border border-amber-200 bg-amber-50/80 p-3.5 text-sm font-medium text-amber-900 flex items-center gap-2 shadow-sm">
                      <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                      Close to limit ({totalOps}/{MAX_BULK_OPERATIONS} ops).
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-sm font-medium text-slate-600 flex items-center gap-2">
                      <svg className="w-5 h-5 shrink-0 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                      Total Operations: {totalOps} / {MAX_BULK_OPERATIONS}
                    </div>
                  )}
                </div>

                <div className="mt-auto pt-6 flex justify-between items-center border-t border-slate-100/80">
                  <button type="button" onClick={prevStep} className="rounded-lg px-4 py-2 text-sm font-bold text-slate-600 hover:text-slate-900 transition-colors">
                    Back
                  </button>
                  <div className="flex gap-3">
                    <button
                      type="button"
                      disabled={!step3Valid}
                      onClick={() => void applyRules('block')}
                      className="relative overflow-hidden group flex items-center justify-center rounded-xl bg-gradient-to-br from-red-500 to-red-600 px-5 py-2.5 text-sm font-bold text-white shadow-lg shadow-red-500/30 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:hover:scale-100 disabled:cursor-not-allowed disabled:shadow-none"
                    >
                      <span className="relative flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
                        Block Traffic
                      </span>
                    </button>
                    <button
                      type="button"
                      disabled={!step3Valid}
                      onClick={() => void applyRules('allow')}
                      className="relative overflow-hidden group flex items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-emerald-600 px-5 py-2.5 text-sm font-bold text-white shadow-lg shadow-emerald-500/30 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:hover:scale-100 disabled:cursor-not-allowed disabled:shadow-none"
                    >
                      <span className="relative flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                        Allow Traffic
                      </span>
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.section>
  );
};

export default ResponsivePortTab;
