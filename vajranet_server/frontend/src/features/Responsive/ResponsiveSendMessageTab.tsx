import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { sanitizeAsciiMultiLine } from '../../services/inputSanitizers';
import { runBulkNodeUiCommands, type NodeUiOutbound } from '../../services/nodeUiBulkSend';
import { useLiveData } from '../../context/useLiveData';
import { useToast } from '../../context/useToast';
import { fetchNodesList, MAX_BULK_OPERATIONS, type NodeRow } from './responsiveNodeUtils';
import { DuoSpinner } from '@/components/ui/loading';

const INITIAL_VISIBLE_NODES = 120;
const LOAD_MORE_CHUNK = 120;

const ResponsiveSendMessageTab = () => {
  const { showToast } = useToast();
  const { nodeStatus } = useLiveData();
  const onlineSet = useMemo(() => new Set(nodeStatus?.agentOnline ?? []), [nodeStatus?.agentOnline]);

  const [message, setMessage] = useState('');
  const [reason, setReason] = useState('');
  const [nodeSearch, setNodeSearch] = useState('');
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [showSelectedOnly, setShowSelectedOnly] = useState(false);
  const [nodes, setNodes] = useState<NodeRow[]>([]);
  const [nodesLoading, setNodesLoading] = useState(true);
  const [, setNodesError] = useState<string | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [visibleNodeCount, setVisibleNodeCount] = useState(INITIAL_VISIBLE_NODES);

  // Wizard state
  const [currentStep, setCurrentStep] = useState(1);
  const [direction, setDirection] = useState(1);

  const loadNodes = useCallback(async () => {
    setNodesLoading(true);
    setNodesError(null);
    const { nodes: list, error } = await fetchNodesList();
    setNodes(list);
    setNodesError(error);
    setNodesLoading(false);
  }, []);

  useEffect(() => {
    void loadNodes();
  }, [loadNodes]);

  const filteredNodes = useMemo(() => {
    const q = nodeSearch.trim().toLowerCase();
    const base = q
      ? nodes.filter(
          (n) =>
            n.hostname?.toLowerCase().includes(q) ||
            n.host_identifier?.toLowerCase().includes(q) ||
            (n.os_platform || '').toLowerCase().includes(q),
        )
      : nodes;

    const onlineFiltered = onlineOnly ? base.filter((n) => onlineSet.has(n.host_identifier)) : base;
    const selectedFiltered = showSelectedOnly
      ? onlineFiltered.filter((n) => selectedHosts.has(n.host_identifier))
      : onlineFiltered;

    return selectedFiltered;
  }, [nodes, nodeSearch, onlineOnly, onlineSet, showSelectedOnly, selectedHosts]);

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

  const selectedRows = useMemo(
    () => nodes.filter((n) => selectedHosts.has(n.host_identifier)),
    [nodes, selectedHosts],
  );

  const cleanReason = reason.trim();
  const cleanMessage = message.trim();
  const selectedCount = selectedRows.length;
  const overLimit = selectedCount > MAX_BULK_OPERATIONS;
  const nearLimit = selectedCount >= Math.floor(MAX_BULK_OPERATIONS * 0.85);

  const step1Valid = !!cleanMessage;
  const step2Valid = selectedCount > 0;
  const step3Valid = !!cleanReason && !overLimit && !submitting;

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

  const runSend = async () => {
    if (!canSubmit) return;

    const commands: NodeUiOutbound[] = selectedRows.map((r) => ({
      type: 'agent',
      host_identifier: r.host_identifier,
      params: {
        agent: 'message',
        action: 'message',
        arg1: cleanMessage,
        arg2: cleanReason,
        reason: cleanReason,
      },
    }));

    setSubmitting(true);
    try {
      const results = await runBulkNodeUiCommands(commands, { timeoutMs: 30_000 });
      const failed = results.filter((x) => !x.ok);
      const okCount = results.length - failed.length;

      if (failed.length === 0) {
        showToast(`Message sent to ${okCount} node(s).`, 'success');
        setMessage('');
        setReason('');
        clearSelection();
        setCurrentStep(1);
      } else if (okCount === 0) {
        showToast(`All ${failed.length} sends failed. First: ${failed[0]?.message ?? 'Unknown'}`, 'error');
      } else {
        showToast(
          `Partial success: ${okCount} sent, ${failed.length} failed. Example: ${failed[0]?.message ?? ''}`,
          'error',
        );
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
      id="responsive-panel-send-message"
      aria-labelledby="responsive-tab-send-message"
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
            const stepLabel = step === 1 ? 'Compose Message' : step === 2 ? 'Select Nodes' : 'Execute';
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
                <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-800 to-slate-600 mb-6 text-center">Compose Message Payload</h2>
                
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5" htmlFor="responsive-send-message">
                      Message Payload <span className="text-red-500">*</span>
                    </label>
                    <div className="relative">
                      <textarea
                        id="responsive-send-message"
                        value={message}
                        onChange={(e) => setMessage(sanitizeAsciiMultiLine(e.target.value, 500, false))}
                        rows={6}
                        placeholder="Write the exact message users will see..."
                        className="w-full rounded-xl border border-slate-200 bg-white/90 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/50 shadow-inner transition-all resize-none"
                      />
                      <div className="absolute bottom-2 right-3 text-[10px] font-bold text-slate-400">{message.length}/500</div>
                    </div>
                  </div>

                  {cleanMessage ? (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="rounded-xl border border-slate-200 bg-slate-50/80 p-3.5 shadow-sm overflow-hidden">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">Preview</div>
                      <div className="text-sm text-slate-800 whitespace-pre-wrap break-words">{cleanMessage}</div>
                    </motion.div>
                  ) : null}
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
                          placeholder="Search nodes..."
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
                <p className="text-center text-sm text-slate-500 mb-6">You are sending a message to {selectedCount} node{selectedCount !== 1 ? 's' : ''}.</p>

                <div className="space-y-6 flex-1">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1.5" htmlFor="responsive-send-reason">
                      Audit Reason <span className="text-red-500">*</span>
                    </label>
                    <div className="relative">
                      <textarea
                        id="responsive-send-reason"
                        value={reason}
                        onChange={(e) => setReason(sanitizeAsciiMultiLine(e.target.value, 240, false))}
                        rows={3}
                        placeholder="Required for compliance logging."
                        className="w-full rounded-xl border border-slate-200 bg-white/90 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 shadow-inner transition-all resize-none"
                      />
                      <div className="absolute bottom-2 right-3 text-[10px] font-bold text-slate-400">{reason.length}/240</div>
                    </div>
                  </div>

                  {overLimit ? (
                    <div className="rounded-xl border border-red-200 bg-red-50/80 p-3.5 text-sm font-medium text-red-700 flex items-center gap-2 shadow-sm">
                      <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                      Max ops exceeded ({selectedCount}/{MAX_BULK_OPERATIONS}). Reduce selection.
                    </div>
                  ) : nearLimit ? (
                    <div className="rounded-xl border border-amber-200 bg-amber-50/80 p-3.5 text-sm font-medium text-amber-900 flex items-center gap-2 shadow-sm">
                      <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                      Close to limit ({selectedCount}/{MAX_BULK_OPERATIONS} ops).
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-sm font-medium text-slate-600 flex items-center gap-2">
                      <svg className="w-5 h-5 shrink-0 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                      Total Operations: {selectedCount} / {MAX_BULK_OPERATIONS}
                    </div>
                  )}
                </div>

                <div className="mt-auto pt-6 flex justify-between items-center border-t border-slate-100/80">
                  <button type="button" onClick={prevStep} className="rounded-lg px-4 py-2 text-sm font-bold text-slate-600 hover:text-slate-900 transition-colors">
                    Back
                  </button>
                  <button
                    type="button"
                    disabled={!step3Valid}
                    onClick={() => void runSend()}
                    className="relative overflow-hidden group flex items-center justify-center rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 px-6 py-2.5 text-sm font-bold text-white shadow-lg shadow-blue-500/30 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:hover:scale-100 disabled:cursor-not-allowed disabled:shadow-none"
                  >
                    <span className="relative flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" /></svg>
                      Dispatch Message
                    </span>
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.section>
  );
};

export default ResponsiveSendMessageTab;
