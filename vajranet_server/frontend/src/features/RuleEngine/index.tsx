import { useCallback, useState } from 'react';
import { ListChecks, GitBranch, Network, Rss, FlaskConical, Workflow } from 'lucide-react';
import { RuleEngineIcon } from '@/components/icons/navIcons';
import { SegmentedControl } from './ui';
import RulesTab from './RulesTab';
import CorrelationRulesTab from './CorrelationRulesTab';
import IpWatchGroupsTab from './IpWatchGroupsTab';
import StixFeedsTab from './StixFeedsTab';
import TestEventTab from './TestEventTab';
import CorrelationSimulationTab from './CorrelationSimulationTab';
import FloatingRuleChat from './FloatingRuleChat';
import type { NewDetectionRule, NewCorrelationRule } from '../../api/services/ruleEngineApi';

type Tab = 'rules' | 'correlation' | 'ip-watch' | 'stix' | 'test-event' | 'simulate';

const TABS: { value: Tab; label: string; icon: React.ReactNode }[] = [
  { value: 'rules', label: 'Rules', icon: <ListChecks className="h-3.5 w-3.5" /> },
  { value: 'correlation', label: 'Correlation Rules', icon: <GitBranch className="h-3.5 w-3.5" /> },
  { value: 'ip-watch', label: 'IP Watch Groups', icon: <Network className="h-3.5 w-3.5" /> },
  { value: 'stix', label: 'STIX Feeds', icon: <Rss className="h-3.5 w-3.5" /> },
  { value: 'test-event', label: 'Test Event', icon: <FlaskConical className="h-3.5 w-3.5" /> },
  { value: 'simulate', label: 'Correlation Simulation', icon: <Workflow className="h-3.5 w-3.5" /> },
];

/**
 * Rule Engine hub — full control over vajra_engine's detection/correlation
 * rules, IP watch groups, and STIX threat-intel feeds, proxied through this
 * app's own authenticated `/api/rule-engine/*` routes (never direct to the
 * sibling repo's unauthenticated console — see docs/RULE_ENGINE_UI_SPEC.md).
 * Mirrors `features/DomainReputation/index.tsx`'s shape: a thin hub + one
 * component per tab/concern.
 */
export default function RuleEngineHub() {
  const [tab, setTab] = useState<Tab>('rules');

  // A propose_rule/propose_correlation_rule chat card's "Load into builder"
  // action populates these, switches to the right tab, and the tab
  // component consumes+clears it by opening its Add/Build modal pre-filled.
  // Nothing here ever saves on the AI's behalf — the human still has to
  // Validate + Save from the normal builder UI.
  const [pendingLoadedRule, setPendingLoadedRule] = useState<Partial<NewDetectionRule> | null>(null);
  const [pendingLoadedCorrelation, setPendingLoadedCorrelation] = useState<Partial<NewCorrelationRule> | null>(null);

  const handleLoadRule = useCallback((rule: Partial<NewDetectionRule>) => {
    setPendingLoadedRule(rule);
    setTab('rules');
  }, []);
  const handleLoadCorrelation = useCallback((rule: Partial<NewCorrelationRule>) => {
    setPendingLoadedCorrelation(rule);
    setTab('correlation');
  }, []);

  return (
    <div className="h-screen overflow-hidden bg-[#f8f9fb] dark:bg-slate-950 flex flex-col">
      <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5 flex-1 flex flex-col min-h-0 w-full">
        <header className="relative overflow-hidden rounded-2xl shadow-lg shadow-blue-950/20 ring-1 ring-white/10 p-5 sm:p-6 mb-5 text-white shrink-0"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <RuleEngineIcon className="w-6 h-6 mr-2" />
                Rule Engine
              </h1>
              <p className="mt-1 text-sm text-blue-100/90 max-w-2xl">
                Detection rules, correlation rules, IP watch groups, and STIX threat-intel feeds for{' '}
                <code className="text-blue-50/90">vajra_engine</code> — proxied through this app's own
                authenticated API, never directly to the engine console.
              </p>
            </div>
          </div>
        </header>

        <div className="mb-4 shrink-0 overflow-x-auto">
          <SegmentedControl value={tab} onChange={setTab} size="sm" options={TABS.map((t) => ({ value: t.value, label: <span className="flex items-center gap-1.5">{t.icon}{t.label}</span> }))} />
        </div>

        <div className="flex-1 min-h-0">
          {tab === 'rules' && (
            <RulesTab
              pendingLoadedRule={pendingLoadedRule}
              onConsumePendingLoadedRule={() => setPendingLoadedRule(null)}
            />
          )}
          {tab === 'correlation' && (
            <CorrelationRulesTab
              pendingLoadedCorrelation={pendingLoadedCorrelation}
              onConsumePendingLoadedCorrelation={() => setPendingLoadedCorrelation(null)}
            />
          )}
          {tab === 'ip-watch' && <IpWatchGroupsTab />}
          {tab === 'stix' && <StixFeedsTab />}
          {tab === 'test-event' && <TestEventTab />}
          {tab === 'simulate' && <CorrelationSimulationTab />}
        </div>
      </div>

      <FloatingRuleChat onLoadRule={handleLoadRule} onLoadCorrelation={handleLoadCorrelation} />
    </div>
  );
}
