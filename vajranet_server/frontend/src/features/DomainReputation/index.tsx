import { useCallback, useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { AlertCircle } from 'lucide-react';
import { Meteors } from '@/components/ui/meteors';
import { DuoSpinner } from '@/components/ui/loading';
import { DomainReputationIcon } from '@/components/icons/navIcons';
import { getDomainReputationProviders } from '../../api/api';
import type { DomainReputationProviderStatus } from '../../api/api';
import DomainReputationPanel from './DomainReputationPanel';

const DomainReputationHub = () => {
  const [providerStatuses, setProviderStatuses] = useState<DomainReputationProviderStatus[] | null>(null);
  const [loadError, setLoadError] = useState(false);

  const loadProviders = useCallback(async () => {
    try {
      const resp = await getDomainReputationProviders();
      setProviderStatuses(resp.data);
      setLoadError(false);
    } catch {
      // Leave providerStatuses as-is (null on first load) rather than [] —
      // an empty array reads downstream as "genuinely nothing configured"
      // and would wrongly tell an already-configured user to reconfigure.
      setLoadError(true);
    }
  }, []);

  useEffect(() => { loadProviders(); }, [loadProviders]);

  return (
    <div className="h-screen overflow-hidden bg-[#f8f9fb] flex flex-col">
      <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5 flex-1 flex flex-col min-h-0 w-full">

        <motion.header
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg shadow-blue-950/20 ring-1 ring-white/10 p-5 sm:p-6 mb-5 text-white shrink-0"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={30} className="!bg-white before:!from-white before:!to-transparent" />
          <div
            className="pointer-events-none absolute inset-0 opacity-[0.07]"
            style={{
              backgroundImage:
                'linear-gradient(rgba(255,255,255,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.6) 1px, transparent 1px)',
            }}
          />
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <DomainReputationIcon className="w-6 h-6 mr-2" />
                Domain Reputation
              </h1>
              <p className="mt-1 text-sm text-blue-100/90">
                Check domains and IPs on demand against your Vajra Reputation Engine, VirusTotal, and AbuseIPDB — or schedule recurring checks against VirusTotal and AbuseIPDB
              </p>
            </div>
          </div>
        </motion.header>

        <div className="flex-1 min-h-0 flex flex-col">
          {providerStatuses === null ? (
            loadError ? (
              <div className="flex flex-col items-center justify-center gap-3 py-24 text-slate-500">
                <AlertCircle className="h-6 w-6 text-red-500" strokeWidth={2} />
                <p className="text-sm font-medium">Couldn't load reputation providers.</p>
                <button
                  type="button"
                  onClick={() => void loadProviders()}
                  className="text-sm font-semibold text-blue-700 hover:underline"
                >
                  Try again
                </button>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center gap-3 py-24 text-slate-400">
                <DuoSpinner size="lg" className="text-[rgb(4,34,119)]" />
                <p className="text-sm font-medium">Loading providers…</p>
              </div>
            )
          ) : (
            <DomainReputationPanel providerStatuses={providerStatuses} onConfigChange={loadProviders} />
          )}
        </div>
      </div>
    </div>
  );
};

export default DomainReputationHub;
