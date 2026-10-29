import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Copy, Check, X, KeyRound, QrCode } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useClipboard } from "@/hooks/useClipboard";
import { cn } from "@/lib/utils";

function formatSecret(secret: string) {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

interface QrSetupCardProps {
  qrCode: string;
  secret?: string;
}

type SetupView = "qr" | "key";

const TABS: { key: SetupView; label: string; icon: typeof QrCode }[] = [
  { key: "qr", label: "QR code", icon: QrCode },
  { key: "key", label: "Secret key", icon: KeyRound },
];

export function QrSetupCard({ qrCode, secret }: QrSetupCardProps) {
  const [view, setView] = useState<SetupView>("qr");
  const { copied, failed, copy } = useClipboard();

  const copyLabel = copied ? "Manual key copied" : failed ? "Copy failed" : "Copy manual key";

  return (
    <div className="rounded-xl border border-blue-100 bg-blue-50/40 p-4 sm:p-5">
      {secret && (
        <div
          role="tablist"
          aria-label="Two-factor setup method"
          className="mx-auto mb-4 flex w-fit gap-0.5 rounded-lg border border-blue-100 bg-white p-1 shadow-sm"
        >
          {TABS.map((tab) => {
            const isActive = view === tab.key;
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                id={`qr-setup-tab-${tab.key}`}
                type="button"
                role="tab"
                aria-selected={isActive}
                aria-controls="qr-setup-panel"
                onClick={() => setView(tab.key)}
                className={cn(
                  "relative flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300",
                  isActive ? "text-blue-700" : "text-gray-500 hover:text-gray-800"
                )}
              >
                {isActive && (
                  <motion.span
                    layoutId="qr-setup-toggle-bg"
                    transition={{ type: "spring", bounce: 0.25, duration: 0.4 }}
                    className="absolute inset-0 rounded-md bg-blue-100"
                  />
                )}
                <Icon className="relative z-10 size-3.5" aria-hidden="true" />
                <span className="relative z-10">{tab.label}</span>
              </button>
            );
          })}
        </div>
      )}

      <div
        id="qr-setup-panel"
        role="tabpanel"
        aria-labelledby={secret ? `qr-setup-tab-${view}` : undefined}
        className="grid"
      >
        <AnimatePresence mode="wait" initial={false}>
          {view === "qr" || !secret ? (
            <motion.div
              key="qr"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.16, ease: "easeOut" }}
              className="col-start-1 row-start-1 flex flex-col items-center gap-3"
            >
              <div className="rounded-xl border border-gray-200 bg-white p-3 shadow-sm">
                <img
                  src={qrCode}
                  alt="Scan this QR code with your authenticator app to link your account"
                  className="size-36 sm:size-40"
                />
              </div>
              <p className="max-w-[280px] text-center text-xs text-gray-500">
                Open your authenticator app and scan this code to link your account.
              </p>
            </motion.div>
          ) : (
            <motion.div
              key="key"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.16, ease: "easeOut" }}
              className="col-start-1 row-start-1 flex flex-col items-center gap-3"
            >
              <div className="flex w-full max-w-[280px] items-center gap-2 rounded-lg border border-gray-200 bg-white p-1.5 shadow-sm">
                <code className="flex-1 break-all font-mono text-sm tracking-[0.15em] text-gray-900">
                  {formatSecret(secret)}
                </code>
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={() => copy(secret)}
                  className="h-4 w-4 shrink-0"
                  aria-label={copyLabel}
                >
                  {copied ? (
                    <Check className="h-2 w-2 text-emerald-600" />
                  ) : failed ? (
                    <X className="h-2 w-2 text-red-600" />
                  ) : (
                    <Copy className="h-2 w-2" />
                  )}
                </Button>
              </div>
              <p className={cn("max-w-[280px] text-center text-xs", failed ? "text-red-600" : "text-gray-500")} role={failed ? "status" : undefined}>
                {failed
                  ? "Couldn't copy automatically — select the key above and press Ctrl/Cmd+C."
                  : "Enter this key manually in your authenticator app."}
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
