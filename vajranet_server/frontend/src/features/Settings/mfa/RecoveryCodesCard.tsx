import { motion } from "motion/react";
import { Copy, Check, X, Download, Printer, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useClipboard } from "@/hooks/useClipboard";

interface RecoveryCodesCardProps {
  codes: string[];
  generatedAt: Date | null;
  onDownload: () => void;
}

export function RecoveryCodesCard({ codes, generatedAt, onDownload }: RecoveryCodesCardProps) {
  const { copied, failed, copy } = useClipboard();

  const handlePrint = () => {
    const printWindow = window.open("", "_blank", "width=480,height=640");
    if (!printWindow) return;
    const escapeHtml = (s: string) =>
      s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

    printWindow.document.write(`<!doctype html><html><head><title>VajraNet Recovery Codes</title>
      <style>
        body { font-family: ui-monospace, "SF Mono", Menlo, monospace; padding: 32px; color: #111827; }
        h1 { font-size: 16px; margin: 0 0 4px; }
        p { font-size: 12px; color: #6b7280; margin: 0 0 20px; }
        ul { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        li { font-size: 15px; letter-spacing: 0.05em; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 14px; text-align: center; }
      </style></head><body>
      <h1>VajraNet Emergency Recovery Codes</h1>
      <p>Generated ${generatedAt ? escapeHtml(generatedAt.toLocaleString()) : ""} — each code works once. Store this printout somewhere safe.</p>
      <ul>${codes.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>
      </body></html>`);
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4">
        <ShieldAlert className="mt-0.5 size-5 shrink-0 text-amber-600" aria-hidden="true" />
        <div>
          <p className="text-sm font-bold text-amber-800">Save these 10 codes now</p>
          <p className="mt-0.5 text-xs text-amber-700/90">
            Each code works once. If you lose access to your authenticator app, they&apos;re the only way back into your account.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-blue-100 bg-blue-50/40 p-3">
        <div className="grid grid-cols-2 gap-2">
          {codes.map((c, i) => (
            <motion.div
              key={c}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03, duration: 0.2 }}
              className="flex items-center justify-center gap-1.5 rounded-lg border border-gray-200 bg-white py-2 font-mono text-sm font-semibold tracking-wider text-gray-900"
            >
              <span className="text-[10px] font-normal tracking-normal text-gray-400">
                {String(i + 1).padStart(2, "0")}
              </span>
              {c}
            </motion.div>
          ))}
        </div>
      </div>

      {generatedAt && (
        <p className="text-center text-[11px] text-gray-500">Generated {generatedAt.toLocaleString()}</p>
      )}

      <div className="grid grid-cols-3 gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => copy(codes.join("\n"))}
          className={
            failed
              ? "border-red-300 text-red-600 hover:bg-red-50 hover:text-red-700"
              : "border-gray-300 text-gray-700 hover:bg-gray-50 hover:text-gray-900"
          }
        >
          {copied ? (
            <Check className="text-emerald-600" aria-hidden="true" />
          ) : failed ? (
            <X aria-hidden="true" />
          ) : (
            <Copy aria-hidden="true" />
          )}
          {copied ? "Copied" : failed ? "Failed" : "Copy"}
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={onDownload}
          className="border-gray-300 text-gray-700 hover:bg-gray-50 hover:text-gray-900"
        >
          <Download aria-hidden="true" />
          Download
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={handlePrint}
          className="border-gray-300 text-gray-700 hover:bg-gray-50 hover:text-gray-900"
        >
          <Printer aria-hidden="true" />
          Print
        </Button>
      </div>
    </div>
  );
}
