import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ArrowUturnLeftIcon, ClipboardIcon, QuestionMarkCircleIcon } from "@heroicons/react/24/outline";
import { useToast } from "../context/useToast";

export default function NotFound() {
  const location = useLocation();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const [copied, setCopied] = useState(false);

  const pathText = useMemo(() => location.pathname || "/", [location.pathname]);

  const copyPath = async () => {
    try {
      await navigator.clipboard.writeText(pathText);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be blocked by the browser; select the text manually instead.
      showToast(`Clipboard unavailable — copy manually: ${pathText}`, "warning");
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden flex items-center justify-center bg-[#f8f9fb] px-4 py-12">
      <div aria-hidden className="absolute inset-0 -z-10">
        <div className="absolute -top-28 -left-28 h-80 w-80 rounded-full bg-[#5044E5]/20 blur-3xl" />
        <div className="absolute top-24 -right-40 h-96 w-96 rounded-full bg-cyan-400/15 blur-3xl" />
        <div className="absolute inset-0 opacity-30 bg-[linear-gradient(to_right,rgba(2,6,23,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(2,6,23,0.06)_1px,transparent_1px)] bg-[size:56px_56px]" />
      </div>

      <div className="w-full max-w-4xl">
        <div className="bg-white/85 backdrop-blur border border-slate-200 rounded-3xl shadow-[0_16px_60px_rgba(15,23,42,0.12)] overflow-hidden">
          <div className="p-6 md:p-8">
            <div className="grid gap-8 md:grid-cols-[1.05fr_0.95fr] md:items-center">
              <section>
                <div className="inline-flex items-center gap-2 rounded-full border border-[#5044E5]/20 bg-[#5044E5]/10 px-3 py-1.5 text-xs font-semibold tracking-wide text-[#5044E5]">
                  <span className="inline-flex h-2 w-2 rounded-full bg-[#5044E5]" />
                  Vajra Security • 404
                </div>

                <div className="mt-4 flex items-start gap-4">
                  <div className="h-14 w-14 rounded-2xl bg-[#5044E5]/10 border border-[#5044E5]/15 flex items-center justify-center">
                    <QuestionMarkCircleIcon className="h-8 w-8 text-[#5044E5]" />
                  </div>

                  <div className="min-w-0">
                    <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-slate-900 leading-none">
                      Page Not Found
                    </h1>
                    <p className="mt-3 text-sm md:text-base text-slate-600 leading-relaxed">
                      We couldn&apos;t find the page you were looking for. The URL may be mistyped or the route may have
                      moved.
                    </p>
                  </div>
                </div>

                <div className="mt-6 rounded-2xl border border-slate-200 bg-gradient-to-br from-blue-50/60 via-white to-indigo-50/50 p-5">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Requested URL</p>
                  <div className="mt-2 flex items-start gap-3">
                    <code className="flex-1 break-all font-mono text-sm text-slate-900 bg-white/70 border border-slate-200 rounded-xl px-3 py-2">
                      {pathText}
                    </code>
                    <button
                      type="button"
                      onClick={copyPath}
                      aria-label={copied ? "Copied URL path" : "Copy URL path"}
                      className="shrink-0 inline-flex items-center justify-center h-10 w-10 rounded-xl border border-slate-200 bg-white/70 hover:bg-white transition shadow-sm"
                    >
                      <ClipboardIcon className="h-4 w-4 text-slate-600" />
                    </button>
                  </div>
                  <p className="mt-2 text-xs text-slate-500">{copied ? "Copied!" : "Copy this path for support/debugging."}</p>
                </div>
              </section>

              <aside className="flex flex-col">
                <div className="rounded-2xl border border-slate-200 bg-white/60 p-6">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Quick Actions</p>
                    <div className="flex items-center gap-2 rounded-full bg-slate-50 border border-slate-200 px-3 py-1.5">
                      <span className="text-sm font-bold text-slate-900">404</span>
                      <span className="text-[11px] text-slate-500">Not found</span>
                    </div>
                  </div>

                  <div className="mt-5 flex flex-col gap-3">
                    <Link
                      to="/dashboard"
                      className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-blue-600 text-white font-semibold shadow-sm hover:bg-blue-700 transition"
                    >
                      Back to Dashboard
                    </Link>
                    <Link
                      to="/login"
                      className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl border border-slate-300 bg-white text-slate-800 font-semibold hover:bg-slate-50 transition"
                    >
                      Go to Login
                    </Link>

                    <button
                      type="button"
                      onClick={() => navigate(-1)}
                      className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-white text-slate-700 font-semibold border border-slate-200 hover:bg-slate-50 transition"
                    >
                      <ArrowUturnLeftIcon className="h-5 w-5" />
                      Go back
                    </button>
                  </div>

                  <div className="mt-5 rounded-xl border border-blue-100 bg-blue-50 px-4 py-3">
                    <p className="text-sm font-semibold text-blue-900">Tip</p>
                    <p className="text-sm text-blue-900/80 mt-1 leading-relaxed">
                      If you&apos;re logged in, use the left sidebar to navigate to the right module. Otherwise, sign in to
                      access the dashboard.
                    </p>
                  </div>
                </div>
              </aside>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

