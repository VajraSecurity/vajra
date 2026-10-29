import { Smartphone } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export function AuthMethodCard() {
  return (
    <div className="relative flex items-start gap-3.5 rounded-xl border-2 border-blue-100 bg-blue-50/60 p-2.5">
      <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-blue-100 text-blue-600">
        <Smartphone className="size-5" aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <h3 className="typo-heading text-sm text-gray-900">Authenticator App</h3>
          <Badge variant="info">Recommended</Badge>
        </div>
        <p className="mt-1 text-sm text-gray-500">
          Generate time-based codes with Google Authenticator, Authy, or any TOTP app — no SMS, no network required.
        </p>
      </div>
    </div>
  );
}
