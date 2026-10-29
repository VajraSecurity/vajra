import type { FimAlert } from '../../api/services/fimApi';
import { getStoredUser } from '../../services/auth';

export interface CurrentUser { id: number | null; email: string | null }

/** The signed-in user from the existing auth cache (id / e-mail), or null when unavailable. */
export function currentUser(): CurrentUser | null {
  try {
    const u = getStoredUser();
    if (!u) return null;
    const id = Number(u.id);
    const email = typeof u.email === 'string' && u.email ? u.email : null;
    const out = { id: Number.isSafeInteger(id) && id > 0 ? id : null, email };
    return out.id === null && out.email === null ? null : out;
  } catch { return null; }
}

function parseMeta(m: unknown): Record<string, unknown> | null {
  if (typeof m === 'string') { try { const o = JSON.parse(m); return o && typeof o === 'object' ? o as Record<string, unknown> : null; } catch { return null; } }
  return m && typeof m === 'object' ? m as Record<string, unknown> : null;
}

/**
 * A fim_config (oversight) alert raised by the current user's own action: the server refuses to
 * let that user close it. Decided by metadata.byUserId when both ids are known, else by
 * metadata.by (e-mail, case-insensitive). False when the user or the metadata is unavailable.
 */
export function isOwnOversightAlert(a: Pick<FimAlert, 'alertType' | 'metadata'>, me: CurrentUser | null): boolean {
  if (a.alertType !== 'fim_config' || !me) return false;
  const meta = parseMeta(a.metadata);
  if (!meta) return false;
  const byId = Number(meta.byUserId);
  if (meta.byUserId != null && Number.isSafeInteger(byId) && byId > 0 && me.id !== null) return byId === me.id;
  return typeof meta.by === 'string' && !!me.email && meta.by.trim().toLowerCase() === me.email.trim().toLowerCase();
}

export const OWN_OVERSIGHT_TEXT = 'This configuration alert was raised by your own action: another Super Administrator must review and close it.';
