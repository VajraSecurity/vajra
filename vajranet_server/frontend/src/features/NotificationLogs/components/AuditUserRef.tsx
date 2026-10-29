/**
 * AuditUserRef — renders a "name <email>" label, falling back to an
 * AuditUserIdPeek chip when only a user id is known. Extracted verbatim, no
 * logic changes.
 */

import type { ReactNode } from 'react';
import type { AuditUserLite } from '../types';
import { AuditUserIdPeek } from './AuditUserIdPeek';

export function AuditUserRef({
  user,
  fallbackId,
}: {
  user: AuditUserLite | { name?: string | null; email?: string | null } | null | undefined;
  fallbackId?: string;
}): ReactNode {
  const u = user ?? null;
  const name = typeof u?.name === 'string' ? u.name.trim() : '';
  const email = typeof u?.email === 'string' ? u.email.trim() : '';
  if (name && email) return `${name} <${email}>`;
  if (name) return name;
  if (email) return email;
  if (fallbackId) return <AuditUserIdPeek userId={fallbackId} />;
  return '—';
}

