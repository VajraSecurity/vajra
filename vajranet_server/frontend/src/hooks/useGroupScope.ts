import { useEffect, useState, useCallback } from 'react';
import { fetchEndpointGroups, type EndpointGroup } from '../api/services/endpointGroupsApi';
import { getStoredUser } from '../services/auth';

/**
 * Shared group-scoping state for the Network Security area (Scan Scheduler,
 * and the Nessus/OpenVAS/Burp Suite setup+scans under Vulnerability Scanner).
 * Backs the same group-scoping model on every one of those surfaces so a
 * Super Administrator always gets the same "My Own (Super Admin)" + per-group
 * switcher, and a Group Admin always gets silently scoped to their own group
 * (or a plain picker if they happen to admin more than one) — instead of each
 * feature growing a slightly different one.
 *
 * `selectedGroupId === null` means "the Super Administrator's own scope, not
 * tied to any group" — mirrors the backend's groupId semantics in
 * backend/src/utils/scannerScope.ts exactly, so callers can pass
 * `selectedGroupId` straight through as the `groupId` query/body param.
 */
export interface UseGroupScopeResult {
  isSuperAdmin: boolean;
  /** Groups the caller can act on — all groups for a Super Admin, only their
   *  own membership(s) for a Group Admin. */
  groups: EndpointGroup[];
  loading: boolean;
  selectedGroupId: string | null;
  setSelectedGroupId: (groupId: string | null) => void;
  /** True when a picker should actually be shown: a Super Admin always gets
   *  one (their own scope is a real choice among groups), a Group Admin only
   *  when they admin more than one group — a single-group admin is silently
   *  scoped with nothing to pick. */
  showPicker: boolean;
}

export function useGroupScope(): UseGroupScopeResult {
  const [isSuperAdmin] = useState(() => getStoredUser()?.role === 'Super Administrator');
  const [groups, setGroups] = useState<EndpointGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // /groups is already server-side scoped (get_groups.ts): a Super Admin
      // gets every group, a Group Admin only their own membership(s).
      const fetched = await fetchEndpointGroups();
      setGroups(fetched);
      if (!isSuperAdmin) {
        // A Group Admin can never target the Super Admin's own (null) scope —
        // default to their single group if unambiguous, otherwise leave
        // unselected so the UI is forced to show a picker before any request
        // that needs groupId goes out.
        setSelectedGroupId((prev) => {
          if (prev && fetched.some((g) => g.groupId === prev)) return prev;
          return fetched.length === 1 ? fetched[0].groupId : null;
        });
      }
      // Super Admin: leave selectedGroupId as-is (default null = their own
      // scope) unless it no longer refers to a real group.
      else {
        setSelectedGroupId((prev) => (prev && !fetched.some((g) => g.groupId === prev) ? null : prev));
      }
    } catch (err) {
      console.error('Failed to load groups for scope selector:', err);
    } finally {
      setLoading(false);
    }
  }, [isSuperAdmin]);

  useEffect(() => {
    load();
  }, [load]);

  const showPicker = isSuperAdmin ? true : groups.length > 1;

  return { isSuperAdmin, groups, loading, selectedGroupId, setSelectedGroupId, showPicker };
}
