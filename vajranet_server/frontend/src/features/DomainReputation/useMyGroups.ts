import { useEffect, useState } from 'react';
import { getMyDomainReputationGroups } from '../../api/api';
import type { DomainReputationMyGroups } from '../../api/api';

/**
 * The caller's own group memberships for VirusTotal/AbuseIPDB scoping —
 * shared by Check Now and the watchlist "Add" modal, the two places that
 * need to resolve "which group's key am I about to use" client-side (config
 * Settings doesn't need this: the backend already scopes GET /providers to
 * the caller). `actableGroups` is the Group Admin subset that can actually
 * be used to run a check / own a watchlist entry — a Group Viewer membership
 * doesn't count, matching resolveWriteGroupId on the backend.
 */
export function useDomainReputationMyGroups() {
  const [myGroups, setMyGroups] = useState<DomainReputationMyGroups | null>(null);

  useEffect(() => {
    getMyDomainReputationGroups()
      .then((r) => setMyGroups(r.data))
      .catch(() => setMyGroups({ unrestricted: false, groups: [] }));
  }, []);

  const actableGroups = myGroups && !myGroups.unrestricted ? myGroups.groups.filter((g) => g.role === 'Group Admin') : [];

  return { myGroups, actableGroups };
}
