import { useEffect, useState } from 'react';
import api from '../../api/axiosInstance';
import { NODES_URLS } from '../../api/urls';
import { fetchEndpointGroups, type EndpointGroup } from '../../api/services/endpointGroupsApi';

export interface FimNodeOption {
  host_identifier: string;
  hostname: string;
  status: string;
  os_platform: string;
}

/** Loads the node + group lists the app already exposes, for target / scope pickers. */
export function useFimNodes(enabled = true) {
  const [nodes, setNodes] = useState<FimNodeOption[]>([]);
  const [groups, setGroups] = useState<EndpointGroup[]>([]);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let cancel = false;
    setLoading(true);
    Promise.allSettled([
      api.get<{ nodes: FimNodeOption[] }>(NODES_URLS.NODES_IDENTIFIERS),
      fetchEndpointGroups(),
    ]).then(([n, g]) => {
      if (cancel) return;
      const errs: string[] = [];
      if (n.status === 'fulfilled') setNodes(n.value.data.nodes ?? []); else errs.push('Could not load hosts');
      if (g.status === 'fulfilled') setGroups(g.value); else errs.push('Could not load groups');
      setError(errs.length ? errs.join('; ') : null);
      setLoading(false);
    });
    return () => { cancel = true; };
  }, [enabled]);

  return { nodes, groups, loading, error };
}

export function nodeMatchesOs(n: FimNodeOption, os: 'linux' | 'windows'): boolean {
  const p = (n.os_platform || '').toLowerCase();
  if (os === 'windows') return p.includes('windows');
  return !p.includes('windows') && !p.includes('darwin') && !p.includes('mac');
}
