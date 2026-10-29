import type { DomainReputationGroupScopedProviderStatus } from '../../api/api';
import ApiKeySettingsCard from './ApiKeySettingsCard';

interface GroupScopedProviderSettingsProps {
  title: string;
  description: string;
  status: DomainReputationGroupScopedProviderStatus | null;
  onConfigChange: () => void;
}

/**
 * VirusTotal/AbuseIPDB are per-group: a Super Admin sees the org-wide default
 * plus every group's config (and may edit any of them); a Group Admin sees
 * only the group(s) they administer. Each slot in `status.configs` renders as
 * its own card — one card per group is intentional, not a layout quirk, since
 * each is an independent credential a different admin may own.
 */
const GroupScopedProviderSettings = ({ title, description, status, onConfigChange }: GroupScopedProviderSettingsProps) => {
  if (!status) return null;

  return (
    <>
      {status.configs.map((entry) => (
        <ApiKeySettingsCard
          key={entry.group_id ?? '__org_default__'}
          provider={status.provider}
          title={title}
          description={description}
          groupId={entry.group_id}
          groupLabel={entry.is_org_default ? 'Organization Default' : (entry.group_name ?? entry.group_id ?? '')}
          status={entry}
          onConfigChange={onConfigChange}
        />
      ))}
    </>
  );
};

export default GroupScopedProviderSettings;
