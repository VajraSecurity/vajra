import type { DomainReputationProviderName } from '../../../orm/entities/fleet/DomainReputationProviderConfig';
import type { DomainReputationVerdict } from '../../../orm/entities/fleet/DomainReputationCheckResult';
import type { DomainReputationTargetType } from '../../../orm/entities/fleet/DomainReputationTarget';

export interface NormalizedReputationResult {
  provider: DomainReputationProviderName;
  verdict: DomainReputationVerdict;
  score: number | null;
  summary: string;
  raw: any;
  /**
   * True when the provider answered from an incomplete check (the manual
   * server's `partial` flag): the verdict rests only on whoever replied in time
   * and must not be read as fully corroborated. Absent means "not applicable",
   * not "complete".
   */
  partial?: boolean;
  /** The manual server's correlation ID, for matching against its own logs. */
  requestId?: string | null;
}

// groupId scopes which config the checker loads (see client.ts's
// getProviderConfig); null means the org-wide default. checkManualServer ignores
// it, since the 'manual' provider is never group-scoped — a two-parameter
// function still satisfies this type.
export type ReputationChecker = (
  value: string,
  type: DomainReputationTargetType,
  groupId: string | null,
) => Promise<NormalizedReputationResult>;
