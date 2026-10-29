import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { VajraUser } from '../users/Users';

// Canonical, exhaustive list of audit trail actions. AuditTrailAction is derived from this
// array (rather than declared as a standalone union) so that any list built from it — e.g.
// the validActions allow-lists in audit_trail.ts / session_actions.ts — can never drift out
// of sync with the type as new actions are added here.
export const AUDIT_TRAIL_ACTIONS = [
  'LOGIN',
  'RENAME_NODE',
  'MARK_NODE_CRITICAL',
  'ISOLATE_NODE',
  'REENROLL_NODE',
  'ALERT_STATUS_UPDATE',
  'ALERT_ASSIGN_UPDATE',
  'ALERT_MARK_UPDATE',
  'USER_REGISTER',
  'PASSWORD_UPDATE',
  'PORT_BLOCK',
  'IP_BLOCK',
  'COMPLIANCE',
  'WIFI',
  'BLUETOOTH',
  'DEFENDER',
  'USB',
  'CLAMAV',
  'LOGOUT',
  'FORCE_PASSWORD_CHANGE',
  'CERTIN_DRAFT_START',
  'CERTIN_DRAFT_EDIT',
  'CERTIN_DRAFT_COMPLETE',
  'CERTIN_DRAFT_DOWNLOAD',
  'NETWORK_SCAN',
  'DATA_RETENTION_UPDATE',
  // DATA_RETENTION_UPDATE records only the policy edit. DATA_RETENTION_PURGE is
  // the deletion the policy then performs — one entry per table per run, with the
  // row count removed and the cutoff applied — so a missing log range can be
  // answered from the trail rather than inferred.
  'DATA_RETENTION_PURGE',
  'NESSUS_CONFIG',
  'NESSUS_SCAN',
  'OPENVAS_CONFIG',
  'OPENVAS_SCAN',
  'BURPSUITE_CONFIG',
  'BURPSUITE_SCAN',
  'POLICY_CREATE',
  'POLICY_UPDATE',
  'POLICY_DELETE',
  'POLICY_ASSIGN_TARGETS',
  // File Integrity Monitoring (/api/fim).
  'FIM_POLICY_CREATE',
  'FIM_POLICY_UPDATE',
  'FIM_POLICY_DELETE',
  'FIM_POLICY_PUBLISH',
  'FIM_BASELINE_INIT',
  'FIM_ALERT_CLOSE',
  'FIM_ALERT_REOPEN',
  'FIM_DRIFT_RESOLVE',
  'FIM_POLICY_TEMPLATE_UPGRADE',
  // Per-node Windows registry coverage (/api/fim/registry, FIM_REGISTRY_DESIGN §3.11/§4.4).
  'FIM_REG_SETTINGS',
  'FIM_REG_PROFILE_CHANGE',
  'FIM_REG_ASSIGN',
  'FIM_REG_RULE_ADD',
  'FIM_REG_RULE_REVOKE',
  'FIM_REG_WAIVER_REQUEST',
  'FIM_REG_WAIVER_DECISION',
  'FIM_REG_PUBLISH',
  'FIM_REG_AUTO_REPUBLISH',
  'FIM_REG_ROLLBACK',
  'FIM_REG_MEASURE',
  'FIM_REG_COMPACT',
  'FIM_REG_HYGIENE_ACK',
  'FIM_REG_MIGRATION',
  'FIM_REG_DENIED',
  'FIM_REG_ANCHOR',
  'FIM_REG_JOB',
  'NODE_ASSIGNMENT_RULE_CREATE',
  'NODE_ASSIGNMENT_RULE_UPDATE',
  'NODE_ASSIGNMENT_RULE_DELETE',
  'NODE_ASSIGNMENT_RULE_RUN',
  'GENERATE_AGENT_CERT_TOKEN',
  'REVOKE_AGENT_CERT_TOKEN',
  'PROVISION_AGENT_CERT',
  'PATCH_CHECK',
  'PATCH_APPLY',
  'PATCH_APPLY_FALLBACK',
  'PATCH_BUNDLE_UPLOADED',
  'PATCH_BUNDLE_UPLOAD_REJECTED',
  'PATCH_BUNDLE_PACKAGES_UPLOADED',
  'PATCH_REBOOT',
  'PATCH_BUNDLE_APPLY',
  'PATCH_BUNDLE_BUILT',
  'SCAN_SCHEDULE_CREATE',
  'SCAN_SCHEDULE_UPDATE',
  'SCAN_SCHEDULE_DELETE',
  'SCAN_SCHEDULE_RUN',
  'DOMAIN_REPUTATION_CONFIG',
  'DOMAIN_REPUTATION_CHECK',
  'DOMAIN_REPUTATION_TARGET_CREATE',
  'DOMAIN_REPUTATION_TARGET_UPDATE',
  'DOMAIN_REPUTATION_TARGET_DELETE',
  'AI_PROVIDER_CONFIG',
  // Vajra platform updates. CHECK is the outbound call to the update API
  // (recorded because it leaves the network and can fail); DISMISS is an
  // admin pressing "Ignore" on the update popup for one version.
  'PLATFORM_UPDATE_CHECK',
  'PLATFORM_UPDATE_DISMISS',
  'PLATFORM_UPDATE_APPLY',
  // Windows maintained-app (third-party software) install/uninstall —
  // deliberately WINDOWS_PATCH_*, not PATCH_* (those are the pre-existing,
  // unrelated Linux osupdate feature's audit actions above). DISPATCHED is
  // written the moment the WS send succeeds ("we told the agent to do this");
  // SUCCESS/FAILURE are written later, at completion-push time, from the
  // agent's own independently-verified outcome — see
  // WINDOWS_AGENT_PATCH_MANAGEMENT.md's audit-trail section on why dispatch
  // success must never be conflated with install success.
  'WINDOWS_PATCH_INSTALL_DISPATCHED',
  'WINDOWS_PATCH_INSTALL_SUCCESS',
  'WINDOWS_PATCH_INSTALL_FAILURE',
] as const;

export type AuditTrailAction = (typeof AUDIT_TRAIL_ACTIONS)[number];

/** Audit action for CERT-In/IRDAI/SEBI/org compliance snapshot writes and compliance agent commands. */
export const AUDIT_ACTION_COMPLIANCE: AuditTrailAction = 'COMPLIANCE';

export type AuditTrailStatus = 'success' | 'failure';

@Entity('audit_trail')
@Index(['userId'])
@Index(['email'])
@Index(['action'])
@Index(['createdAt'])
export class AuditTrail {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'varchar', length: 50 })
  action!: AuditTrailAction;

  @Column({ type: 'varchar', length: 20 })
  status!: AuditTrailStatus;

  @Column({ type: 'integer', nullable: true, name: 'user_id' })
  userId!: number | null;

  @ManyToOne(() => VajraUser, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'user_id' })
  user!: VajraUser | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  email!: string | null;

  @Column({ type: 'inet', nullable: true, name: 'ip_address' })
  ipAddress!: string | null;

  @Column({ type: 'text', nullable: true, name: 'user_agent' })
  userAgent!: string | null;

  /** Optional JSON for action-specific data (e.g. alert_id, host_identifier, new_hostname) */
  @Column({ type: 'jsonb', nullable: true })
  details!: Record<string, any> | null;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;
}
