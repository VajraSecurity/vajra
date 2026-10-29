import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
} from 'typeorm';
import { MaintainedApp } from './MaintainedApp';

/**
 * One row per known version of a MaintainedApp; exactly one is_current=true
 * row per maintained_app_id at a time. install_script/uninstall_script are
 * the literal PowerShell text forwarded verbatim to the agent — never
 * templated server-side (see WINDOWS_AGENT_PATCH_MANAGEMENT.md's "Injection
 * safety" section on why the script is never string-interpolated).
 *
 * Schema-tracked by migration backend/migrations/011_add_windows_maintained_apps.sql
 * — see MaintainedApp.ts's header comment; this entity exists for schema
 * drift-detection only, controllers use raw fleetDb.query(...).
 */
@Entity('maintained_app_versions')
@Index('idx_mav_app_version', ['maintainedAppId', 'version'], { unique: true })
@Index('idx_mav_current', ['maintainedAppId', 'isCurrent'])
export class MaintainedAppVersion {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'bigint', name: 'maintained_app_id' })
  maintainedAppId!: number;

  @ManyToOne(() => MaintainedApp, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'maintained_app_id' })
  maintainedApp!: MaintainedApp;

  @Column({ type: 'varchar', length: 50 })
  version!: string;

  @Column({ type: 'text', nullable: true, name: 'installer_url' })
  installerUrl!: string | null;

  // Required together with installerUrl — enforced at the API/import layer,
  // mirroring the agent's own installer_url+sha256 pairing rule.
  @Column({ type: 'varchar', length: 64, nullable: true })
  sha256!: string | null;

  @Column({ type: 'text', name: 'install_script' })
  installScript!: string;

  @Column({ type: 'text', name: 'uninstall_script' })
  uninstallScript!: string;

  @Column({ type: 'boolean', default: false, name: 'is_current' })
  isCurrent!: boolean;

  // e.g. the source manifest slug, for traceability/regeneration only.
  @Column({ type: 'varchar', length: 300, nullable: true, name: 'source_ref' })
  sourceRef!: string | null;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;
}
