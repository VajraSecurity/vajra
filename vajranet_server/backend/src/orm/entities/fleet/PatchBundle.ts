import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { PatchBundleFamily, PatchBundleManifest } from '../../../utils/patchBundle';

/**
 * One row per uploaded, signature-verified Patch Bundle — a signed,
 * versioned snapshot of OS packages (Phase 1: deb/rpm only) produced OFFLINE
 * by backend/src/scripts/sign-patch-bundle.ts and accepted by
 * `POST /api/patch/bundles` only after its ECDSA signature verifies against
 * the configured PATCH_BUNDLE_VERIFY_KEY_PATH public key (see
 * utils/patchBundle.ts). A failed verification is never stored — every row
 * in this table passed signature verification at upload time.
 *
 * `manifestJson` holds the full verified manifest, including the per-package
 * list — this phase does not normalize packages into their own table (see
 * migration 006_add_patch_bundles_table.sql). Schema-tracked by that
 * migration; this codebase's controllers use raw fleetDb.query(...) against
 * this table name (see controllers/nodes/patch_bundles.ts) — this entity
 * exists for schema consistency/drift-detection (findMissingEntityTables()),
 * not as the query interface.
 */
@Entity('patch_bundles')
@Unique(['bundleId'])
@Index(['family'])
@Index(['family', 'osMatch'])
export class PatchBundle {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'text', name: 'bundle_id' })
  bundleId!: string;

  @Column({ type: 'text' })
  version!: string;

  @Column({ type: 'text' })
  family!: PatchBundleFamily;

  @Column({ type: 'text', name: 'os_match' })
  osMatch!: string;

  @Column({ type: 'text' })
  channel!: string;

  @Column({ type: 'jsonb', name: 'manifest_json' })
  manifestJson!: PatchBundleManifest;

  @Column({ type: 'boolean', default: true, name: 'signature_valid' })
  signatureValid!: boolean;

  // Original signed-manifest wire bytes (base64), verbatim from the upload
  // request — see migration 008_add_patch_bundle_raw_signed.sql. Required to
  // forward a re-verifiable signed manifest to the agent's apply_bundle
  // action; manifestJson alone cannot serve this (parse→re-stringify is not
  // guaranteed to reproduce the exact signed byte sequence). Nullable: a row
  // uploaded before this migration has neither and cannot be dispatched via
  // the bundle-apply path until re-uploaded.
  @Column({ type: 'text', nullable: true })
  payload!: string | null;

  @Column({ type: 'text', nullable: true })
  signature!: string | null;

  @Column({ type: 'integer', name: 'packages_count' })
  packagesCount!: number;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'integer', nullable: true, name: 'created_by_id' })
  createdById!: number | null;

  @Column({ type: 'text', nullable: true, name: 'created_by_email' })
  createdByEmail!: string | null;
}
