import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm';

/**
 * The sibling rule-engine console (routes/api/rule-engine.ts,
 * services/ruleEngineClient.ts) has no group/tenant concept at all — it's
 * flat JSON files on one box, with a single global live-instance process.
 * This table is the ONLY place "which vajranet group may manage this
 * resource" is tracked; the engine itself has no idea it exists. See
 * utils/ruleEngineScope.ts for how it's used.
 *
 * Phase 1 only ever writes 'ip_watch_group' rows — IP watch-group create/
 * delete/enable-disable, rules, correlation rules, threat-intel feeds, and
 * live-instance config all stay Super-Admin-only (see rule-engine.ts's
 * header comment), since none of those have a way to scope enforcement to
 * one group even if we tracked an owner for them. resource_type is kept
 * generic rather than hardcoded to make a future extension (e.g. scoped
 * rule authorship) an additive row, not a schema change.
 */
export const RULE_ENGINE_RESOURCE_TYPES = ['ip_watch_group'] as const;
export type RuleEngineResourceType = (typeof RULE_ENGINE_RESOURCE_TYPES)[number];

@Entity('rule_engine_resource_owners')
@Index(['resourceType', 'resourceKey'], { unique: true })
export class RuleEngineResourceOwner {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 32, name: 'resource_type' })
  resourceType!: RuleEngineResourceType;

  // The engine's own key for this resource — e.g. an IP watch group's
  // `name` (the engine has no numeric/UUID id for these, just a unique name).
  @Column({ type: 'varchar', length: 255, name: 'resource_key' })
  resourceKey!: string;

  // Soft reference to the fleet DB's nodes_groups.group_id — same
  // no-FK-possible pattern as UserGroupMembership.groupId (different
  // PostgreSQL DataSource, so no real foreign key is possible).
  @Column({ type: 'varchar', length: 255, name: 'owner_group_id' })
  ownerGroupId!: string;

  @Column({ type: 'varchar', length: 255, name: 'created_by', nullable: true })
  createdBy!: string | null;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;
}
