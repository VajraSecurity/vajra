import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

/**
 * Queues a Patch Management WS command for a host that was offline at
 * dispatch time (see createPatchJob in controllers/nodes/patch_management.ts).
 * Replayed — one command at a time, oldest first, gated on the host not
 * already having an in-flight patch_job_nodes row — when the host reconnects
 * (see websocket/patchDispatch.ts). Deleted once successfully redispatched.
 */
@Entity('pending_patch_commands')
@Index(['hostIdentifier'])
export class PendingPatchCommand {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'bigint', name: 'patch_job_node_id' })
  patchJobNodeId!: number;

  @Column({ type: 'text', name: 'host_identifier' })
  hostIdentifier!: string;

  @Column({ type: 'jsonb' })
  payload!: Record<string, unknown>;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;
}
