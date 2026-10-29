import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

export const GROUP_MEMBERSHIP_ROLES = ['Group Admin', 'Group Viewer'] as const;
export type GroupMembershipRole = (typeof GROUP_MEMBERSHIP_ROLES)[number];

/** Per-group access level: read + act on that group's nodes. */
export const GROUP_MEMBERSHIP_ROLE_ADMIN: GroupMembershipRole = 'Group Admin';
/** Per-group access level: read only. */
export const GROUP_MEMBERSHIP_ROLE_VIEWER: GroupMembershipRole = 'Group Viewer';

@Entity('user_group_memberships')
@Index(['userId', 'groupId'], { unique: true })
export class UserGroupMembership {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'int', name: 'user_id' })
  userId!: number;

  // Soft reference to the fleet DB's nodes_groups.group_id / nodes.owner_group_id
  // values. No FK possible — groups live in a separate PostgreSQL DataSource.
  @Column({ type: 'varchar', length: 255, name: 'group_id' })
  groupId!: string;

  // Access level within this one group: 'Group Admin' can read and act on the
  // group's nodes, 'Group Viewer' can only read. Lets one person hold a
  // different level of access in each group they belong to.
  @Column({ type: 'varchar', length: 32, name: 'role', default: GROUP_MEMBERSHIP_ROLE_ADMIN })
  role!: GroupMembershipRole;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;
}
