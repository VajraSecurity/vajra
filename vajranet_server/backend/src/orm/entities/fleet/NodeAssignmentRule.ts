import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn
} from 'typeorm';

/** Only supported condition type for a node-assignment rule (IPv4 CIDR match). */
export const NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR = 'ip_cidr';

/** Default evaluation priority (lower runs first) for a newly created node-assignment rule. */
export const NODE_ASSIGNMENT_RULE_DEFAULT_PRIORITY = 100;

@Entity('node_assignment_rules')
export class NodeAssignmentRule {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ type: 'varchar', length: 255 })
    name: string;

    @Column({ type: 'int', default: NODE_ASSIGNMENT_RULE_DEFAULT_PRIORITY })
    priority: number;

    @Column({ type: 'boolean', default: true })
    enabled: boolean;

    @Column({ type: 'varchar', length: 50, default: NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR })
    conditionType: typeof NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR;

    @Column({ type: 'varchar', length: 100, name: 'condition_value' })
    conditionValue: string; // e.g. "10.0.5.0/24"

    @Column({ type: 'varchar', length: 255, name: 'group_id' })
    groupId: string;

    @Column({ type: 'varchar', length: 255, name: 'created_by' })
    createdBy: string;

    @Column({ type: 'timestamptz', name: 'last_run_at', nullable: true })
    lastRunAt: Date | null;

    @Column({ type: 'int', name: 'last_matched_count', nullable: true })
    lastMatchedCount: number | null;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt: Date;
}
