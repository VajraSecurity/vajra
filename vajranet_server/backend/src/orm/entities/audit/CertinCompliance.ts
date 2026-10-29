import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';

@Entity('certin_compliance')
@Index('idx_certin_compliance_user_node', ['userId', 'nodeHostIdentifier'], { unique: true })
@Index('idx_certin_compliance_updated_at', ['updatedAt'])
export class CertinCompliance {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'int' })
  userId!: number;

  @Column({ type: 'text' })
  nodeHostIdentifier!: string;

  @Column({ type: 'jsonb' })
  statusByPointer!: Record<string, 'yes' | 'no'>;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt!: Date;
}
