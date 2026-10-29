import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';

@Entity('certin_drafts')
@Index('idx_certin_drafts_user_id', ['userId'])
@Index('idx_certin_drafts_created_at', ['createdAt'])
export class CertinDraft {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'int' })
  userId!: number;

  @Column({ type: 'jsonb' })
  formData!: any;

  @Column({ type: 'simple-array', nullable: true })
  selectedAlertIds?: string[];

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt!: Date;

  @Column({ type: 'timestamptz', nullable: true })
  expiresAt?: Date | null;
}
