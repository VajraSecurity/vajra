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

export type AuditAction =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGIN_CAPTCHA_TRIGGERED'
  | 'PASSWORD_CHANGE'
  | 'PASSWORD_RESET'
  | 'PROFILE_UPDATE'
  | 'OAUTH_LOGIN'
  | 'LOGOUT'
  | 'ACCOUNT_CREATED'
  | 'SESSION_INVALIDATED';

export type AuditStatus = 'success' | 'failure';
export type AuditSeverity = 'low' | 'medium' | 'high' | 'critical';

@Entity('audit_logs')
@Index(['userId'])
@Index(['email'])
@Index(['action'])
@Index(['createdAt'])
@Index(['severity'])
export class AuditLog {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'varchar', length: 100 })
  action!: AuditAction;

  @Column({ type: 'varchar', length: 20 })
  status!: AuditStatus;

  @Column({ type: 'varchar', length: 20, default: 'medium' })
  severity!: AuditSeverity;

  @Column({ type: 'integer', nullable: true })
  userId!: number | null;

  @ManyToOne(() => VajraUser, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'user_id' })
  user!: VajraUser | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  email!: string | null;

  @Column({ type: 'inet', nullable: true })
  ipAddress!: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent!: string | null;

  @Column({ type: 'jsonb', nullable: true })
  details!: Record<string, any> | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt!: Date;
}
