import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { VajraUser } from '../users/Users';

@Entity('user_sessions')
@Index(['userId'])
@Index(['isActive'])
@Index(['loginTime'])
export class UserSession {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'integer' })
  userId!: number;

  @ManyToOne(() => VajraUser, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user!: VajraUser;

  @Column({ type: 'inet', nullable: true })
  ipAddress!: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  loginTime!: Date;

  @Column({ type: 'timestamptz', nullable: true })
  logoutTime!: Date | null;

  @Column({ type: 'boolean', default: true })
  isActive!: boolean;

  @Column({ type: 'integer', nullable: true })
  durationSeconds!: number | null;

  @Column({ type: 'varchar', nullable: true })
  logoutReason!: string | null;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt!: Date;
}
