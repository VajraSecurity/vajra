import bcrypt from 'bcryptjs';
import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { BCRYPT_SALT_ROUNDS } from '../../../consts/auth';

export const USER_ROLES = ['Super Administrator', 'Group Admin', 'Viewer'] as const;
export type UserRole = (typeof USER_ROLES)[number];

export const SUPER_ADMIN_ROLE: UserRole = 'Super Administrator';

export const GROUP_ADMIN_ROLE: UserRole = 'Group Admin';
/** Role assigned when none is specified/valid, and the least-privileged role. */
export const DEFAULT_USER_ROLE: UserRole = 'Viewer';

@Entity('vajra_users')
export class VajraUser {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'varchar', length: 255 })
  name!: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email!: string;

  @Column({ type: 'varchar', length: 20 })
  mobile!: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  company!: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  address!: string | null;

  @Column({ type: 'varchar', length: 32, default: DEFAULT_USER_ROLE })
  role!: UserRole;

  // Built-in avatar id (1-4) or 999 = custom uploaded image
  @Column({ type: 'int', default: 1 })
  avatar_id!: number;

  // Small base64 data URL for the custom avatar; only ever served to its owner
  @Column({ type: 'text', nullable: true })
  avatar_image!: string | null;

  // Password (nullable for legacy accounts)
  @Column({ type: 'text', nullable: true })
  password_hash!: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updated_at!: Date;

  // Password hash — async (matches checkIfPasswordMatch's bcrypt.compare
  // below), so hashing doesn't block the Node event loop for every other
  // concurrent request while it runs. bcrypt.hashSync at BCRYPT_SALT_ROUNDS
  // takes on the order of ~200ms; synchronous, that stalls the entire
  // process (WS heartbeats, in-flight requests, everything) for that long
  // on every registration/password change.
  async hashPassword() {
    if (this.password_hash) {
      this.password_hash = await bcrypt.hash(this.password_hash, BCRYPT_SALT_ROUNDS);
    }
  }

  @Column({ type: 'boolean', default: false })
  forcePasswordChange!: boolean;

  @Column({ type: 'int', default: 0 })
  session_version!: number;

  @Column({ type: 'boolean', default: false })
  suspended!: boolean;
 @Column({ type: 'varchar', nullable: true })
  mfa_secret!: string | null;

  @Column({ type: 'boolean', default: false })
  mfa_enabled!: boolean;

  @Column({ type: 'text', array: true, default: () => "'{}'" })
  recovery_codes!: string[];

  @Column({ type: 'varchar', nullable: true })
  security_question_1!: string | null;

  @Column({ type: 'text', nullable: true })
  security_answer_1_hash!: string | null;

  @Column({ type: 'varchar', nullable: true })
  security_question_2!: string | null;

  @Column({ type: 'text', nullable: true })
  security_answer_2_hash!: string | null;

  // Password checker
  async checkIfPasswordMatch(unencryptedPassword: string): Promise<boolean> {
    if (!this.password_hash) return false;
    return bcrypt.compare(unencryptedPassword, this.password_hash);
  }
}
