import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('ai_conversations')
@Index(['userId'])
export class AiConversation {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ type: 'integer', name: 'user_id' })
  userId!: number;

  @Column({ type: 'varchar', length: 200, default: 'New Chat' })
  title!: string;

  /** Full message history sent to the AI API (role + content pairs) */
  @Column({ type: 'jsonb', default: [] })
  messages!: unknown[];

  /** Display bubbles stored for UI restore (tool events, etc.) */
  @Column({ type: 'jsonb', default: [] })
  bubbles!: unknown[];

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
