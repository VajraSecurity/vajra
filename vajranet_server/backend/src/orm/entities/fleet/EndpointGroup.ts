import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn
} from 'typeorm';

@Entity('nodes_groups')
export class EndpointGroup {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ type: 'varchar', length: 255 })
    name: string;

    @Column({ type: 'varchar', length: 255, unique: true, name: 'group_id' })
    groupId: string;

    @Column({ type: 'varchar', length: 255, name: 'created_by' })
    createdBy: string;

    @Column({ type: 'bigint' })
    unixtime: string;

    @Column({ type: 'varchar', length: 255 })
    organisation: string;

    @Column({ type: 'varchar', length: 255 })
    manager: string;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt: Date;
}
