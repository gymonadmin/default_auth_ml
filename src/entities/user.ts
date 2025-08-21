// src/entities/user.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import type { Profile } from './profile';

@Entity('users')
@Index('idx_users_email', ['email'])
@Index('users_email_unique_active', ['email'], { 
  unique: true, 
  where: '"deletedAt" IS NULL' 
})
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ 
    type: 'varchar', 
    length: 254, 
    nullable: false 
  })
  email!: string;

  @Column({ 
    type: 'boolean', 
    default: false, 
    nullable: false 
  })
  isVerified!: boolean;

  @Column({ 
    type: 'timestamptz', 
    nullable: true 
  })
  verifiedAt!: Date | null;

  @Column({ 
    type: 'timestamptz', 
    nullable: true 
  })
  deletedAt!: Date | null;

  @CreateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  createdAt!: Date;

  @UpdateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  updatedAt!: Date;

  // Virtual properties for manually joined data (not persisted to DB)
  profile?: Profile;
  sessions?: any[];
  magicSigninTokens?: any[];
  auditLogs?: any[];

  // Computed properties
  get isDeleted(): boolean {
    return this.deletedAt !== null;
  }

  get isActive(): boolean {
    return this.isVerified === true && (this.deletedAt === null || this.deletedAt === undefined);
  }

  // Methods
  markAsVerified(): void {
    this.isVerified = true;
    this.verifiedAt = new Date();
  }

  markAsDeleted(): void {
    this.deletedAt = new Date();
  }

  restore(): void {
    this.deletedAt = null;
  }
}
