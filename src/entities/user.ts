// src/entities/user.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  OneToOne,
  Index,
} from 'typeorm';
import { Profile } from './profile';
import { Session } from './session';
import { MagicSigninToken } from './magic-signin-token';
import { AuditLog } from './audit-log';

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

  // Relationships
  @OneToOne(() => Profile, profile => profile.user, {
    cascade: ['remove'],
    onDelete: 'CASCADE'
  })
  profile?: Profile;

  @OneToMany(() => Session, session => session.user, {
    cascade: ['remove'],
    onDelete: 'CASCADE'
  })
  sessions?: Session[];

  @OneToMany(() => MagicSigninToken, token => token.user, {
    cascade: ['remove'],
    onDelete: 'CASCADE'
  })
  magicSigninTokens?: MagicSigninToken[];

  @OneToMany(() => AuditLog, auditLog => auditLog.user, {
    cascade: ['remove'],
    onDelete: 'CASCADE'
  })
  auditLogs?: AuditLog[];

  // Computed properties
  get isDeleted(): boolean {
    return this.deletedAt !== null;
  }

  get isActive(): boolean {
    return this.isVerified && !this.isDeleted;
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
