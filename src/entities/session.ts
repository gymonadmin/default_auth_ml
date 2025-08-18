// src/entities/session.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';

@Entity('sessions')
@Index('sessions_token_hash_unique', ['tokenHash'], { unique: true })
@Index('idx_sessions_user_id', ['userId'])
@Index('idx_sessions_expires_at', ['expiresAt'])
@Index('idx_sessions_active', ['isActive'], { 
  where: '"isActive" = true' 
})
export class Session {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ 
    type: 'uuid', 
    nullable: false 
  })
  userId!: string;

  @Column({ 
    type: 'varchar', 
    length: 64, 
    nullable: false 
  })
  tokenHash!: string;

  @Column({ 
    type: 'timestamptz', 
    nullable: false 
  })
  expiresAt!: Date;

  @Column({ 
    type: 'inet', 
    nullable: true 
  })
  ipAddress!: string | null;

  @Column({ 
    type: 'text', 
    nullable: true 
  })
  userAgent!: string | null;

  @Column({ 
    type: 'varchar', 
    length: 2, 
    nullable: true 
  })
  country!: string | null;

  @Column({ 
    type: 'varchar', 
    length: 100, 
    nullable: true 
  })
  city!: string | null;

  @Column({ 
    type: 'boolean', 
    default: true, 
    nullable: false 
  })
  isActive!: boolean;

  @Column({ 
    type: 'timestamptz', 
    nullable: true 
  })
  lastAccessedAt!: Date | null;

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

  // Relationships - using string name to avoid circular imports
  @ManyToOne('User', 'sessions', {
    onDelete: 'CASCADE'
  })
  @JoinColumn({ 
    name: 'userId',
    foreignKeyConstraintName: 'fk_sessions_user'
  })
  user!: any;

  // Computed properties
  get isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  get isValid(): boolean {
    return this.isActive && !this.isExpired;
  }

  get timeUntilExpiry(): number {
    const now = new Date().getTime();
    const expiryTime = this.expiresAt.getTime();
    return Math.max(0, expiryTime - now);
  }

  // Methods
  updateLastAccessed(): void {
    this.lastAccessedAt = new Date();
  }

  revoke(): void {
    this.isActive = false;
  }

  extend(newExpiryDate: Date): void {
    this.expiresAt = newExpiryDate;
    this.updateLastAccessed();
  }

  updateLocation(ipAddress: string | null, country: string | null, city: string | null): void {
    this.ipAddress = ipAddress;
    this.country = country;
    this.city = city;
  }
}
