// src/entities/magic-signin-token.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('magic_signin_tokens')
@Index('magic_signin_tokens_token_hash_unique', ['tokenHash'], { unique: true })
@Index('idx_magic_signin_tokens_user_id', ['userId'])
@Index('idx_magic_signin_tokens_email', ['email'])
@Index('idx_magic_signin_tokens_expires_at', ['expiresAt'])
@Index('idx_magic_signin_tokens_used', ['isUsed'], { 
  where: '"isUsed" = false' 
})
export class MagicSigninToken {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ 
    type: 'uuid', 
    nullable: true 
  })
  userId!: string | null;

  @Column({ 
    type: 'varchar', 
    length: 254, 
    nullable: false 
  })
  email!: string;

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
    type: 'boolean', 
    default: false, 
    nullable: false 
  })
  isUsed!: boolean;

  @Column({ 
    type: 'timestamptz', 
    nullable: true 
  })
  usedAt!: Date | null;

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
    type: 'varchar', 
    length: 500, 
    nullable: true 
  })
  redirectUrl!: string | null;

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

  // NO RELATIONSHIPS DEFINED HERE
  // We'll handle relationships through queries instead

  // Computed properties
  get isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  get isValid(): boolean {
    return !this.isUsed && !this.isExpired;
  }

  get timeUntilExpiry(): number {
    const now = new Date().getTime();
    const expiryTime = this.expiresAt.getTime();
    return Math.max(0, expiryTime - now);
  }

  get isForNewUser(): boolean {
    return this.userId === null;
  }

  get isForExistingUser(): boolean {
    return this.userId !== null;
  }

  // Methods
  markAsUsed(): void {
    this.isUsed = true;
    this.usedAt = new Date();
  }

  linkToUser(userId: string): void {
    this.userId = userId;
  }

  updateLocation(ipAddress: string | null, country: string | null, city: string | null): void {
    this.ipAddress = ipAddress;
    this.country = country;
    this.city = city;
  }

  setRedirectUrl(url: string | null): void {
    this.redirectUrl = url;
  }
}
