// src/entities/audit-log.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';

export enum AuditEvent {
  ACCOUNT_CONFIRMED = 'account_confirmed',
  SIGNIN_SUCCESS = 'signin_success',
  SIGNIN_FAILED = 'signin_failed',
  SIGNOUT = 'signout',
  MAGIC_LINK_SENT = 'magic_link_sent',
  MAGIC_LINK_VERIFIED = 'magic_link_verified',
  MAGIC_LINK_EXPIRED = 'magic_link_expired',
  SESSION_CREATED = 'session_created',
  SESSION_EXPIRED = 'session_expired',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
}

@Entity('audit_logs')
@Index('idx_audit_logs_user_id', ['userId'])
@Index('idx_audit_logs_email', ['email'])
@Index('idx_audit_logs_event', ['event'])
@Index('idx_audit_logs_success', ['success'])
@Index('idx_audit_logs_created_at', ['createdAt'])
@Index('idx_audit_logs_correlation_id', ['correlationId'])
export class AuditLog {
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
    type: 'enum',
    enum: AuditEvent,
    nullable: false 
  })
  event!: AuditEvent;

  @Column({ 
    type: 'jsonb', 
    nullable: true 
  })
  context!: Record<string, any> | null;

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
    length: 36, 
    nullable: true 
  })
  correlationId!: string | null;

  @Column({ 
    type: 'boolean', 
    default: true, 
    nullable: false 
  })
  success!: boolean;

  @Column({ 
    type: 'text', 
    nullable: true 
  })
  errorMessage!: string | null;

  @CreateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  createdAt!: Date;

  // Relationships - using string name to avoid circular imports
  @ManyToOne('User', 'auditLogs', {
    onDelete: 'CASCADE',
    nullable: true
  })
  @JoinColumn({ 
    name: 'userId',
    foreignKeyConstraintName: 'fk_audit_logs_user'
  })
  user?: any;

  // Static factory methods
  static createSuccess(
    email: string,
    event: AuditEvent,
    options: {
      userId?: string;
      context?: Record<string, any>;
      ipAddress?: string;
      userAgent?: string;
      country?: string;
      city?: string;
      correlationId?: string;
    } = {}
  ): Partial<AuditLog> {
    return {
      email,
      event,
      userId: options.userId || null,
      context: options.context || null,
      ipAddress: options.ipAddress || null,
      userAgent: options.userAgent || null,
      country: options.country || null,
      city: options.city || null,
      correlationId: options.correlationId || null,
      success: true,
      errorMessage: null,
    };
  }

  static createFailure(
    email: string,
    event: AuditEvent,
    errorMessage: string,
    options: {
      userId?: string;
      context?: Record<string, any>;
      ipAddress?: string;
      userAgent?: string;
      country?: string;
      city?: string;
      correlationId?: string;
    } = {}
  ): Partial<AuditLog> {
    return {
      email,
      event,
      userId: options.userId || null,
      context: options.context || null,
      ipAddress: options.ipAddress || null,
      userAgent: options.userAgent || null,
      country: options.country || null,
      city: options.city || null,
      correlationId: options.correlationId || null,
      success: false,
      errorMessage,
    };
  }

  // Methods
  isAccountConfirmation(): boolean {
    return this.event === AuditEvent.ACCOUNT_CONFIRMED;
  }

  isSigninSuccess(): boolean {
    return this.event === AuditEvent.SIGNIN_SUCCESS;
  }

  isRateLimitExceeded(): boolean {
    return this.event === AuditEvent.RATE_LIMIT_EXCEEDED;
  }

  getContextValue<T = any>(key: string): T | undefined {
    return this.context?.[key] as T;
  }

  setContextValue(key: string, value: any): void {
    if (!this.context) {
      this.context = {};
    }
    this.context[key] = value;
  }
}
