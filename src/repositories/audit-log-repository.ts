// src/repositories/audit-log-repository.ts
import { Repository, DataSource, Between, LessThan } from 'typeorm';
import { AuditLog, AuditEvent } from '@/entities/audit-log';
import { DatabaseError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface CreateAuditLogData {
  userId?: string;
  email: string;
  event: AuditEvent;
  context?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
  correlationId?: string;
  success?: boolean;
  errorMessage?: string;
}

export interface AuditLogFilters {
  userId?: string;
  email?: string;
  event?: AuditEvent;
  success?: boolean;
  startDate?: Date;
  endDate?: Date;
  ipAddress?: string;
  correlationId?: string;
}

export class AuditLogRepository {
  private repository: Repository<AuditLog>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(AuditLog);
    this.logger = new Logger(correlationId);
  }

  /**
   * Create a new audit log entry
   */
  async create(auditData: CreateAuditLogData): Promise<AuditLog> {
    try {
      this.logger.debug('Creating audit log entry', { 
        event: auditData.event,
        email: auditData.email,
        userId: auditData.userId,
        success: auditData.success !== false
      });
      
      const auditLog = this.repository.create({
        userId: auditData.userId || null,
        email: auditData.email.toLowerCase(),
        event: auditData.event,
        context: auditData.context || null,
        ipAddress: auditData.ipAddress || null,
        userAgent: auditData.userAgent || null,
        country: auditData.country || null,
        city: auditData.city || null,
        correlationId: auditData.correlationId || null,
        success: auditData.success !== false,
        errorMessage: auditData.errorMessage || null,
      });

      const savedAuditLog = await this.repository.save(auditLog);
      
      this.logger.debug('Audit log entry created successfully', { 
        auditLogId: savedAuditLog.id,
        event: savedAuditLog.event,
        email: savedAuditLog.email
      });

      return savedAuditLog;
    } catch (error) {
      this.logger.error('Error creating audit log entry', error instanceof Error ? error : new Error(String(error)), {
        event: auditData.event,
        email: auditData.email 
      });
      
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to create audit log entry',
        { event: auditData.event, email: auditData.email },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Log successful event
   */
  async logSuccess(
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
  ): Promise<AuditLog> {
    return this.create({
      email,
      event,
      success: true,
      ...options,
    });
  }

  /**
   * Log failed event
   */
  async logFailure(
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
  ): Promise<AuditLog> {
    return this.create({
      email,
      event,
      success: false,
      errorMessage,
      ...options,
    });
  }

  /**
   * Find audit logs with filters and pagination
   */
  async findWithFilters(
    filters: AuditLogFilters = {},
    page: number = 1,
    limit: number = 50
  ): Promise<{ logs: AuditLog[]; total: number }> {
    try {
      this.logger.debug('Finding audit logs with filters', { 
        filters, 
        page, 
        limit 
      });
      
      const queryBuilder = this.repository
        .createQueryBuilder('audit_log')
        .leftJoinAndSelect('audit_log.user', 'user');

      // Apply filters
      if (filters.userId) {
        queryBuilder.andWhere('audit_log.userId = :userId', { userId: filters.userId });
      }

      if (filters.email) {
        queryBuilder.andWhere('LOWER(audit_log.email) = LOWER(:email)', { email: filters.email });
      }

      if (filters.event) {
        queryBuilder.andWhere('audit_log.event = :event', { event: filters.event });
      }

      if (filters.success !== undefined) {
        queryBuilder.andWhere('audit_log.success = :success', { success: filters.success });
      }

      if (filters.startDate && filters.endDate) {
        queryBuilder.andWhere('audit_log.createdAt BETWEEN :startDate AND :endDate', {
          startDate: filters.startDate,
          endDate: filters.endDate,
        });
      } else if (filters.startDate) {
        queryBuilder.andWhere('audit_log.createdAt >= :startDate', { startDate: filters.startDate });
      } else if (filters.endDate) {
        queryBuilder.andWhere('audit_log.createdAt <= :endDate', { endDate: filters.endDate });
      }

      if (filters.ipAddress) {
        queryBuilder.andWhere('audit_log.ipAddress = :ipAddress', { ipAddress: filters.ipAddress });
      }

      if (filters.correlationId) {
        queryBuilder.andWhere('audit_log.correlationId = :correlationId', { 
          correlationId: filters.correlationId 
        });
      }

      // Get total count
      const total = await queryBuilder.getCount();

      // Apply pagination and ordering
      const logs = await queryBuilder
        .orderBy('audit_log.createdAt', 'DESC')
        .skip((page - 1) * limit)
        .take(limit)
        .getMany();

      this.logger.debug('Audit logs found with filters', { 
        count: logs.length,
        total,
        page,
        limit
      });

      return { logs, total };
    } catch (error) {
      this.logger.error('Error finding audit logs with filters', error instanceof Error ? error : new Error(String(error)), { filters });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find audit logs with filters',
        { filters },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find audit logs by correlation ID
   */
  async findByCorrelationId(correlationId: string): Promise<AuditLog[]> {
    try {
      this.logger.debug('Finding audit logs by correlation ID', { correlationId });
      
      const logs = await this.repository.find({
        where: { correlationId },
        relations: ['user'],
        order: {
          createdAt: 'ASC',
        },
      });

      this.logger.debug('Audit logs found by correlation ID', { 
        correlationId,
        count: logs.length 
      });

      return logs;
    } catch (error) {
      this.logger.error('Error finding audit logs by correlation ID', error instanceof Error ? error : new Error(String(error)), { correlationId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find audit logs by correlation ID',
        { correlationId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find recent audit logs for user
   */
  async findRecentForUser(userId: string, limit: number = 20): Promise<AuditLog[]> {
    try {
      this.logger.debug('Finding recent audit logs for user', { userId, limit });
      
      const logs = await this.repository.find({
        where: { userId },
        order: {
          createdAt: 'DESC',
        },
        take: limit,
      });

      this.logger.debug('Recent audit logs found for user', { 
        userId,
        count: logs.length 
      });

      return logs;
    } catch (error) {
      this.logger.error('Error finding recent audit logs for user', error instanceof Error ? error : new Error(String(error)), { userId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find recent audit logs for user',
        { userId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find recent audit logs for email
   */
  async findRecentForEmail(email: string, limit: number = 20): Promise<AuditLog[]> {
    try {
      this.logger.debug('Finding recent audit logs for email', { email, limit });
      
      const logs = await this.repository.find({
        where: { email: email.toLowerCase() },
        order: {
          createdAt: 'DESC',
        },
        take: limit,
      });

      this.logger.debug('Recent audit logs found for email', { 
        email,
        count: logs.length 
      });

      return logs;
    } catch (error) {
      this.logger.error('Error finding recent audit logs for email', error instanceof Error ? error : new Error(String(error)), { email });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find recent audit logs for email',
        { email },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Count events for email in time window
   */
  async countEventsForEmailInWindow(
    email: string,
    event: AuditEvent,
    windowStart: Date,
    windowEnd: Date = new Date()
  ): Promise<number> {
    try {
      this.logger.debug('Counting events for email in window', { 
        email, 
        event, 
        windowStart, 
        windowEnd 
      });
      
      const count = await this.repository.count({
        where: {
          email: email.toLowerCase(),
          event,
          createdAt: Between(windowStart, windowEnd),
        },
      });

      this.logger.debug('Event count for email in window', { 
        email, 
        event, 
        count 
      });

      return count;
    } catch (error) {
      this.logger.error('Error counting events for email in window', error instanceof Error ? error : new Error(String(error)), { email, event });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to count events for email in window',
        { email, event },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Clean up old audit logs
   */
  async cleanupOld(olderThan: Date): Promise<number> {
    try {
      this.logger.debug('Cleaning up old audit logs', { olderThan });
      
      const result = await this.repository.delete({
        createdAt: LessThan(olderThan),
      });

      const deletedCount = result.affected || 0;
      
      this.logger.info('Old audit logs cleaned up', { 
        deletedCount, 
        olderThan 
      });

      return deletedCount;
    } catch (error) {
      this.logger.error('Error cleaning up old audit logs', error instanceof Error ? error : new Error(String(error)), { olderThan });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to cleanup old audit logs',
        { olderThan },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Get audit statistics
   */
  async getStatistics(
    startDate: Date,
    endDate: Date
  ): Promise<Record<string, any>> {
    try {
      this.logger.debug('Getting audit statistics', { startDate, endDate });
      
      const stats = await this.repository
        .createQueryBuilder('audit_log')
        .select([
          'audit_log.event',
          'audit_log.success',
          'COUNT(*) as count',
        ])
        .where('audit_log.createdAt BETWEEN :startDate AND :endDate', {
          startDate,
          endDate,
        })
        .groupBy('audit_log.event, audit_log.success')
        .getRawMany();

      this.logger.debug('Audit statistics retrieved', { 
        startDate, 
        endDate, 
        statsCount: stats.length 
      });

      return stats.reduce((acc, stat) => {
        const key = `${stat.audit_log_event}_${stat.audit_log_success ? 'success' : 'failure'}`;
        acc[key] = parseInt(stat.count, 10);
        return acc;
      }, {} as Record<string, number>);
    } catch (error) {
      this.logger.error('Error getting audit statistics', error instanceof Error ? error : new Error(String(error)), { startDate, endDate });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to get audit statistics',
        { startDate, endDate },
        this.logger['correlationId']
      );
    }
  }
}
