// src/repositories/session-repository.ts
import { Repository, DataSource, LessThan, MoreThan } from 'typeorm';
import { Session } from '@/entities/session';
import { DatabaseError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface CreateSessionData {
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
}

export class SessionRepository {
  private repository: Repository<Session>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(Session);
    this.logger = new Logger(correlationId);
  }

  /**
   * Find session by token hash
   */
  async findByTokenHash(tokenHash: string): Promise<Session | null> {
    try {
      this.logger.debug('Finding session by token hash', { tokenHashPrefix: tokenHash.substring(0, 8) });
      
      const session = await this.repository.findOne({
        where: { tokenHash },
        relations: ['user', 'user.profile'],
      });

      this.logger.debug('Session found by token hash', { 
        found: !!session, 
        sessionId: session?.id,
        userId: session?.userId,
        isActive: session?.isActive,
        isExpired: session?.isExpired
      });

      return session;
    } catch (error) {
      this.logger.error('Error finding session by token hash', error instanceof Error ? error : new Error(String(error)));
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find session by token hash',
        undefined,
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find session by ID
   */
  async findById(id: string): Promise<Session | null> {
    try {
      this.logger.debug('Finding session by ID', { sessionId: id });
      
      const session = await this.repository.findOne({
        where: { id },
        relations: ['user', 'user.profile'],
      });

      this.logger.debug('Session found by ID', { 
        found: !!session, 
        sessionId: id,
        userId: session?.userId,
        isActive: session?.isActive
      });

      return session;
    } catch (error) {
      this.logger.error('Error finding session by ID', error instanceof Error ? error : new Error(String(error)), { sessionId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find session by ID',
        { sessionId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Create a new session
   */
  async create(sessionData: CreateSessionData): Promise<Session> {
    try {
      this.logger.debug('Creating new session', { 
        userId: sessionData.userId,
        expiresAt: sessionData.expiresAt,
        ipAddress: sessionData.ipAddress
      });
      
      const session = this.repository.create({
        userId: sessionData.userId,
        tokenHash: sessionData.tokenHash,
        expiresAt: sessionData.expiresAt,
        ipAddress: sessionData.ipAddress || null,
        userAgent: sessionData.userAgent || null,
        country: sessionData.country || null,
        city: sessionData.city || null,
        isActive: true,
        lastAccessedAt: new Date(),
      });

      const savedSession = await this.repository.save(session);
      
      this.logger.info('Session created successfully', { 
        sessionId: savedSession.id,
        userId: savedSession.userId,
        expiresAt: savedSession.expiresAt
      });

      return savedSession;
    } catch (error) {
      this.logger.error('Error creating session', error instanceof Error ? error : new Error(String(error)), { userId: sessionData.userId });
      
      if (error instanceof Error && 'code' in error && (error as any).code === '23505') {
        throw new DatabaseError(
          ErrorCode.DUPLICATE_RECORD,
          'Session token already exists',
          { userId: sessionData.userId },
          this.logger['correlationId']
        );
      }
      
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to create session',
        { userId: sessionData.userId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Update session last accessed time
   */
  async updateLastAccessed(id: string): Promise<Session> {
    try {
      this.logger.debug('Updating session last accessed time', { sessionId: id });
      
      const session = await this.findById(id);
      if (!session) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Session not found',
          { sessionId: id },
          this.logger['correlationId']
        );
      }

      session.updateLastAccessed();
      const savedSession = await this.repository.save(session);
      
      this.logger.debug('Session last accessed time updated', { 
        sessionId: savedSession.id,
        lastAccessedAt: savedSession.lastAccessedAt
      });

      return savedSession;
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating session last accessed time', error instanceof Error ? error : new Error(String(error)), { sessionId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to update session last accessed time',
        { sessionId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Revoke session
   */
  async revoke(id: string): Promise<void> {
    try {
      this.logger.debug('Revoking session', { sessionId: id });
      
      const session = await this.findById(id);
      if (!session) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Session not found',
          { sessionId: id },
          this.logger['correlationId']
        );
      }

      session.revoke();
      await this.repository.save(session);
      
      this.logger.info('Session revoked successfully', { sessionId: id });
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error revoking session', error instanceof Error ? error : new Error(String(error)), { sessionId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to revoke session',
        { sessionId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Revoke all sessions for a user
   */
  async revokeAllForUser(userId: string): Promise<number> {
    try {
      this.logger.debug('Revoking all sessions for user', { userId });
      
      const result = await this.repository.update(
        { userId, isActive: true },
        { isActive: false }
      );

      const revokedCount = result.affected || 0;
      
      this.logger.info('All sessions revoked for user', { 
        userId, 
        revokedCount 
      });

      return revokedCount;
    } catch (error) {
      this.logger.error('Error revoking all sessions for user', error instanceof Error ? error : new Error(String(error)), { userId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to revoke all sessions for user',
        { userId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Extend session expiry
   */
  async extend(id: string, newExpiryDate: Date): Promise<Session> {
    try {
      this.logger.debug('Extending session expiry', { 
        sessionId: id, 
        newExpiryDate 
      });
      
      const session = await this.findById(id);
      if (!session) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Session not found',
          { sessionId: id },
          this.logger['correlationId']
        );
      }

      session.extend(newExpiryDate);
      const savedSession = await this.repository.save(session);
      
      this.logger.info('Session expiry extended', { 
        sessionId: savedSession.id,
        newExpiryDate: savedSession.expiresAt
      });

      return savedSession;
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error extending session expiry', error instanceof Error ? error : new Error(String(error)), { sessionId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to extend session expiry',
        { sessionId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find active sessions for user
   */
  async findActiveForUser(userId: string): Promise<Session[]> {
    try {
      this.logger.debug('Finding active sessions for user', { userId });
      
      const sessions = await this.repository.find({
        where: {
          userId,
          isActive: true,
          expiresAt: MoreThan(new Date()),
        },
        order: {
          lastAccessedAt: 'DESC',
        },
      });

      this.logger.debug('Active sessions found for user', { 
        userId, 
        count: sessions.length 
      });

      return sessions;
    } catch (error) {
      this.logger.error('Error finding active sessions for user', error instanceof Error ? error : new Error(String(error)), { userId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find active sessions for user',
        { userId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpired(): Promise<number> {
    try {
      this.logger.debug('Cleaning up expired sessions');
      
      const result = await this.repository.delete({
        expiresAt: LessThan(new Date()),
      });

      const deletedCount = result.affected || 0;
      
      this.logger.info('Expired sessions cleaned up', { deletedCount });

      return deletedCount;
    } catch (error) {
      this.logger.error('Error cleaning up expired sessions', error instanceof Error ? error : new Error(String(error)));
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to cleanup expired sessions',
        undefined,
        this.logger['correlationId']
      );
    }
  }

  /**
   * Count active sessions for user
   */
  async countActiveForUser(userId: string): Promise<number> {
    try {
      this.logger.debug('Counting active sessions for user', { userId });
      
      const count = await this.repository.count({
        where: {
          userId,
          isActive: true,
          expiresAt: MoreThan(new Date()),
        },
      });

      this.logger.debug('Active session count for user', { userId, count });

      return count;
    } catch (error) {
      this.logger.error('Error counting active sessions for user', error instanceof Error ? error : new Error(String(error)), { userId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to count active sessions for user',
        { userId },
        this.logger['correlationId']
      );
    }
  }
}
