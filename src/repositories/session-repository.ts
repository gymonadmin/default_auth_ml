// src/repositories/session-repository.ts 
import { Repository, DataSource, LessThan, MoreThan } from 'typeorm';
import { Session } from '@/entities/session';
import { User } from '@/entities/user';
import { Profile } from '@/entities/profile';
import { DatabaseError, ErrorCode, mapDatabaseErrorCode } from '@/lib/errors/error-codes';
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

// Extended session type with manually joined data
export interface SessionWithUser extends Session {
  user: User;
}

export class SessionRepository {
  private repository: Repository<Session>;
  private userRepository: Repository<User>;
  private profileRepository: Repository<Profile>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(Session);
    this.userRepository = dataSource.getRepository(User);
    this.profileRepository = dataSource.getRepository(Profile);
    this.logger = new Logger(correlationId);
  }

  /**
   * Validate UUID format
   */
  private isValidUUID(id: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(id);
  }

  /**
   * Manually join user and profile data to session
   */
  private async joinUserData(session: Session): Promise<SessionWithUser | null> {
    try {
      // Get user data
      const user = await this.userRepository.findOne({
        where: { 
          id: session.userId,
          deletedAt: null as any
        }
      });

      if (!user) {
        this.logger.debug('User not found for session', {
          sessionId: session.id,
          userId: session.userId
        });
        return null;
      }

      // Get profile data
      const profile = await this.profileRepository.findOne({
        where: { 
          userId: session.userId,
          deletedAt: null as any
        }
      });

      // Manually attach the profile data to user
      if (profile) {
        user.profile = profile;
      }

      // Create the session with user data
      const sessionWithUser = session as SessionWithUser;
      sessionWithUser.user = user;

      return sessionWithUser;
    } catch (error) {
      this.logger.error('Error joining user data to session', {
        sessionId: session.id,
        userId: session.userId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Find session by token hash with user data
   */
  async findByTokenHash(tokenHash: string): Promise<SessionWithUser | null> {
    try {
      this.logger.debug('Finding session by token hash', { tokenHashPrefix: tokenHash.substring(0, 8) });
      
      const session = await this.repository.findOne({
        where: { tokenHash }
      });

      if (!session) {
        this.logger.debug('Session not found by token hash');
        return null;
      }

      this.logger.debug('Session found by token hash', { 
        found: true, 
        sessionId: session.id,
        userId: session.userId,
        isActive: session.isActive,
        isExpired: session.isExpired
      });

      // Manually join user and profile data
      return await this.joinUserData(session);
    } catch (error) {
      this.logger.error('Error finding session by token hash', {
        tokenHashPrefix: tokenHash.substring(0, 8),
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find session by token hash',
        { 
          tokenHashPrefix: tokenHash.substring(0, 8),
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find session by ID with user data
   */
  async findById(id: string): Promise<SessionWithUser | null> {
    try {
      this.logger.debug('Finding session by ID', { sessionId: id });
      
      const session = await this.repository.findOne({
        where: { id }
      });

      if (!session) {
        this.logger.debug('Session not found by ID', { sessionId: id });
        return null;
      }

      this.logger.debug('Session found by ID', { 
        found: true, 
        sessionId: id,
        userId: session.userId,
        isActive: session.isActive
      });

      // Manually join user and profile data
      return await this.joinUserData(session);
    } catch (error) {
      this.logger.error('Error finding session by ID', {
        sessionId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find session by ID',
        { 
          sessionId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      this.logger.error('Error creating session', {
        userId: sessionData.userId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      
      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        errorCode === ErrorCode.DUPLICATE_RECORD 
          ? 'Session token already exists'
          : 'Failed to create session',
        { 
          userId: sessionData.userId,
          originalError: error instanceof Error ? error.name : 'Unknown',
          pgCode: error && typeof error === 'object' && 'code' in error ? error.code : undefined
        },
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
      
      const session = await this.repository.findOne({ where: { id } });
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
      
      this.logger.error('Error updating session last accessed time', {
        sessionId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to update session last accessed time',
        { 
          sessionId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      
      const session = await this.repository.findOne({ where: { id } });
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
      
      this.logger.error('Error revoking session', {
        sessionId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to revoke session',
        { 
          sessionId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      
      if (!this.isValidUUID(userId)) {
        this.logger.debug('Invalid UUID format for user ID', { userId });
        return 0;
      }
      
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
      this.logger.error('Error revoking all sessions for user', {
        userId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to revoke all sessions for user',
        { 
          userId,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      
      const session = await this.repository.findOne({ where: { id } });
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
      
      this.logger.error('Error extending session expiry', {
        sessionId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to extend session expiry',
        { 
          sessionId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      
      if (!this.isValidUUID(userId)) {
        this.logger.debug('Invalid UUID format for user ID, returning empty array', { userId });
        return [];
      }
      
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
      this.logger.error('Error finding active sessions for user', {
        userId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find active sessions for user',
        { 
          userId,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      this.logger.error('Error cleaning up expired sessions', {
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to cleanup expired sessions',
        { originalError: error instanceof Error ? error.name : 'Unknown' },
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
      
      if (!this.isValidUUID(userId)) {
        this.logger.debug('Invalid UUID format for user ID, returning 0', { userId });
        return 0;
      }
      
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
      this.logger.error('Error counting active sessions for user', {
        userId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to count active sessions for user',
        { 
          userId,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }
}
