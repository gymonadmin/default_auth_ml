// src/services/session-service.ts
import { DataSource } from 'typeorm';
import { Session } from '@/entities/session';
import { User } from '@/entities/user';
import { AuditEvent } from '@/entities/audit-log';
import { SessionRepository } from '@/repositories/session-repository';
import { UserRepository } from '@/repositories/user-repository';
import { AuditLogRepository } from '@/repositories/audit-log-repository';
import { 
  generateSessionToken, 
  hashToken, 
  verifyTokenHash 
} from '@/lib/utils/crypto';
import { createExpirationDate, hasExpired } from '@/lib/utils/time';
import { AuthError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface CreateSessionRequest {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
  expiresInSeconds?: number;
}

export interface SessionValidationResult {
  session: Session;
  user: User;
  isValid: boolean;
  shouldExtend: boolean;
}

export interface SessionMetrics {
  totalActiveSessions: number;
  userActiveSessions: number;
  sessionsCreatedToday: number;
  sessionsExpiredToday: number;
}

export interface SessionServiceConfig {
  defaultTTLSeconds: number;
  extensionThresholdSeconds: number;
  maxSessionsPerUser: number;
  cleanupIntervalMinutes: number;
}

export class SessionService {
  private dataSource: DataSource;
  private sessionRepo: SessionRepository;
  private userRepo: UserRepository;
  private auditRepo: AuditLogRepository;
  private config: SessionServiceConfig;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.dataSource = dataSource;
    this.logger = new Logger(correlationId);
    
    // Initialize repositories
    this.sessionRepo = new SessionRepository(dataSource, correlationId);
    this.userRepo = new UserRepository(dataSource, correlationId);
    this.auditRepo = new AuditLogRepository(dataSource, correlationId);
    
    // Load configuration
    this.config = this.loadConfiguration();
  }

  /**
   * Load session service configuration
   */
  private loadConfiguration(): SessionServiceConfig {
    return {
      defaultTTLSeconds: parseInt(process.env.SESSION_TTL_SECONDS || '604800', 10), // 7 days
      extensionThresholdSeconds: 1800, // 30 minutes - extend if less than this time remaining
      maxSessionsPerUser: 5, // Maximum concurrent sessions per user
      cleanupIntervalMinutes: 60, // How often to clean expired sessions
    };
  }

  /**
   * Create a new session for a user
   */
  async createSession(request: CreateSessionRequest): Promise<{ session: Session; token: string }> {
    try {
      this.logger.info('Creating new session', {
        userId: request.userId,
        ipAddress: request.ipAddress,
      });

      // Validate input parameters
      if (!request.userId || typeof request.userId !== 'string') {
        throw new AuthError(
          ErrorCode.INVALID_INPUT,
          'Valid user ID is required',
          400,
          { userId: request.userId },
          this.logger['correlationId']
        );
      }

      if (request.expiresInSeconds && (request.expiresInSeconds < 60 || request.expiresInSeconds > 31536000)) {
        throw new AuthError(
          ErrorCode.INVALID_INPUT,
          'Session expiration must be between 1 minute and 1 year',
          400,
          { expiresInSeconds: request.expiresInSeconds },
          this.logger['correlationId']
        );
      }

      // Verify user exists and is active
      const user = await this.userRepo.findById(request.userId);
      if (!user) {
        throw new AuthError(
          ErrorCode.RECORD_NOT_FOUND,
          'User not found',
          404,
          { userId: request.userId },
          this.logger['correlationId']
        );
      }

      if (!user.isActive) {
        throw new AuthError(
          ErrorCode.ACCOUNT_NOT_VERIFIED,
          'User account is not active',
          401,
          { userId: request.userId },
          this.logger['correlationId']
        );
      }

      // Check session limits
      await this.enforceSessionLimits(request.userId);

      // Generate session token and hash
      const sessionToken = generateSessionToken();
      const tokenHash = await hashToken(sessionToken);
      const expiresAt = createExpirationDate(
        request.expiresInSeconds || this.config.defaultTTLSeconds
      );

      // Create session in database
      const session = await this.sessionRepo.create({
        userId: request.userId,
        tokenHash,
        expiresAt,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        country: request.country,
        city: request.city,
      });

      // Log audit event
      await this.auditRepo.logSuccess(
        user.email,
        AuditEvent.SESSION_CREATED,
        {
          userId: user.id,
          context: {
            sessionId: session.id,
            expiresAt: session.expiresAt.toISOString(),
            ipAddress: request.ipAddress,
          },
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          country: request.country,
          city: request.city,
          correlationId: this.logger['correlationId'],
        }
      );

      this.logger.info('Session created successfully', {
        sessionId: session.id,
        userId: session.userId,
        expiresAt: session.expiresAt,
      });

      return { session, token: sessionToken };
    } catch (error) {
      this.logger.error('Failed to create session', error instanceof Error ? error : new Error(String(error)), {
        userId: request.userId,
      });
      throw error;
    }
  }

  /**
   * Validate a session token and return session data
   */
  async validateSession(sessionToken: string): Promise<SessionValidationResult | null> {
    try {
      this.logger.debug('Validating session token', {
        tokenLength: sessionToken.length,
      });

      // Validate token format
      if (!sessionToken || typeof sessionToken !== 'string' || sessionToken.length !== 64) {
        this.logger.debug('Invalid session token format', {
          tokenLength: sessionToken?.length,
          tokenType: typeof sessionToken,
        });
        return null;
      }

      // Validate token contains only hex characters
      if (!/^[0-9a-f]{64}$/i.test(sessionToken)) {
        this.logger.debug('Session token contains invalid characters');
        return null;
      }

      // Hash the token to find the session
      const tokenHash = await hashToken(sessionToken);
      const session = await this.sessionRepo.findByTokenHash(tokenHash);

      if (!session) {
        this.logger.debug('Session not found');
        return null;
      }

      // Verify token hash using timing-safe comparison
      if (!verifyTokenHash(sessionToken, session.tokenHash)) {
        this.logger.debug('Session token verification failed');
        return null;
      }

      // Check if session is active
      if (!session.isActive) {
        this.logger.debug('Session is not active', { sessionId: session.id });
        return null;
      }

      // Check if session has expired
      if (hasExpired(session.expiresAt)) {
        this.logger.debug('Session has expired', {
          sessionId: session.id,
          expiresAt: session.expiresAt,
        });
        
        // Mark session as expired and log audit event
        await this.expireSession(session.id, 'Session expired naturally');
        return null;
      }

      // Get user data
      const user = session.user;
      if (!user || !user.isActive) {
        this.logger.debug('User not found or inactive', {
          sessionId: session.id,
          userId: session.userId,
        });
        return null;
      }

      // Update last accessed time
      await this.sessionRepo.updateLastAccessed(session.id);

      // Determine if session should be extended
      const shouldExtend = this.shouldExtendSession(session);

      this.logger.debug('Session validated successfully', {
        sessionId: session.id,
        userId: session.userId,
        shouldExtend,
      });

      return {
        session,
        user,
        isValid: true,
        shouldExtend,
      };
    } catch (error) {
      this.logger.error('Session validation error', error instanceof Error ? error : new Error(String(error)));
      return null;
    }
  }

  /**
   * Extend session expiration
   */
  async extendSession(sessionId: string, extensionSeconds?: number): Promise<Session> {
    try {
      this.logger.debug('Extending session', { sessionId, extensionSeconds });

      const session = await this.sessionRepo.findById(sessionId);
      if (!session) {
        throw new AuthError(
          ErrorCode.SESSION_NOT_FOUND,
          'Session not found',
          404,
          { sessionId },
          this.logger['correlationId']
        );
      }

      if (!session.isActive || hasExpired(session.expiresAt)) {
        throw new AuthError(
          ErrorCode.SESSION_EXPIRED,
          'Session is expired or inactive',
          401,
          { sessionId },
          this.logger['correlationId']
        );
      }

      const newExpiryDate = createExpirationDate(
        extensionSeconds || this.config.defaultTTLSeconds
      );

      const extendedSession = await this.sessionRepo.extend(sessionId, newExpiryDate);

      this.logger.info('Session extended successfully', {
        sessionId,
        newExpiryDate: extendedSession.expiresAt,
      });

      return extendedSession;
    } catch (error) {
      this.logger.error('Failed to extend session', error instanceof Error ? error : new Error(String(error)), { sessionId });
      throw error;
    }
  }

  /**
   * Revoke a specific session
   */
  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    try {
      this.logger.info('Revoking session', { sessionId, reason });

      const session = await this.sessionRepo.findById(sessionId);
      if (!session) {
        this.logger.debug('Session not found for revocation', { sessionId });
        return; // Session doesn't exist, consider it revoked
      }

      await this.sessionRepo.revoke(sessionId);

      // Log audit event
      if (session.user) {
        await this.auditRepo.logSuccess(
          session.user.email,
          AuditEvent.SIGNOUT,
          {
            userId: session.userId,
            context: {
              sessionId,
              reason: reason || 'Manual revocation',
            },
            correlationId: this.logger['correlationId'],
          }
        );
      }

      this.logger.info('Session revoked successfully', { sessionId });
    } catch (error) {
      this.logger.error('Failed to revoke session', error instanceof Error ? error : new Error(String(error)), { sessionId });
      throw error;
    }
  }

  /**
   * Revoke all sessions for a user
   */
  async revokeAllUserSessions(userId: string, excludeSessionId?: string, reason?: string): Promise<number> {
    try {
      this.logger.info('Revoking all user sessions', { userId, excludeSessionId, reason });

      // Get all active sessions for user
      const activeSessions = await this.sessionRepo.findActiveForUser(userId);
      
      let revokedCount = 0;
      for (const session of activeSessions) {
        if (excludeSessionId && session.id === excludeSessionId) {
          continue; // Skip the excluded session
        }
        
        await this.sessionRepo.revoke(session.id);
        revokedCount++;
      }

      // Log audit event
      const user = await this.userRepo.findById(userId);
      if (user) {
        await this.auditRepo.logSuccess(
          user.email,
          AuditEvent.SIGNOUT,
          {
            userId,
            context: {
              reason: reason || 'Bulk session revocation',
              revokedCount,
              excludeSessionId,
            },
            correlationId: this.logger['correlationId'],
          }
        );
      }

      this.logger.info('All user sessions revoked', { userId, revokedCount });
      return revokedCount;
    } catch (error) {
      this.logger.error('Failed to revoke all user sessions', error instanceof Error ? error : new Error(String(error)), { userId });
      throw error;
    }
  }

  /**
   * Get active sessions for a user
   */
  async getUserActiveSessions(userId: string): Promise<Session[]> {
    try {
      this.logger.debug('Getting active sessions for user', { userId });

      const sessions = await this.sessionRepo.findActiveForUser(userId);
      
      this.logger.debug('Active sessions retrieved', { 
        userId, 
        count: sessions.length 
      });

      return sessions;
    } catch (error) {
      this.logger.error('Failed to get user active sessions', error instanceof Error ? error : new Error(String(error)), { userId });
      throw error;
    }
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    try {
      this.logger.debug('Starting expired session cleanup');

      const deletedCount = await this.sessionRepo.cleanupExpired();

      this.logger.info('Expired session cleanup completed', { deletedCount });
      return deletedCount;
    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  /**
   * Get session metrics
   */
  async getSessionMetrics(userId?: string): Promise<SessionMetrics> {
    try {
      this.logger.debug('Getting session metrics', { userId });

      // This would require additional repository methods for metrics
      // For now, returning basic metrics
      const userActiveSessions = userId ? 
        await this.sessionRepo.countActiveForUser(userId) : 0;

      // TODO: Implement more comprehensive metrics in repository
      const metrics: SessionMetrics = {
        totalActiveSessions: 0, // Would need repository method
        userActiveSessions,
        sessionsCreatedToday: 0, // Would need repository method
        sessionsExpiredToday: 0, // Would need repository method
      };

      this.logger.debug('Session metrics retrieved', metrics);
      return metrics;
    } catch (error) {
      this.logger.error('Failed to get session metrics', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  /**
   * Expire a session and log the event
   */
  private async expireSession(sessionId: string, reason: string): Promise<void> {
    try {
      const session = await this.sessionRepo.findById(sessionId);
      if (!session) return;

      await this.sessionRepo.revoke(sessionId);

      // Log audit event
      if (session.user) {
        await this.auditRepo.logSuccess(
          session.user.email,
          AuditEvent.SESSION_EXPIRED,
          {
            userId: session.userId,
            context: {
              sessionId,
              reason,
              expiredAt: new Date().toISOString(),
            },
            correlationId: this.logger['correlationId'],
          }
        );
      }

      this.logger.debug('Session expired and logged', { sessionId, reason });
    } catch (error) {
      this.logger.error('Failed to expire session', error instanceof Error ? error : new Error(String(error)), { sessionId });
    }
  }

  /**
   * Check if session should be extended
   */
  private shouldExtendSession(session: Session): boolean {
    const timeUntilExpiry = session.timeUntilExpiry;
    return timeUntilExpiry > 0 && timeUntilExpiry < (this.config.extensionThresholdSeconds * 1000);
  }

  /**
   * Enforce session limits for a user
   */
  private async enforceSessionLimits(userId: string): Promise<void> {
    const activeSessions = await this.sessionRepo.findActiveForUser(userId);
    
    if (activeSessions.length >= this.config.maxSessionsPerUser) {
      // Revoke the oldest session(s) to make room
      const sessionsToRevoke = activeSessions
        .sort((a, b) => a.lastAccessedAt!.getTime() - b.lastAccessedAt!.getTime())
        .slice(0, activeSessions.length - this.config.maxSessionsPerUser + 1);

      for (const session of sessionsToRevoke) {
        await this.sessionRepo.revoke(session.id);
        this.logger.info('Revoked old session due to limit', {
          sessionId: session.id,
          userId,
        });
      }
    }
  }

  /**
   * Create SessionService instance
   */
  static create(dataSource: DataSource, correlationId?: string): SessionService {
    return new SessionService(dataSource, correlationId);
  }
}
