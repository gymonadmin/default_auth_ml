// src/services/auth-service.ts

import { DataSource } from 'typeorm';
import { User } from '@/entities/user';
import { Profile } from '@/entities/profile';
import { Session } from '@/entities/session';
import { MagicSigninToken } from '@/entities/magic-signin-token';
import { AuditLog, AuditEvent } from '@/entities/audit-log';
import { UserRepository } from '@/repositories/user-repository';
import { ProfileRepository } from '@/repositories/profile-repository';
import { SessionRepository } from '@/repositories/session-repository';
import { MagicSigninTokenRepository } from '@/repositories/magic-signin-token-repository';
import { AuditLogRepository } from '@/repositories/audit-log-repository';
import { EmailService } from '@/services/email-service';
import { RateLimitService } from '@/services/rate-limit-service';
import { 
  generateMagicLinkToken, 
  generateSessionToken, 
  hashToken, 
  verifyTokenHash 
} from '@/lib/utils/crypto';
import { 
  generateMagicLinkUrl, 
  normalizeEmail, 
  validateBusinessEmail 
} from '@/lib/utils/email';
import { createExpirationDate, hasExpired } from '@/lib/utils/time';
import { AuthError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';
import { getDataSource, isDatabaseConnected } from '@/lib/config/database';

export interface SendMagicLinkRequest {
  email: string;
  redirectUrl?: string;
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
}

export interface VerifyMagicLinkRequest {
  token: string;
  profile?: {
    firstName: string;
    lastName: string;
  };
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
}

export interface MagicLinkResponse {
  success: boolean;
  message: string;
  isNewUser: boolean;
  requiresProfile: boolean;
}

export interface VerifyMagicLinkResponse {
  success: boolean;
  message: string;
  user: User;
  session: Session;
  isNewUser: boolean;
  redirectUrl?: string;
}

export interface AuthServiceConfig {
  magicLinkTTLSeconds: number;
  sessionTTLSeconds: number;
  maxTokensPerEmail: number;
  rateLimitWindow: number;
  rateLimitCount: number;
}

export class AuthService {
  private dataSource: DataSource;
  private userRepo: UserRepository;
  private profileRepo: ProfileRepository;
  private sessionRepo: SessionRepository;
  private tokenRepo: MagicSigninTokenRepository;
  private auditRepo: AuditLogRepository;
  private emailService: EmailService;
  private rateLimitService: RateLimitService;
  private config: AuthServiceConfig;
  private logger: Logger;
  private correlationId: string;

  constructor(correlationId?: string) {
    this.correlationId = correlationId || 'unknown';
    this.logger = new Logger(this.correlationId);
    
    // Validate database connection
    if (!isDatabaseConnected()) {
      throw new AuthError(
        ErrorCode.DATABASE_ERROR,
        'Database not connected',
        500,
        { correlationId: this.correlationId },
        this.correlationId,
        'Database connection is not available'
      );
    }

    // Get singleton database connection
    this.dataSource = getDataSource();
    
    // Initialize repositories with correlation ID
    this.userRepo = new UserRepository(this.dataSource, this.correlationId);
    this.profileRepo = new ProfileRepository(this.dataSource, this.correlationId);
    this.sessionRepo = new SessionRepository(this.dataSource, this.correlationId);
    this.tokenRepo = new MagicSigninTokenRepository(this.dataSource, this.correlationId);
    this.auditRepo = new AuditLogRepository(this.dataSource, this.correlationId);
    
    // Initialize services with correlation ID
    this.emailService = new EmailService(this.correlationId);
    this.rateLimitService = new RateLimitService(this.correlationId);
    
    // Load configuration
    this.config = this.loadConfiguration();

    this.logger.debug('AuthService initialized', {
      correlationId: this.correlationId,
      hasDataSource: !!this.dataSource,
      databaseConnected: isDatabaseConnected(),
      config: this.config,
    });
  }

  /**
   * Load authentication service configuration
   */
  private loadConfiguration(): AuthServiceConfig {
    return {
      magicLinkTTLSeconds: parseInt(process.env.MAGIC_LINK_TTL_SECONDS || '900', 10), // 15 minutes
      sessionTTLSeconds: parseInt(process.env.SESSION_TTL_SECONDS || '604800', 10), // 7 days
      maxTokensPerEmail: 3, // Maximum active tokens per email
      rateLimitWindow: parseInt(process.env.RATE_LIMIT_AUTH_WINDOW_SECONDS || '900', 10), // 15 minutes
      rateLimitCount: parseInt(process.env.RATE_LIMIT_AUTH_COUNT || '3', 10), // 3 attempts per window
    };
  }

  /**
   * Send magic link email
   */
  async sendMagicLink(request: SendMagicLinkRequest): Promise<MagicLinkResponse> {
    const startTime = Date.now();
    
    try {
      this.logger.info('Starting magic link send process', {
        email: request.email,
        hasRedirectUrl: !!request.redirectUrl,
        ipAddress: request.ipAddress,
        correlationId: this.correlationId,
      });

      // Validate and normalize email
      const normalizedEmail = normalizeEmail(request.email);
      validateBusinessEmail(normalizedEmail);

      // Check rate limiting
      await this.checkRateLimit(normalizedEmail, request.ipAddress);

      // Check if user exists
      const existingUser = await this.userRepo.findByEmail(normalizedEmail);
      const isNewUser = !existingUser;

      this.logger.debug('User lookup complete', {
        email: normalizedEmail,
        isNewUser,
        userExists: !!existingUser,
        isVerified: existingUser?.isVerified,
        correlationId: this.correlationId,
      });

      // Generate magic link token
      const magicToken = generateMagicLinkToken();
      const tokenHash = await hashToken(magicToken);
      const expiresAt = createExpirationDate(this.config.magicLinkTTLSeconds);

      // Create magic link URL
      const magicLinkUrl = generateMagicLinkUrl(
        process.env.NEXT_PUBLIC_APP_URL!,
        magicToken,
        request.redirectUrl
      );

      // Start database transaction
      await this.dataSource.transaction(async (manager) => {
        // Create new repository instances with the same correlation ID for the transaction
        const transactionUserRepo = new UserRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );
        const transactionTokenRepo = new MagicSigninTokenRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );
        const transactionAuditRepo = new AuditLogRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );

        let userId: string | undefined;

        if (isNewUser) {
          // Create unverified user
          const newUser = await transactionUserRepo.create({
            email: normalizedEmail,
            isVerified: false,
          });
          userId = newUser.id;

          this.logger.info('Created new unverified user', {
            userId: newUser.id,
            email: normalizedEmail,
            correlationId: this.correlationId,
          });
        } else {
          userId = existingUser!.id;
          
          // Invalidate existing tokens for this email
          await transactionTokenRepo.invalidateAllForEmail(normalizedEmail);
          
          this.logger.debug('Invalidated existing tokens', {
            email: normalizedEmail,
            userId,
            correlationId: this.correlationId,
          });
        }

        // Create magic signin token
        await transactionTokenRepo.create({
          userId: isNewUser ? undefined : userId,
          email: normalizedEmail,
          tokenHash,
          expiresAt,
          ipAddress: request.ipAddress || undefined,
          userAgent: request.userAgent || undefined,
          country: request.country || undefined,
          city: request.city || undefined,
          redirectUrl: request.redirectUrl || undefined,
        });

        // Log audit event
        await transactionAuditRepo.logSuccess(
          normalizedEmail,
          AuditEvent.MAGIC_LINK_SENT,
          {
            userId,
            context: {
              isNewUser,
              expiresAt: expiresAt.toISOString(),
              hasRedirectUrl: !!request.redirectUrl,
              tokenLength: magicToken.length,
            },
            ipAddress: request.ipAddress || undefined,
            userAgent: request.userAgent || undefined,
            country: request.country || undefined,
            city: request.city || undefined,
            correlationId: this.correlationId,
          }
        );
      });

      // Send email
      await this.emailService.sendMagicLinkEmail({
        email: normalizedEmail,
        magicLink: magicLinkUrl,
        firstName: existingUser?.profile?.firstName,
        isNewUser,
        expiresInMinutes: Math.floor(this.config.magicLinkTTLSeconds / 60),
        redirectUrl: request.redirectUrl,
      });

      const duration = Date.now() - startTime;
      this.logger.info('Magic link sent successfully', {
        email: normalizedEmail,
        isNewUser,
        duration,
        expiresAt: expiresAt.toISOString(),
        correlationId: this.correlationId,
      });

      return {
        success: true,
        message: isNewUser 
          ? 'Please check your email to complete your account setup'
          : 'Please check your email for your sign-in link',
        isNewUser,
        requiresProfile: false,
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.logger.error('Failed to send magic link', {
        email: request.email,
        duration,
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      // Log audit failure
      try {
        await this.auditRepo.logFailure(
          normalizeEmail(request.email),
          AuditEvent.MAGIC_LINK_SENT,
          error instanceof Error ? error.message : 'Unknown error',
          {
            context: { error: error instanceof Error ? error.name : 'UnknownError' },
            ipAddress: request.ipAddress,
            userAgent: request.userAgent,
            correlationId: this.correlationId,
          }
        );
      } catch (auditError) {
        this.logger.error('Failed to log audit failure', {
          correlationId: this.correlationId,
          error: auditError instanceof Error ? {
            message: auditError.message,
            name: auditError.name,
            stack: auditError.stack,
          } : { message: String(auditError) },
        });
      }

      throw error;
    }
  }

  /**
   * Verify magic link token and create session
   */
  async verifyMagicLink(request: VerifyMagicLinkRequest): Promise<VerifyMagicLinkResponse> {
    const startTime = Date.now();
    
    try {
      this.logger.info('Starting magic link verification', {
        tokenLength: request.token.length,
        hasProfile: !!request.profile,
        ipAddress: request.ipAddress,
        correlationId: this.correlationId,
      });

      // Find and validate token
      const tokenHash = await hashToken(request.token);
      const magicToken = await this.tokenRepo.findByTokenHash(tokenHash);

      if (!magicToken) {
        throw new AuthError(
          ErrorCode.INVALID_TOKEN,
          'Invalid or expired magic link',
          401,
          { tokenHash: tokenHash.substring(0, 8) },
          this.correlationId,
          'The magic link is invalid or has expired. Please request a new one.'
        );
      }

      // Additional token verification using timing-safe comparison
      if (!verifyTokenHash(request.token, magicToken.tokenHash)) {
        throw new AuthError(
          ErrorCode.INVALID_TOKEN,
          'Invalid magic link token',
          401,
          { tokenId: magicToken.id },
          this.correlationId,
          'The magic link is invalid. Please request a new one.'
        );
      }

      // Check if token has expired
      if (hasExpired(magicToken.expiresAt)) {
        throw new AuthError(
          ErrorCode.TOKEN_EXPIRED,
          'Magic link expired',
          401,
          { 
            tokenId: magicToken.id,
            expiresAt: magicToken.expiresAt.toISOString(),
          },
          this.correlationId,
          'The magic link has expired. Please request a new one.'
        );
      }

      // Check if token is already used
      if (magicToken.isUsed) {
        throw new AuthError(
          ErrorCode.TOKEN_ALREADY_USED,
          'Magic link already used',
          401,
          { 
            tokenId: magicToken.id,
            usedAt: magicToken.usedAt?.toISOString(),
          },
          this.correlationId,
          'The magic link has already been used. Please request a new one.'
        );
      }

      const isNewUser = magicToken.isForNewUser;
      
      this.logger.debug('Magic token validated', {
        tokenId: magicToken.id,
        email: magicToken.email,
        isNewUser,
        userId: magicToken.userId,
        correlationId: this.correlationId,
      });

      // Start database transaction for user verification and session creation
      const result = await this.dataSource.transaction(async (manager) => {
        // Create new repository instances with the same correlation ID for the transaction
        const transactionUserRepo = new UserRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );
        const transactionProfileRepo = new ProfileRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );
        const transactionSessionRepo = new SessionRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );
        const transactionTokenRepo = new MagicSigninTokenRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );
        const transactionAuditRepo = new AuditLogRepository(
          { getRepository: (entity) => manager.getRepository(entity) } as DataSource,
          this.correlationId
        );

        let user: User;

        if (isNewUser) {
          // Find the unverified user and mark as verified
          const foundUser = await transactionUserRepo.findByEmail(magicToken.email);
          if (!foundUser) {
            throw new AuthError(
              ErrorCode.RECORD_NOT_FOUND,
              'User account not found',
              404,
              { email: magicToken.email },
              this.correlationId
            );
          }

          // Mark user as verified
          user = await transactionUserRepo.markAsVerified(foundUser.id);
          
          // Validate and create profile if provided (new users should provide profile)
          if (!request.profile?.firstName || !request.profile?.lastName) {
            throw new AuthError(
              ErrorCode.MISSING_REQUIRED_FIELD,
              'Profile details are required for new accounts',
              400,
              { 
                email: user.email,
                missingFields: {
                  firstName: !request.profile?.firstName,
                  lastName: !request.profile?.lastName,
                }
              },
              this.correlationId,
              'Please provide your first and last name to complete account setup.'
            );
          }

          // Create profile
          await transactionProfileRepo.create({
            userId: user.id,
            firstName: request.profile.firstName,
            lastName: request.profile.lastName,
          });

          // Link token to user
          await transactionTokenRepo.linkToUser(magicToken.id, user.id);

          this.logger.info('New user verified and profile created', {
            userId: user.id,
            email: user.email,
            hasProfile: true,
            correlationId: this.correlationId,
          });

        } else {
          // Get existing verified user
          const foundUser = await transactionUserRepo.findById(magicToken.userId!);
          if (!foundUser) {
            throw new AuthError(
              ErrorCode.RECORD_NOT_FOUND,
              'User account not found',
              404,
              { userId: magicToken.userId },
              this.correlationId
            );
          }

          if (!foundUser.isVerified) {
            throw new AuthError(
              ErrorCode.ACCOUNT_NOT_VERIFIED,
              'Account not verified',
              401,
              { userId: foundUser.id },
              this.correlationId
            );
          }

          user = foundUser;
        }

        // Mark token as used
        await transactionTokenRepo.markAsUsed(magicToken.id);

        // Create new session
        const sessionToken = generateSessionToken();
        const sessionTokenHash = await hashToken(sessionToken);
        const sessionExpiresAt = createExpirationDate(this.config.sessionTTLSeconds);

        const session = await transactionSessionRepo.create({
          userId: user.id,
          tokenHash: sessionTokenHash,
          expiresAt: sessionExpiresAt,
          ipAddress: request.ipAddress || undefined,
          userAgent: request.userAgent || undefined,
          country: request.country || undefined,
          city: request.city || undefined,
        });

        // Log audit events
        if (isNewUser) {
          await transactionAuditRepo.logSuccess(
            user.email,
            AuditEvent.ACCOUNT_CONFIRMED,
            {
              userId: user.id,
              context: {
                hasProfile: !!request.profile,
                sessionId: session.id,
              },
              ipAddress: request.ipAddress,
              userAgent: request.userAgent,
              country: request.country,
              city: request.city,
              correlationId: this.correlationId,
            }
          );
        }

        await transactionAuditRepo.logSuccess(
          user.email,
          AuditEvent.SIGNIN_SUCCESS,
          {
            userId: user.id,
            context: {
              method: 'magic_link',
              isNewUser,
              sessionId: session.id,
            },
            ipAddress: request.ipAddress || undefined,
            userAgent: request.userAgent || undefined,
            country: request.country || undefined,
            city: request.city || undefined,
            correlationId: this.correlationId,
          }
        );

        await transactionAuditRepo.logSuccess(
          user.email,
          AuditEvent.SESSION_CREATED,
          {
            userId: user.id,
            context: {
              sessionId: session.id,
              expiresAt: session.expiresAt.toISOString(),
            },
            ipAddress: request.ipAddress || undefined,
            userAgent: request.userAgent || undefined,
            correlationId: this.correlationId,
          }
        );

        return { user, session, sessionToken };
      });

      const duration = Date.now() - startTime;
      this.logger.info('Magic link verification completed successfully', {
        userId: result.user.id,
        email: result.user.email,
        isNewUser,
        sessionId: result.session.id,
        duration,
        correlationId: this.correlationId,
      });

      // Set session token in result
      (result.session as any).token = result.sessionToken;

      return {
        success: true,
        message: isNewUser ? 'Account created and signed in successfully' : 'Signed in successfully',
        user: result.user,
        session: result.session,
        isNewUser,
        redirectUrl: magicToken.redirectUrl || undefined,
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.logger.error('Magic link verification failed', {
        tokenLength: request.token.length,
        duration,
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      // Log audit failure for specific email if we can determine it
      try {
        const tokenHash = await hashToken(request.token);
        const magicToken = await this.tokenRepo.findByTokenHash(tokenHash);
        
        if (magicToken) {
          await this.auditRepo.logFailure(
            magicToken.email,
            AuditEvent.SIGNIN_FAILED,
            error instanceof Error ? error.message : 'Unknown error',
            {
              userId: magicToken.userId || undefined,
              context: { 
                method: 'magic_link',
                error: error instanceof Error ? error.name : 'UnknownError',
                tokenId: magicToken.id,
              },
              ipAddress: request.ipAddress,
              userAgent: request.userAgent,
              correlationId: this.correlationId,
            }
          );
        }
      } catch (auditError) {
        this.logger.error('Failed to log audit failure', {
          correlationId: this.correlationId,
          error: auditError instanceof Error ? {
            message: auditError.message,
            name: auditError.name,
            stack: auditError.stack,
          } : { message: String(auditError) },
        });
      }

      throw error;
    }
  }

  /**
   * Check rate limiting for magic link requests
   */
  private async checkRateLimit(email: string, ipAddress?: string): Promise<void> {
    const rateLimitKey = `magic_link:${email}`;
    const ipRateLimitKey = ipAddress ? `magic_link_ip:${ipAddress}` : undefined;

    // Check email-based rate limit
    const emailLimited = await this.rateLimitService.isRateLimited(
      rateLimitKey,
      this.config.rateLimitCount,
      this.config.rateLimitWindow
    );

    if (emailLimited) {
      this.logger.warn('Rate limit exceeded for email', { 
        email, 
        ipAddress,
        correlationId: this.correlationId,
      });
      
      throw new AuthError(
        ErrorCode.RATE_LIMIT_EXCEEDED,
        'Too many magic link requests',
        429,
        { email, ipAddress },
        this.correlationId,
        'Too many sign-in attempts. Please wait before trying again.'
      );
    }

    // Check IP-based rate limit if IP is available
    if (ipAddress) {
      const ipLimited = await this.rateLimitService.isRateLimited(
        ipRateLimitKey!,
        this.config.rateLimitCount * 2, // Allow more attempts per IP
        this.config.rateLimitWindow
      );

      if (ipLimited) {
        this.logger.warn('Rate limit exceeded for IP', { 
          email, 
          ipAddress,
          correlationId: this.correlationId,
        });
        
        throw new AuthError(
          ErrorCode.RATE_LIMIT_EXCEEDED,
          'Too many requests from this IP',
          429,
          { email, ipAddress },
          this.correlationId,
          'Too many requests from your location. Please wait before trying again.'
        );
      }
    }

    // Increment rate limit counters
    await this.rateLimitService.incrementRateLimit(rateLimitKey, this.config.rateLimitWindow);
    if (ipRateLimitKey) {
      await this.rateLimitService.incrementRateLimit(ipRateLimitKey, this.config.rateLimitWindow);
    }
  }

  /**
   * Validate session token and get user
   */
  async validateSession(sessionToken: string): Promise<{ user: User; session: Session } | null> {
    try {
      this.logger.debug('Validating session token', {
        tokenLength: sessionToken.length,
        correlationId: this.correlationId,
      });

      const tokenHash = await hashToken(sessionToken);
      const session = await this.sessionRepo.findByTokenHash(tokenHash);

      if (!session || !session.isValid) {
        this.logger.debug('Invalid session token', {
          found: !!session,
          isValid: session?.isValid,
          isExpired: session?.isExpired,
          isActive: session?.isActive,
          correlationId: this.correlationId,
        });
        return null;
      }

      // Additional validation using timing-safe comparison
      if (!verifyTokenHash(sessionToken, session.tokenHash)) {
        this.logger.debug('Session token verification failed', {
          correlationId: this.correlationId,
        });
        return null;
      }

      // Check if session has expired using utility function
      if (hasExpired(session.expiresAt)) {
        this.logger.debug('Session has expired', {
          sessionId: session.id,
          expiresAt: session.expiresAt.toISOString(),
          correlationId: this.correlationId,
        });
        return null;
      }

      // Update last accessed time
      await this.sessionRepo.updateLastAccessed(session.id);

      this.logger.debug('Session validated successfully', {
        sessionId: session.id,
        userId: session.userId,
        lastAccessed: session.lastAccessedAt,
        correlationId: this.correlationId,
      });

      return {
        user: session.user!,
        session,
      };

    } catch (error) {
      this.logger.error('Session validation error', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      return null;
    }
  }

  /**
   * Sign out user and revoke session
   */
  async signOut(sessionToken: string, ipAddress?: string, userAgent?: string): Promise<void> {
    try {
      this.logger.info('Starting sign out process', {
        tokenLength: sessionToken.length,
        ipAddress,
        correlationId: this.correlationId,
      });

      const tokenHash = await hashToken(sessionToken);
      const session = await this.sessionRepo.findByTokenHash(tokenHash);

      if (session) {
        await this.sessionRepo.revoke(session.id);

        // Log audit event
        await this.auditRepo.logSuccess(
          session.user!.email,
          AuditEvent.SIGNOUT,
          {
            userId: session.userId,
            context: {
              sessionId: session.id,
            },
            ipAddress: ipAddress || undefined,
            userAgent: userAgent || undefined,
            correlationId: this.correlationId,
          }
        );

        this.logger.info('Sign out completed successfully', {
          sessionId: session.id,
          userId: session.userId,
          email: session.user!.email,
          correlationId: this.correlationId,
        });
      } else {
        this.logger.debug('Session not found for sign out', {
          tokenHashPrefix: tokenHash.substring(0, 8),
          correlationId: this.correlationId,
        });
      }

    } catch (error) {
      this.logger.error('Sign out error', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw error;
    }
  }

  /**
   * Clean up expired tokens and sessions
   */
  async cleanupExpired(): Promise<{ expiredTokens: number; expiredSessions: number }> {
    try {
      this.logger.debug('Starting cleanup of expired tokens and sessions', {
        correlationId: this.correlationId,
      });

      const [expiredTokens, expiredSessions] = await Promise.all([
        this.tokenRepo.cleanupExpired(),
        this.sessionRepo.cleanupExpired(),
      ]);

      this.logger.info('Cleanup completed', {
        expiredTokens,
        expiredSessions,
        correlationId: this.correlationId,
      });

      return { expiredTokens, expiredSessions };

    } catch (error) {
      this.logger.error('Cleanup error', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw error;
    }
  }

  /**
   * Get user profile by user ID (using Profile entity)
   */
  async getUserProfile(userId: string): Promise<Profile | null> {
    try {
      this.logger.debug('Getting user profile', { 
        userId,
        correlationId: this.correlationId,
      });
      
      const profile = await this.profileRepo.findByUserId(userId);
      
      this.logger.debug('User profile retrieved', { 
        userId, 
        found: !!profile,
        profileId: profile?.id,
        correlationId: this.correlationId,
      });
      
      return profile;
    } catch (error) {
      this.logger.error('Error getting user profile', {
        userId,
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw error;
    }
  }

  /**
   * Get magic signin token details (using MagicSigninToken entity)
   */
  async getMagicTokenDetails(tokenId: string): Promise<MagicSigninToken | null> {
    try {
      this.logger.debug('Getting magic token details', { 
        tokenId,
        correlationId: this.correlationId,
      });
      
      const token = await this.tokenRepo.findById(tokenId);
      
      this.logger.debug('Magic token details retrieved', { 
        tokenId, 
        found: !!token,
        isUsed: token?.isUsed,
        isValid: token?.isValid,
        correlationId: this.correlationId,
      });
      
      return token;
    } catch (error) {
      this.logger.error('Error getting magic token details', {
        tokenId,
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw error;
    }
  }

  /**
   * Get audit logs for user (using AuditLog entity)
   */
  async getUserAuditLogs(userId: string, limit: number = 10): Promise<AuditLog[]> {
    try {
      this.logger.debug('Getting user audit logs', { 
        userId, 
        limit,
        correlationId: this.correlationId,
      });
      
      const auditLogs = await this.auditRepo.findRecentForUser(userId, limit);
      
      this.logger.debug('User audit logs retrieved', { 
        userId, 
        count: auditLogs.length,
        correlationId: this.correlationId,
      });
      
      return auditLogs;
    } catch (error) {
      this.logger.error('Error getting user audit logs', {
        userId,
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw error;
    }
  }

  /**
   * Get correlation ID for this service instance
   */
  getCorrelationId(): string {
    return this.correlationId;
  }

  /**
   * Create AuthService instance
   */
  static create(correlationId?: string): AuthService {
    return new AuthService(correlationId);
  }

  /**
   * Create AuthService instance with database validation
   */
  static async createWithConnection(correlationId?: string): Promise<AuthService> {
    // Ensure database is connected
    if (!isDatabaseConnected()) {
      throw new AuthError(
        ErrorCode.DATABASE_ERROR,
        'Database connection required but not available',
        500,
        { correlationId },
        correlationId,
        'Database service is not available'
      );
    }
    
    return new AuthService(correlationId);
  }
}
