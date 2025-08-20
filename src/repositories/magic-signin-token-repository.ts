// src/repositories/magic-signin-token-repository.ts
import { Repository, DataSource, LessThan } from 'typeorm';
import { MagicSigninToken } from '@/entities/magic-signin-token';
import { DatabaseError, ErrorCode, mapDatabaseErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface CreateMagicSigninTokenData {
  userId?: string;
  email: string;
  tokenHash: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
  redirectUrl?: string;
}

export class MagicSigninTokenRepository {
  private repository: Repository<MagicSigninToken>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(MagicSigninToken);
    this.logger = new Logger(correlationId);
  }

  /**
   * Find token by token hash
   */
  async findByTokenHash(tokenHash: string): Promise<MagicSigninToken | null> {
    try {
      this.logger.debug('Finding magic signin token by hash', { 
        tokenHashPrefix: tokenHash.substring(0, 8) 
      });
      
      const token = await this.repository.findOne({
        where: { tokenHash },
        relations: ['user'],
      });

      this.logger.debug('Magic signin token found by hash', { 
        found: !!token, 
        tokenId: token?.id,
        email: token?.email,
        isUsed: token?.isUsed,
        isExpired: token?.isExpired,
        isValid: token?.isValid
      });

      return token;
    } catch (error) {
      this.logger.error('Error finding magic signin token by hash', {
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
        'Failed to find magic signin token by hash',
        { 
          tokenHashPrefix: tokenHash.substring(0, 8),
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find token by ID
   */
  async findById(id: string): Promise<MagicSigninToken | null> {
    try {
      this.logger.debug('Finding magic signin token by ID', { tokenId: id });
      
      const token = await this.repository.findOne({
        where: { id },
        relations: ['user'],
      });

      this.logger.debug('Magic signin token found by ID', { 
        found: !!token, 
        tokenId: id,
        email: token?.email,
        isUsed: token?.isUsed
      });

      return token;
    } catch (error) {
      this.logger.error('Error finding magic signin token by ID', {
        tokenId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find magic signin token by ID',
        { 
          tokenId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Create a new magic signin token
   */
  async create(tokenData: CreateMagicSigninTokenData): Promise<MagicSigninToken> {
    try {
      this.logger.debug('Creating new magic signin token', { 
        email: tokenData.email,
        userId: tokenData.userId,
        expiresAt: tokenData.expiresAt,
        isForNewUser: !tokenData.userId
      });
      
      const token = this.repository.create({
        userId: tokenData.userId || null,
        email: tokenData.email.toLowerCase(),
        tokenHash: tokenData.tokenHash,
        expiresAt: tokenData.expiresAt,
        ipAddress: tokenData.ipAddress || null,
        userAgent: tokenData.userAgent || null,
        country: tokenData.country || null,
        city: tokenData.city || null,
        redirectUrl: tokenData.redirectUrl || null,
        isUsed: false,
        usedAt: null,
      });

      const savedToken = await this.repository.save(token);
      
      this.logger.info('Magic signin token created successfully', { 
        tokenId: savedToken.id,
        email: savedToken.email,
        userId: savedToken.userId,
        expiresAt: savedToken.expiresAt
      });

      return savedToken;
    } catch (error) {
      this.logger.error('Error creating magic signin token', {
        email: tokenData.email,
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
          ? 'Magic signin token already exists'
          : 'Failed to create magic signin token',
        { 
          email: tokenData.email,
          originalError: error instanceof Error ? error.name : 'Unknown',
          pgCode: error && typeof error === 'object' && 'code' in error ? error.code : undefined
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Mark token as used
   */
  async markAsUsed(id: string): Promise<MagicSigninToken> {
    try {
      this.logger.debug('Marking magic signin token as used', { tokenId: id });
      
      const token = await this.findById(id);
      if (!token) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Magic signin token not found',
          { tokenId: id },
          this.logger['correlationId']
        );
      }

      token.markAsUsed();
      const savedToken = await this.repository.save(token);
      
      this.logger.info('Magic signin token marked as used', { 
        tokenId: savedToken.id,
        usedAt: savedToken.usedAt
      });

      return savedToken;
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error marking magic signin token as used', {
        tokenId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to mark magic signin token as used',
        { 
          tokenId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Link token to user
   */
  async linkToUser(id: string, userId: string): Promise<MagicSigninToken> {
    try {
      this.logger.debug('Linking magic signin token to user', { 
        tokenId: id, 
        userId 
      });
      
      const token = await this.findById(id);
      if (!token) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Magic signin token not found',
          { tokenId: id },
          this.logger['correlationId']
        );
      }

      token.linkToUser(userId);
      const savedToken = await this.repository.save(token);
      
      this.logger.info('Magic signin token linked to user', { 
        tokenId: savedToken.id,
        userId: savedToken.userId
      });

      return savedToken;
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error linking magic signin token to user', {
        tokenId: id,
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
        'Failed to link magic signin token to user',
        { 
          tokenId: id, 
          userId,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find valid tokens for email
   */
  async findValidForEmail(email: string): Promise<MagicSigninToken[]> {
    try {
      this.logger.debug('Finding valid magic signin tokens for email', { email });
      
      const tokens = await this.repository.find({
        where: {
          email: email.toLowerCase(),
          isUsed: false,
        },
        relations: ['user'],
        order: {
          createdAt: 'DESC',
        },
      });

      // Filter out expired tokens
      const validTokens = tokens.filter(token => token.isValid);

      this.logger.debug('Valid magic signin tokens found for email', { 
        email, 
        totalFound: tokens.length,
        validCount: validTokens.length
      });

      return validTokens;
    } catch (error) {
      this.logger.error('Error finding valid magic signin tokens for email', {
        email,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find valid magic signin tokens for email',
        { 
          email,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Invalidate all tokens for email
   */
  async invalidateAllForEmail(email: string): Promise<number> {
    try {
      this.logger.debug('Invalidating all magic signin tokens for email', { email });
      
      const result = await this.repository.update(
        { 
          email: email.toLowerCase(), 
          isUsed: false 
        },
        { 
          isUsed: true, 
          usedAt: new Date() 
        }
      );

      const invalidatedCount = result.affected || 0;
      
      this.logger.info('Magic signin tokens invalidated for email', { 
        email, 
        invalidatedCount 
      });

      return invalidatedCount;
    } catch (error) {
      this.logger.error('Error invalidating magic signin tokens for email', {
        email,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to invalidate magic signin tokens for email',
        { 
          email,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Clean up expired tokens
   */
  async cleanupExpired(): Promise<number> {
    try {
      this.logger.debug('Cleaning up expired magic signin tokens');
      
      const result = await this.repository.delete({
        expiresAt: LessThan(new Date()),
      });

      const deletedCount = result.affected || 0;
      
      this.logger.info('Expired magic signin tokens cleaned up', { deletedCount });

      return deletedCount;
    } catch (error) {
      this.logger.error('Error cleaning up expired magic signin tokens', {
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to cleanup expired magic signin tokens',
        { originalError: error instanceof Error ? error.name : 'Unknown' },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Count unused tokens for email in time window
   */
  async countUnusedForEmailInWindow(
    email: string, 
    windowStart: Date
  ): Promise<number> {
    try {
      this.logger.debug('Counting unused magic signin tokens for email in window', { 
        email, 
        windowStart 
      });
      
      const count = await this.repository.count({
        where: {
          email: email.toLowerCase(),
          isUsed: false,
          createdAt: LessThan(windowStart),
        },
      });

      this.logger.debug('Unused token count for email in window', { 
        email, 
        count 
      });

      return count;
    } catch (error) {
      this.logger.error('Error counting unused tokens for email in window', {
        email,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to count unused tokens for email in window',
        { 
          email,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find recent tokens for user
   */
  async findRecentForUser(userId: string, limit: number = 10): Promise<MagicSigninToken[]> {
    try {
      this.logger.debug('Finding recent magic signin tokens for user', { 
        userId, 
        limit 
      });
      
      const tokens = await this.repository.find({
        where: { userId },
        order: {
          createdAt: 'DESC',
        },
        take: limit,
      });

      this.logger.debug('Recent magic signin tokens found for user', { 
        userId, 
        count: tokens.length 
      });

      return tokens;
    } catch (error) {
      this.logger.error('Error finding recent magic signin tokens for user', {
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
        'Failed to find recent magic signin tokens for user',
        { 
          userId,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Update token location
   */
  async updateLocation(
    id: string, 
    ipAddress: string | null, 
    country: string | null, 
    city: string | null
  ): Promise<MagicSigninToken> {
    try {
      this.logger.debug('Updating magic signin token location', { 
        tokenId: id, 
        ipAddress, 
        country, 
        city 
      });
      
      const token = await this.findById(id);
      if (!token) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Magic signin token not found',
          { tokenId: id },
          this.logger['correlationId']
        );
      }

      token.updateLocation(ipAddress, country, city);
      const savedToken = await this.repository.save(token);
      
      this.logger.debug('Magic signin token location updated', { 
        tokenId: savedToken.id,
        ipAddress: savedToken.ipAddress,
        country: savedToken.country,
        city: savedToken.city
      });

      return savedToken;
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating magic signin token location', {
        tokenId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to update magic signin token location',
        { 
          tokenId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }
}
