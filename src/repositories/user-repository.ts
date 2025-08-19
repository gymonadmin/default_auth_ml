// src/repositories/user-repository.ts
import { Repository, DataSource, IsNull } from 'typeorm';
import { User } from '@/entities/user';
import { DatabaseError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export class UserRepository {
  private repository: Repository<User>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(User);
    this.logger = new Logger(correlationId);
  }

  /**
   * Find user by email (excluding deleted users)
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      this.logger.debug('Finding user by email', { email: email.toLowerCase() });
      
      const user = await this.repository.findOne({
        where: {
          email: email.toLowerCase(),
          deletedAt: IsNull(),
        },
        relations: ['profile'],
      });

      this.logger.debug('User found by email', { 
        found: !!user, 
        userId: user?.id,
        isVerified: user?.isVerified 
      });

      return user;
    } catch (error) {
      this.logger.error('Error finding user by email', error instanceof Error ? error : new Error(String(error)), { email });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find user by email',
        { email },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find user by ID (excluding deleted users)
   */
  async findById(id: string): Promise<User | null> {
    try {
      this.logger.debug('Finding user by ID', { userId: id });
      
      const user = await this.repository.findOne({
        where: {
          id,
          deletedAt: IsNull(),
        },
        relations: ['profile'],
      });

      this.logger.debug('User found by ID', { 
        found: !!user, 
        userId: id,
        isVerified: user?.isVerified 
      });

      return user;
    } catch (error) {
      this.logger.error('Error finding user by ID', error instanceof Error ? error : new Error(String(error)), { userId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find user by ID',
        { userId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Create a new user
   */
  async create(userData: { email: string; isVerified?: boolean }): Promise<User> {
    try {
      this.logger.debug('Creating new user', { email: userData.email });
      
      const user = this.repository.create({
        email: userData.email.toLowerCase(),
        isVerified: userData.isVerified || false,
        verifiedAt: userData.isVerified ? new Date() : null,
      });

      const savedUser = await this.repository.save(user);
      
      this.logger.info('User created successfully', { 
        userId: savedUser.id, 
        email: savedUser.email,
        isVerified: savedUser.isVerified
      });

      return savedUser;
    } catch (error) {
      this.logger.error('Error creating user', error instanceof Error ? error : new Error(String(error)), { email: userData.email });
      
      if (error instanceof Error && 'code' in error && (error as any).code === '23505') {
        throw new DatabaseError(
          ErrorCode.DUPLICATE_RECORD,
          'User with this email already exists',
          { email: userData.email },
          this.logger['correlationId']
        );
      }
      
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to create user',
        { email: userData.email },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Update user
   */
  async update(id: string, updates: Partial<User>): Promise<User> {
    try {
      this.logger.debug('Updating user', { userId: id, updates });
      
      const user = await this.findById(id);
      if (!user) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'User not found',
          { userId: id },
          this.logger['correlationId']
        );
      }

      Object.assign(user, updates);
      const savedUser = await this.repository.save(user);
      
      this.logger.info('User updated successfully', { 
        userId: savedUser.id,
        updatedFields: Object.keys(updates)
      });

      return savedUser;
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating user', error instanceof Error ? error : new Error(String(error)), { userId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to update user',
        { userId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Mark user as verified
   */
  async markAsVerified(id: string): Promise<User> {
    try {
      this.logger.debug('Marking user as verified', { userId: id });
      
      const user = await this.findById(id);
      if (!user) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'User not found',
          { userId: id },
          this.logger['correlationId']
        );
      }

      user.markAsVerified();
      const savedUser = await this.repository.save(user);
      
      this.logger.info('User marked as verified', { userId: savedUser.id });
      return savedUser;
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error marking user as verified', error instanceof Error ? error : new Error(String(error)), { userId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to mark user as verified',
        { userId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Soft delete user
   */
  async softDelete(id: string): Promise<void> {
    try {
      this.logger.debug('Soft deleting user', { userId: id });
      
      const user = await this.findById(id);
      if (!user) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'User not found',
          { userId: id },
          this.logger['correlationId']
        );
      }

      user.markAsDeleted();
      await this.repository.save(user);
      
      this.logger.info('User soft deleted successfully', { userId: id });
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error soft deleting user', error instanceof Error ? error : new Error(String(error)), { userId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to soft delete user',
        { userId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Check if email exists (excluding deleted users)
   */
  async emailExists(email: string): Promise<boolean> {
    try {
      this.logger.debug('Checking if email exists', { email: email.toLowerCase() });
      
      const count = await this.repository.count({
        where: {
          email: email.toLowerCase(),
          deletedAt: IsNull(),
        },
      });

      const exists = count > 0;
      this.logger.debug('Email existence check result', { 
        email: email.toLowerCase(), 
        exists 
      });

      return exists;
    } catch (error) {
      this.logger.error('Error checking email existence', error instanceof Error ? error : new Error(String(error)), { email });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to check email existence',
        { email },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find users by verification status
   */
  async findByVerificationStatus(isVerified: boolean, limit: number = 100): Promise<User[]> {
    try {
      this.logger.debug('Finding users by verification status', { isVerified, limit });
      
      const users = await this.repository.find({
        where: {
          isVerified,
          deletedAt: IsNull(),
        },
        relations: ['profile'],
        take: limit,
        order: {
          createdAt: 'DESC',
        },
      });

      this.logger.debug('Users found by verification status', { 
        isVerified, 
        count: users.length 
      });

      return users;
    } catch (error) {
      this.logger.error('Error finding users by verification status', error instanceof Error ? error : new Error(String(error)), { isVerified });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find users by verification status',
        { isVerified },
        this.logger['correlationId']
      );
    }
  }
}
