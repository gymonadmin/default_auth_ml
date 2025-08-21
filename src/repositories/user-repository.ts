// src/repositories/user-repository.ts
import { Repository, DataSource, IsNull } from 'typeorm';
import { User } from '@/entities/user';
import { Profile } from '@/entities/profile';
import { DatabaseError, ErrorCode, mapDatabaseErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export class UserRepository {
  private repository: Repository<User>;
  private profileRepository: Repository<Profile>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(User);
    this.profileRepository = dataSource.getRepository(Profile);
    this.logger = new Logger(correlationId);
  }

  /**
   * Manually join profile data to user
   */
  private async joinProfileData(user: User): Promise<User> {
    try {
      // Get profile data
      const profile = await this.profileRepository.findOne({
        where: { 
          userId: user.id,
          deletedAt: IsNull()
        }
      });

      // Manually attach the profile data
      if (profile) {
        user.profile = profile;
      }

      return user;
    } catch (error) {
      this.logger.error('Error joining profile data to user', {
        userId: user.id,
        error: error instanceof Error ? error.message : String(error),
      });
      return user;
    }
  }

  /**
   * Find user by email (excluding deleted users) with profile
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      this.logger.debug('Finding user by email', { email: email.toLowerCase() });
      
      const user = await this.repository.findOne({
        where: {
          email: email.toLowerCase(),
          deletedAt: IsNull(),
        }
      });

      if (!user) {
        this.logger.debug('User not found by email', { email: email.toLowerCase() });
        return null;
      }

      this.logger.debug('User found by email', { 
        found: true, 
        userId: user.id,
        isVerified: user.isVerified 
      });

      // Manually join profile data
      return await this.joinProfileData(user);
    } catch (error) {
      this.logger.error('Error finding user by email', {
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
        'Failed to find user by email',
        { 
          email,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find user by ID (excluding deleted users) with profile
   */
  async findById(id: string): Promise<User | null> {
    try {
      this.logger.debug('Finding user by ID', { userId: id });
      
      const user = await this.repository.findOne({
        where: {
          id,
          deletedAt: IsNull(),
        }
      });

      if (!user) {
        this.logger.debug('User not found by ID', { userId: id });
        return null;
      }

      this.logger.debug('User found by ID', { 
        found: true, 
        userId: id,
        isVerified: user.isVerified 
      });

      // Manually join profile data
      return await this.joinProfileData(user);
    } catch (error) {
      this.logger.error('Error finding user by ID', {
        userId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find user by ID',
        { 
          userId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      this.logger.error('Error creating user', {
        email: userData.email,
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
          ? 'User with this email already exists'
          : 'Failed to create user',
        { 
          email: userData.email,
          originalError: error instanceof Error ? error.name : 'Unknown',
          pgCode: error && typeof error === 'object' && 'code' in error ? error.code : undefined
        },
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
      
      const user = await this.repository.findOne({
        where: { id, deletedAt: IsNull() }
      });
      
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

      // Return user with profile data
      return await this.joinProfileData(savedUser);
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating user', {
        userId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to update user',
        { 
          userId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      
      const user = await this.repository.findOne({
        where: { id, deletedAt: IsNull() }
      });
      
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
      
      // Return user with profile data
      return await this.joinProfileData(savedUser);
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error marking user as verified', {
        userId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to mark user as verified',
        { 
          userId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      
      const user = await this.repository.findOne({
        where: { id, deletedAt: IsNull() }
      });
      
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
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error soft deleting user', {
        userId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to soft delete user',
        { 
          userId: id,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
      this.logger.error('Error checking email existence', {
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
        'Failed to check email existence',
        { 
          email,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
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
        take: limit,
        order: {
          createdAt: 'DESC',
        },
      });

      // Manually join profile data for each user
      const usersWithProfiles = await Promise.all(
        users.map(user => this.joinProfileData(user))
      );

      this.logger.debug('Users found by verification status', { 
        isVerified, 
        count: usersWithProfiles.length 
      });

      return usersWithProfiles;
    } catch (error) {
      this.logger.error('Error finding users by verification status', {
        isVerified,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find users by verification status',
        { 
          isVerified,
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }
}
