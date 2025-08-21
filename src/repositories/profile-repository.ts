// src/repositories/profile-repository.ts
import { Repository, DataSource, IsNull } from 'typeorm';
import { Profile } from '@/entities/profile';
import { DatabaseError, ErrorCode, mapDatabaseErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface CreateProfileData {
  userId: string;
  firstName: string;
  lastName: string;
}

export class ProfileRepository {
  private repository: Repository<Profile>;
  private logger: Logger;

  constructor(dataSource: DataSource, correlationId?: string) {
    this.repository = dataSource.getRepository(Profile);
    this.logger = new Logger(correlationId);
  }

  /**
   * Find profile by user ID (excluding deleted profiles)
   */
  async findByUserId(userId: string): Promise<Profile | null> {
    try {
      this.logger.debug('Finding profile by user ID', { userId });
      
      const profile = await this.repository.findOne({
        where: { 
          userId,
          deletedAt: IsNull()
        },
        relations: ['user'],
      });

      this.logger.debug('Profile found by user ID', { 
        found: !!profile, 
        userId,
        profileId: profile?.id 
      });

      return profile;
    } catch (error) {
      this.logger.error('Error finding profile by user ID', {
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
        'Failed to find profile by user ID',
        { userId, originalError: error instanceof Error ? error.name : 'Unknown' },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find profile by ID (excluding deleted profiles)
   */
  async findById(id: string): Promise<Profile | null> {
    try {
      this.logger.debug('Finding profile by ID', { profileId: id });
      
      const profile = await this.repository.findOne({
        where: { 
          id,
          deletedAt: IsNull()
        },
        relations: ['user'],
      });

      this.logger.debug('Profile found by ID', { 
        found: !!profile, 
        profileId: id,
        userId: profile?.userId 
      });

      return profile;
    } catch (error) {
      this.logger.error('Error finding profile by ID', {
        profileId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to find profile by ID',
        { profileId: id, originalError: error instanceof Error ? error.name : 'Unknown' },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Create a new profile
   */
  async create(profileData: CreateProfileData): Promise<Profile> {
    try {
      this.logger.debug('Creating new profile', { 
        userId: profileData.userId,
        firstName: profileData.firstName,
        lastName: profileData.lastName
      });
      
      const profile = this.repository.create({
        userId: profileData.userId,
        firstName: profileData.firstName.trim(),
        lastName: profileData.lastName.trim(),
        deletedAt: null,
      });

      const savedProfile = await this.repository.save(profile);
      
      this.logger.info('Profile created successfully', { 
        profileId: savedProfile.id,
        userId: savedProfile.userId,
        fullName: savedProfile.fullName
      });

      return savedProfile;
    } catch (error) {
      this.logger.error('Error creating profile', {
        userId: profileData.userId,
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
          ? 'Profile already exists for this user'
          : 'Failed to create profile',
        { 
          userId: profileData.userId, 
          originalError: error instanceof Error ? error.name : 'Unknown',
          pgCode: error && typeof error === 'object' && 'code' in error ? error.code : undefined
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Update profile
   */
  async update(id: string, updates: Partial<Profile>): Promise<Profile> {
    try {
      this.logger.debug('Updating profile', { profileId: id, updates });
      
      const profile = await this.findById(id);
      if (!profile) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Profile not found',
          { profileId: id },
          this.logger['correlationId']
        );
      }

      Object.assign(profile, updates);
      const savedProfile = await this.repository.save(profile);
      
      this.logger.info('Profile updated successfully', { 
        profileId: savedProfile.id,
        updatedFields: Object.keys(updates)
      });

      return savedProfile;
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating profile', {
        profileId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to update profile',
        { 
          profileId: id, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Update profile name
   */
  async updateName(id: string, firstName: string, lastName: string): Promise<Profile> {
    try {
      this.logger.debug('Updating profile name', { 
        profileId: id, 
        firstName, 
        lastName 
      });
      
      const profile = await this.findById(id);
      if (!profile) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Profile not found',
          { profileId: id },
          this.logger['correlationId']
        );
      }

      profile.updateName(firstName, lastName);
      const savedProfile = await this.repository.save(profile);
      
      this.logger.info('Profile name updated successfully', { 
        profileId: savedProfile.id,
        fullName: savedProfile.fullName
      });

      return savedProfile;
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating profile name', {
        profileId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to update profile name',
        { 
          profileId: id, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Soft delete profile
   */
  async softDelete(id: string): Promise<void> {
    try {
      this.logger.debug('Soft deleting profile', { profileId: id });
      
      const profile = await this.findById(id);
      if (!profile) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Profile not found',
          { profileId: id },
          this.logger['correlationId']
        );
      }

      profile.markAsDeleted();
      await this.repository.save(profile);
      
      this.logger.info('Profile soft deleted successfully', { profileId: id });
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error soft deleting profile', {
        profileId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to soft delete profile',
        { 
          profileId: id, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Soft delete profile by user ID
   */
  async softDeleteByUserId(userId: string): Promise<void> {
    try {
      this.logger.debug('Soft deleting profile by user ID', { userId });
      
      const profile = await this.findByUserId(userId);
      if (!profile) {
        this.logger.debug('No profile found for user ID', { userId });
        return; // No profile to delete
      }

      profile.markAsDeleted();
      await this.repository.save(profile);
      
      this.logger.info('Profile soft deleted successfully by user ID', { 
        userId, 
        profileId: profile.id 
      });
    } catch (error) {
      this.logger.error('Error soft deleting profile by user ID', {
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
        'Failed to soft delete profile by user ID',
        { 
          userId, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Delete profile (hard delete)
   */
  async delete(id: string): Promise<void> {
    try {
      this.logger.debug('Deleting profile', { profileId: id });
      
      const profile = await this.findById(id);
      if (!profile) {
        throw new DatabaseError(
          ErrorCode.RECORD_NOT_FOUND,
          'Profile not found',
          { profileId: id },
          this.logger['correlationId']
        );
      }

      await this.repository.remove(profile);
      
      this.logger.info('Profile deleted successfully', { profileId: id });
    } catch (error) {
      // Re-throw if it's already a DatabaseError
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error deleting profile', {
        profileId: id,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to delete profile',
        { 
          profileId: id, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Check if profile exists for user (excluding deleted)
   */
  async existsForUser(userId: string): Promise<boolean> {
    try {
      this.logger.debug('Checking if profile exists for user', { userId });
      
      const count = await this.repository.count({
        where: { 
          userId,
          deletedAt: IsNull()
        },
      });

      const exists = count > 0;
      this.logger.debug('Profile existence check result', { 
        userId, 
        exists 
      });

      return exists;
    } catch (error) {
      this.logger.error('Error checking profile existence', {
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
        'Failed to check profile existence',
        { 
          userId, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Search profiles by name (excluding deleted)
   */
  async searchByName(query: string, limit: number = 20): Promise<Profile[]> {
    try {
      this.logger.debug('Searching profiles by name', { query, limit });
      
      const profiles = await this.repository
        .createQueryBuilder('profile')
        .leftJoinAndSelect('profile.user', 'user')
        .where(
          'LOWER(profile.firstName) LIKE LOWER(:query) OR LOWER(profile.lastName) LIKE LOWER(:query)',
          { query: `%${query}%` }
        )
        .andWhere('user.deletedAt IS NULL')
        .andWhere('profile.deletedAt IS NULL')
        .take(limit)
        .orderBy('profile.firstName', 'ASC')
        .addOrderBy('profile.lastName', 'ASC')
        .getMany();

      this.logger.debug('Profiles found by name search', { 
        query, 
        count: profiles.length 
      });

      return profiles;
    } catch (error) {
      this.logger.error('Error searching profiles by name', {
        query,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });

      const errorCode = mapDatabaseErrorCode(error);
      throw new DatabaseError(
        errorCode,
        'Failed to search profiles by name',
        { 
          query, 
          originalError: error instanceof Error ? error.name : 'Unknown' 
        },
        this.logger['correlationId']
      );
    }
  }
}
