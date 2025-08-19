// src/repositories/profile-repository.ts
import { Repository, DataSource } from 'typeorm';
import { Profile } from '@/entities/profile';
import { DatabaseError, ErrorCode } from '@/lib/errors/error-codes';
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
   * Find profile by user ID
   */
  async findByUserId(userId: string): Promise<Profile | null> {
    try {
      this.logger.debug('Finding profile by user ID', { userId });
      
      const profile = await this.repository.findOne({
        where: { userId },
        relations: ['user'],
      });

      this.logger.debug('Profile found by user ID', { 
        found: !!profile, 
        userId,
        profileId: profile?.id 
      });

      return profile;
    } catch (error) {
      this.logger.error('Error finding profile by user ID', error instanceof Error ? error : new Error(String(error)), { userId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find profile by user ID',
        { userId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Find profile by ID
   */
  async findById(id: string): Promise<Profile | null> {
    try {
      this.logger.debug('Finding profile by ID', { profileId: id });
      
      const profile = await this.repository.findOne({
        where: { id },
        relations: ['user'],
      });

      this.logger.debug('Profile found by ID', { 
        found: !!profile, 
        profileId: id,
        userId: profile?.userId 
      });

      return profile;
    } catch (error) {
      this.logger.error('Error finding profile by ID', error instanceof Error ? error : new Error(String(error)), { profileId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to find profile by ID',
        { profileId: id },
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
      });

      const savedProfile = await this.repository.save(profile);
      
      this.logger.info('Profile created successfully', { 
        profileId: savedProfile.id,
        userId: savedProfile.userId,
        fullName: savedProfile.fullName
      });

      return savedProfile;
    } catch (error) {
      this.logger.error('Error creating profile', error instanceof Error ? error : new Error(String(error)), { userId: profileData.userId });
      
      if (error instanceof Error && 'code' in error && (error as any).code === '23505') {
        throw new DatabaseError(
          ErrorCode.DUPLICATE_RECORD,
          'Profile already exists for this user',
          { userId: profileData.userId },
          this.logger['correlationId']
        );
      }
      
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to create profile',
        { userId: profileData.userId },
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
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating profile', error instanceof Error ? error : new Error(String(error)), { profileId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to update profile',
        { profileId: id },
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
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error updating profile name', error instanceof Error ? error : new Error(String(error)), { profileId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to update profile name',
        { profileId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Delete profile
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
      if (error instanceof DatabaseError) {
        throw error;
      }
      
      this.logger.error('Error deleting profile', error instanceof Error ? error : new Error(String(error)), { profileId: id });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to delete profile',
        { profileId: id },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Check if profile exists for user
   */
  async existsForUser(userId: string): Promise<boolean> {
    try {
      this.logger.debug('Checking if profile exists for user', { userId });
      
      const count = await this.repository.count({
        where: { userId },
      });

      const exists = count > 0;
      this.logger.debug('Profile existence check result', { 
        userId, 
        exists 
      });

      return exists;
    } catch (error) {
      this.logger.error('Error checking profile existence', error instanceof Error ? error : new Error(String(error)), { userId });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to check profile existence',
        { userId },
        this.logger['correlationId']
      );
    }
  }

  /**
   * Search profiles by name
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
      this.logger.error('Error searching profiles by name', error instanceof Error ? error : new Error(String(error)), { query });
      throw new DatabaseError(
        ErrorCode.DATABASE_ERROR,
        'Failed to search profiles by name',
        { query },
        this.logger['correlationId']
      );
    }
  }
}
