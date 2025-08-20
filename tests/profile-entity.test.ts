// tests/profile-entity.test.ts
import { DataSource } from 'typeorm';
import { User } from '../src/entities/user';
import { Profile } from '../src/entities/profile';
import { 
  TestRunner, 
  setupTestDatabase, 
  cleanupTestDatabase, 
  clearAllTables,
  createTestUser,
  createTestProfile,
  TEST_PROFILES 
} from './setup';

describe('Profile Entity', () => {
  let dataSource: DataSource;
  let userRepository: any;
  let profileRepository: any;

  beforeAll(async () => {
    dataSource = await setupTestDatabase();
    userRepository = dataSource.getRepository(User);
    profileRepository = dataSource.getRepository(Profile);
  });

  afterAll(async () => {
    await cleanupTestDatabase(dataSource);
  });

  beforeEach(async () => {
    await clearAllTables(dataSource);
  });

  describe('Basic Operations', () => {
    it('should create a profile', async () => {
      // Create user first
      const userData = createTestUser();
      const user = userRepository.create(userData);
      const savedUser = await userRepository.save(user);

      // Create profile
      const profileData = createTestProfile(savedUser.id, TEST_PROFILES.john);
      const profile = profileRepository.create(profileData);
      const savedProfile = await profileRepository.save(profile);

      expect(savedProfile.id).toBeDefined();
      expect(savedProfile.userId).toBe(savedUser.id);
      expect(savedProfile.firstName).toBe(TEST_PROFILES.john.firstName);
      expect(savedProfile.lastName).toBe(TEST_PROFILES.john.lastName);
    });

    it('should enforce unique userId constraint', async () => {
      // Create user
      const userData = createTestUser();
      const user = userRepository.create(userData);
      const savedUser = await userRepository.save(user);

      // Create first profile
      const profileData1 = createTestProfile(savedUser.id, TEST_PROFILES.john);
      const profile1 = profileRepository.create(profileData1);
      await profileRepository.save(profile1);

      // Try to create second profile for same user
      const profileData2 = createTestProfile(savedUser.id, TEST_PROFILES.jane);
      const profile2 = profileRepository.create(profileData2);
      
      let errorThrown = false;
      try {
        await profileRepository.save(profile2);
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('Computed Properties', () => {
    it('should generate full name correctly', async () => {
      const profileData = createTestProfile('test-id', TEST_PROFILES.john);
      const profile = profileRepository.create(profileData);
      
      expect(profile.fullName).toBe('John Doe');
    });

    it('should generate initials correctly', async () => {
      const profileData = createTestProfile('test-id', TEST_PROFILES.jane);
      const profile = profileRepository.create(profileData);
      
      expect(profile.initials).toBe('JS');
    });

    it('should handle single names', async () => {
      const profileData = createTestProfile('test-id', { 
        firstName: 'Madonna', 
        lastName: '' 
      });
      const profile = profileRepository.create(profileData);
      
      expect(profile.fullName).toBe('Madonna');
      expect(profile.initials).toBe('M');
    });
  });

  describe('Methods', () => {
    it('should update name correctly', async () => {
      const profileData = createTestProfile('test-id', TEST_PROFILES.john);
      const profile = profileRepository.create(profileData);
      
      profile.updateName('Updated', 'Name');
      
      expect(profile.firstName).toBe('Updated');
      expect(profile.lastName).toBe('Name');
      expect(profile.fullName).toBe('Updated Name');
    });

    it('should trim whitespace when updating name', async () => {
      const profileData = createTestProfile('test-id', TEST_PROFILES.john);
      const profile = profileRepository.create(profileData);
      
      profile.updateName('  Spaced  ', '  Name  ');
      
      expect(profile.firstName).toBe('Spaced');
      expect(profile.lastName).toBe('Name');
    });
  });
});

// Run the tests
async function runTests() {
  await TestRunner.run();
}

if (require.main === module) {
  runTests().catch(console.error);
}
