// tests/user-repository.test.ts
import { DataSource } from 'typeorm';
import { User } from '../src/entities/user';
import { UserRepository } from '../src/repositories/user-repository';
import { 
  TestRunner, 
  setupTestDatabase, 
  cleanupTestDatabase, 
  clearAllTables,
  createTestUser,
  createDeletedTestUser,
  TEST_USERS 
} from './setup';

describe('UserRepository', () => {
  let dataSource: DataSource;
  let userRepository: UserRepository;
  let rawUserRepository: any; // For direct entity operations

  beforeAll(async () => {
    dataSource = await setupTestDatabase();
    userRepository = new UserRepository(dataSource, 'test-correlation-id');
    rawUserRepository = dataSource.getRepository(User);
  });

  afterAll(async () => {
    await cleanupTestDatabase(dataSource);
  });

  beforeEach(async () => {
    await clearAllTables(dataSource);
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      const userData = createTestUser(TEST_USERS.verified);
      await userRepository.create(userData);

      const foundUser = await userRepository.findByEmail(userData.email!);
      
      expect(foundUser).toBeDefined();
      expect(foundUser!.email).toBe(userData.email);
    });

    it('should return null for non-existent email', async () => {
      const foundUser = await userRepository.findByEmail('nonexistent@test.com');
      expect(foundUser).toBeNull();
    });

    it('should not find deleted users', async () => {
      // Fixed: Create a properly deleted user
      await createDeletedTestUser(rawUserRepository, 'deleted@example.com');

      const foundUser = await userRepository.findByEmail('deleted@example.com');
      expect(foundUser).toBeNull();
    });
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const userData = createTestUser(TEST_USERS.unverified);
      const createdUser = await userRepository.create(userData);

      expect(createdUser.id).toBeDefined();
      expect(createdUser.email).toBe(userData.email);
      expect(createdUser.isVerified).toBe(userData.isVerified);
    });

    it('should throw error for duplicate email', async () => {
      const userData = createTestUser({ email: 'duplicate@test.com' });
      await userRepository.create(userData);

      let errorThrown = false;
      try {
        await userRepository.create(userData);
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('markAsVerified', () => {
    it('should mark user as verified', async () => {
      const userData = createTestUser(TEST_USERS.unverified);
      const createdUser = await userRepository.create(userData);

      const verifiedUser = await userRepository.markAsVerified(createdUser.id);

      expect(verifiedUser.isVerified).toBe(true);
      expect(verifiedUser.verifiedAt).toBeDefined();
    });

    it('should throw error for non-existent user', async () => {
      let errorThrown = false;
      try {
        await userRepository.markAsVerified('non-existent-id');
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('emailExists', () => {
    it('should return true for existing email', async () => {
      const userData = createTestUser(TEST_USERS.verified);
      await userRepository.create(userData);

      const exists = await userRepository.emailExists(userData.email!);
      expect(exists).toBe(true);
    });

    it('should return false for non-existent email', async () => {
      const exists = await userRepository.emailExists('nonexistent@test.com');
      expect(exists).toBe(false);
    });

    it('should return false for deleted user email', async () => {
      // Fixed: Create a properly deleted user
      await createDeletedTestUser(rawUserRepository, 'deleted@example.com');

      const exists = await userRepository.emailExists('deleted@example.com');
      expect(exists).toBe(false);
    });
  });

  describe('softDelete', () => {
    it('should soft delete a user', async () => {
      const userData = createTestUser(TEST_USERS.verified);
      const createdUser = await userRepository.create(userData);

      await userRepository.softDelete(createdUser.id);

      const foundUser = await userRepository.findByEmail(userData.email!);
      expect(foundUser).toBeNull();
    });
  });

  describe('findByVerificationStatus', () => {
    it('should find verified users', async () => {
      const userData1 = createTestUser({ email: 'verified1@test.com', isVerified: true });
      const userData2 = createTestUser({ email: 'unverified1@test.com', isVerified: false });
      
      await userRepository.create(userData1);
      await userRepository.create(userData2);

      const verifiedUsers = await userRepository.findByVerificationStatus(true, 10);
      expect(verifiedUsers).toHaveLength(1);
      expect(verifiedUsers[0].email).toBe('verified1@test.com');
    });

    it('should find unverified users', async () => {
      const userData1 = createTestUser({ email: 'verified2@test.com', isVerified: true });
      const userData2 = createTestUser({ email: 'unverified2@test.com', isVerified: false });
      
      await userRepository.create(userData1);
      await userRepository.create(userData2);

      const unverifiedUsers = await userRepository.findByVerificationStatus(false, 10);
      expect(unverifiedUsers).toHaveLength(1);
      expect(unverifiedUsers[0].email).toBe('unverified2@test.com');
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
