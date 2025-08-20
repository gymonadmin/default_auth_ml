// tests/user-entity.test.ts
import { DataSource } from 'typeorm';
import { User } from '../src/entities/user';
import { 
  TestRunner, 
  setupTestDatabase, 
  cleanupTestDatabase, 
  clearAllTables,
  createTestUser,
  TEST_USERS 
} from './setup';

describe('User Entity', () => {
  let dataSource: DataSource;
  let userRepository: any;

  beforeAll(async () => {
    dataSource = await setupTestDatabase();
    userRepository = dataSource.getRepository(User);
  });

  afterAll(async () => {
    await cleanupTestDatabase(dataSource);
  });

  beforeEach(async () => {
    await clearAllTables(dataSource);
  });

  describe('Basic Operations', () => {
    it('should create a user', async () => {
      const userData = createTestUser(TEST_USERS.unverified);
      const user = userRepository.create(userData);
      const savedUser = await userRepository.save(user);

      expect(savedUser.id).toBeDefined();
      expect(savedUser.email).toBe(userData.email);
      expect(savedUser.isVerified).toBe(false);
      expect(savedUser.createdAt).toBeDefined();
      expect(savedUser.updatedAt).toBeDefined();
    });

    it('should find user by email', async () => {
      const userData = createTestUser(TEST_USERS.verified);
      const user = userRepository.create(userData);
      await userRepository.save(user);

      const foundUser = await userRepository.findOne({
        where: { email: userData.email }
      });

      expect(foundUser).toBeDefined();
      expect(foundUser.email).toBe(userData.email);
    });

    it('should enforce unique email constraint', async () => {
      const userData = createTestUser({ email: 'unique@test.com' });
      
      // Create first user
      const user1 = userRepository.create(userData);
      await userRepository.save(user1);

      // Try to create second user with same email
      const user2 = userRepository.create(userData);
      
      let errorThrown = false;
      try {
        await userRepository.save(user2);
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('Computed Properties', () => {
    it('should correctly identify deleted users', async () => {
      const userData = createTestUser(TEST_USERS.deleted);
      const user = userRepository.create(userData);
      
      expect(user.isDeleted).toBe(true);
    });

    it('should correctly identify active users', async () => {
      const userData = createTestUser(TEST_USERS.verified);
      const user = userRepository.create(userData);
      
      expect(user.isActive).toBe(true);
    });

    it('should correctly identify inactive users', async () => {
      const userData = createTestUser(TEST_USERS.unverified);
      const user = userRepository.create(userData);
      
      expect(user.isActive).toBe(false);
    });
  });

  describe('Methods', () => {
    it('should mark user as verified', async () => {
      const userData = createTestUser(TEST_USERS.unverified);
      const user = userRepository.create(userData);
      
      user.markAsVerified();
      
      expect(user.isVerified).toBe(true);
      expect(user.verifiedAt).toBeDefined();
    });

    it('should mark user as deleted', async () => {
      const userData = createTestUser(TEST_USERS.verified);
      const user = userRepository.create(userData);
      
      user.markAsDeleted();
      
      expect(user.deletedAt).toBeDefined();
      expect(user.isDeleted).toBe(true);
    });

    it('should restore deleted user', async () => {
      const userData = createTestUser(TEST_USERS.deleted);
      const user = userRepository.create(userData);
      
      user.restore();
      
      expect(user.deletedAt).toBeNull();
      expect(user.isDeleted).toBe(false);
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
