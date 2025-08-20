// tests/session-repository.test.ts
import { DataSource } from 'typeorm';
import { User } from '../src/entities/user';
import { Session } from '../src/entities/session';
import { UserRepository } from '../src/repositories/user-repository';
import { SessionRepository } from '../src/repositories/session-repository';
import { 
  TestRunner, 
  setupTestDatabase, 
  cleanupTestDatabase, 
  clearAllTables,
  createTestUser,
  TEST_USERS 
} from './setup';
import { generateSessionToken, hashToken } from '../src/lib/utils/crypto';
import { createExpirationDate, addSeconds } from '../src/lib/utils/time';

async function createTestSession(userId: string, data: Partial<Session> = {}): Promise<Partial<Session>> {
  const sessionToken = generateSessionToken();
  const tokenHash = await hashToken(sessionToken);
  
  return {
    userId,
    tokenHash,
    expiresAt: createExpirationDate(3600), // 1 hour
    isActive: true,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    ...data,
  };
}

describe('SessionRepository', () => {
  let dataSource: DataSource;
  let userRepository: UserRepository;
  let sessionRepository: SessionRepository;
  let testUser: User;

  beforeAll(async () => {
    dataSource = await setupTestDatabase();
    userRepository = new UserRepository(dataSource, 'test-correlation-id');
    sessionRepository = new SessionRepository(dataSource, 'test-correlation-id');
  });

  afterAll(async () => {
    await cleanupTestDatabase(dataSource);
  });

  beforeEach(async () => {
    await clearAllTables(dataSource);

    // Create test user
    const userData = createTestUser(TEST_USERS.verified);
    testUser = await userRepository.create(userData);
  });

  describe('create', () => {
    it('should create a new session', async () => {
      const sessionData = await createTestSession(testUser.id);
      const createdSession = await sessionRepository.create(sessionData);

      expect(createdSession.id).toBeDefined();
      expect(createdSession.userId).toBe(testUser.id);
      expect(createdSession.isActive).toBe(true);
      expect(createdSession.lastAccessedAt).toBeDefined();
    });

    it('should throw error for duplicate token hash', async () => {
      const sessionData = await createTestSession(testUser.id);
      await sessionRepository.create(sessionData);

      let errorThrown = false;
      try {
        // Try to create another session with same token hash
        await sessionRepository.create(sessionData);
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('findByTokenHash', () => {
    it('should find session by token hash', async () => {
      const sessionData = await createTestSession(testUser.id);
      const createdSession = await sessionRepository.create(sessionData);

      const foundSession = await sessionRepository.findByTokenHash(sessionData.tokenHash!);
      
      expect(foundSession).toBeDefined();
      expect(foundSession!.id).toBe(createdSession.id);
    });

    it('should return null for non-existent token hash', async () => {
      const foundSession = await sessionRepository.findByTokenHash('non-existent-hash');
      expect(foundSession).toBeNull();
    });
  });

  describe('updateLastAccessed', () => {
    it('should update last accessed time', async () => {
      const sessionData = await createTestSession(testUser.id);
      const createdSession = await sessionRepository.create(sessionData);

      // Wait a bit to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      const updatedSession = await sessionRepository.updateLastAccessed(createdSession.id);
      
      expect(updatedSession.lastAccessedAt!.getTime()).toBeGreaterThan(
        createdSession.lastAccessedAt!.getTime()
      );
    });

    it('should throw error for non-existent session', async () => {
      let errorThrown = false;
      try {
        await sessionRepository.updateLastAccessed('non-existent-id');
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('revoke', () => {
    it('should revoke a session', async () => {
      const sessionData = await createTestSession(testUser.id);
      const createdSession = await sessionRepository.create(sessionData);

      await sessionRepository.revoke(createdSession.id);

      const foundSession = await sessionRepository.findById(createdSession.id);
      expect(foundSession!.isActive).toBe(false);
    });

    it('should throw error for non-existent session', async () => {
      let errorThrown = false;
      try {
        await sessionRepository.revoke('non-existent-id');
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('findActiveForUser', () => {
    it('should find all active sessions for user', async () => {
      const sessionData1 = await createTestSession(testUser.id);
      const sessionData2 = await createTestSession(testUser.id);
      
      await sessionRepository.create(sessionData1);
      const session2 = await sessionRepository.create(sessionData2);

      // Revoke one session
      await sessionRepository.revoke(session2.id);

      const activeSessions = await sessionRepository.findActiveForUser(testUser.id);
      expect(activeSessions).toHaveLength(1);
    });

    it('should return empty array for user with no sessions', async () => {
      const activeSessions = await sessionRepository.findActiveForUser('non-existent-user');
      expect(activeSessions).toHaveLength(0);
    });
  });

  describe('extend', () => {
    it('should extend session expiry', async () => {
      const sessionData = await createTestSession(testUser.id);
      const createdSession = await sessionRepository.create(sessionData);
      
      const newExpiryDate = createExpirationDate(7200); // 2 hours
      const extendedSession = await sessionRepository.extend(createdSession.id, newExpiryDate);
      
      expect(extendedSession.expiresAt.getTime()).toBe(newExpiryDate.getTime());
      expect(extendedSession.lastAccessedAt).toBeDefined();
    });

    it('should throw error for non-existent session', async () => {
      const newExpiryDate = createExpirationDate(7200);
      
      let errorThrown = false;
      try {
        await sessionRepository.extend('non-existent-id', newExpiryDate);
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).toBeTruthy();
    });
  });

  describe('revokeAllForUser', () => {
    it('should revoke all sessions for user', async () => {
      const sessionData1 = await createTestSession(testUser.id);
      const sessionData2 = await createTestSession(testUser.id);
      
      await sessionRepository.create(sessionData1);
      await sessionRepository.create(sessionData2);

      const revokedCount = await sessionRepository.revokeAllForUser(testUser.id);
      expect(revokedCount).toBe(2);

      const activeSessions = await sessionRepository.findActiveForUser(testUser.id);
      expect(activeSessions).toHaveLength(0);
    });

    it('should return 0 for user with no sessions', async () => {
      const revokedCount = await sessionRepository.revokeAllForUser('non-existent-user');
      expect(revokedCount).toBe(0);
    });
  });

  describe('cleanupExpired', () => {
    it('should clean up expired sessions', async () => {
      // Create expired session
      const expiredSessionData = await createTestSession(testUser.id, {
        expiresAt: addSeconds(new Date(), -3600), // 1 hour ago
      });
      await sessionRepository.create(expiredSessionData);

      // Create valid session
      const validSessionData = await createTestSession(testUser.id);
      await sessionRepository.create(validSessionData);

      const deletedCount = await sessionRepository.cleanupExpired();
      expect(deletedCount).toBe(1);

      const activeSessions = await sessionRepository.findActiveForUser(testUser.id);
      expect(activeSessions).toHaveLength(1);
    });

    it('should return 0 when no expired sessions exist', async () => {
      // Create only valid sessions
      const validSessionData = await createTestSession(testUser.id);
      await sessionRepository.create(validSessionData);

      const deletedCount = await sessionRepository.cleanupExpired();
      expect(deletedCount).toBe(0);
    });
  });

  describe('countActiveForUser', () => {
    it('should count active sessions for user', async () => {
      const sessionData1 = await createTestSession(testUser.id);
      const sessionData2 = await createTestSession(testUser.id);
      
      await sessionRepository.create(sessionData1);
      const session2 = await sessionRepository.create(sessionData2);

      // Should count 2 active sessions
      let count = await sessionRepository.countActiveForUser(testUser.id);
      expect(count).toBe(2);

      // Revoke one session
      await sessionRepository.revoke(session2.id);

      // Should count 1 active session
      count = await sessionRepository.countActiveForUser(testUser.id);
      expect(count).toBe(1);
    });

    it('should return 0 for user with no sessions', async () => {
      const count = await sessionRepository.countActiveForUser('non-existent-user');
      expect(count).toBe(0);
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
