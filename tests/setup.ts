// tests/setup.ts
import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { User } from '../src/entities/user';
import { Profile } from '../src/entities/profile';
import { Session } from '../src/entities/session';
import { MagicSigninToken } from '../src/entities/magic-signin-token';
import { AuditLog } from '../src/entities/audit-log';

export class TestRunner {
  private static tests: Array<{ name: string; fn: () => Promise<void> }> = [];
  private static beforeEachFn: (() => Promise<void>) | null = null;
  private static beforeAllFn: (() => Promise<void>) | null = null;
  private static afterAllFn: (() => Promise<void>) | null = null;

  static describe(name: string, fn: () => void) {
    console.log(`\n📋 ${name}`);
    fn();
  }

  static it(name: string, fn: () => Promise<void>) {
    this.tests.push({ name, fn });
  }

  static beforeEach(fn: () => Promise<void>) {
    this.beforeEachFn = fn;
  }

  static beforeAll(fn: () => Promise<void>) {
    this.beforeAllFn = fn;
  }

  static afterAll(fn: () => Promise<void>) {
    this.afterAllFn = fn;
  }

  static async run() {
    let passed = 0;
    let failed = 0;

    if (this.beforeAllFn) {
      try {
        await this.beforeAllFn();
      } catch (error) {
        console.error('❌ beforeAll failed:', error);
        return;
      }
    }

    for (const test of this.tests) {
      try {
        if (this.beforeEachFn) {
          await this.beforeEachFn();
        }

        await test.fn();
        console.log(`  ✅ ${test.name}`);
        passed++;
      } catch (error) {
        console.log(`  ❌ ${test.name}`);
        console.error(`     Error: ${error instanceof Error ? error.message : error}`);
        if (error instanceof Error && error.stack) {
          console.error(`     Stack: ${error.stack.split('\n').slice(1, 3).join('\n')}`);
        }
        failed++;
      }
    }

    if (this.afterAllFn) {
      try {
        await this.afterAllFn();
      } catch (error) {
        console.error('❌ afterAll failed:', error);
      }
    }

    console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
    
    if (failed > 0) {
      process.exit(1);
    }
  }

  static expect(actual: any) {
    return {
      toBe: (expected: any) => {
        if (actual !== expected) {
          throw new Error(`Expected ${JSON.stringify(expected)}, but got ${JSON.stringify(actual)}`);
        }
      },
      toEqual: (expected: any) => {
        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
          throw new Error(`Expected ${JSON.stringify(expected)}, but got ${JSON.stringify(actual)}`);
        }
      },
      toBeDefined: () => {
        if (actual === undefined) {
          throw new Error('Expected value to be defined');
        }
      },
      toBeNull: () => {
        if (actual !== null) {
          throw new Error(`Expected null, but got ${JSON.stringify(actual)}`);
        }
      },
      toBeTruthy: () => {
        if (!actual) {
          throw new Error(`Expected truthy value, but got ${JSON.stringify(actual)}`);
        }
      },
      toBeFalsy: () => {
        if (actual) {
          throw new Error(`Expected falsy value, but got ${JSON.stringify(actual)}`);
        }
      },
      toHaveLength: (length: number) => {
        if (!actual || actual.length !== length) {
          throw new Error(`Expected length ${length}, but got ${actual?.length || 'undefined'}`);
        }
      },
      toThrow: async () => {
        let thrown = false;
        try {
          if (typeof actual === 'function') {
            await actual();
          }
        } catch {
          thrown = true;
        }
        if (!thrown) {
          throw new Error('Expected function to throw');
        }
      },
      toBeGreaterThan: (expected: number) => {
        if (actual <= expected) {
          throw new Error(`Expected ${actual} to be greater than ${expected}`);
        }
      }
    };
  }
}

// Global test functions
declare global {
  var describe: typeof TestRunner.describe;
  var it: typeof TestRunner.it;
  var beforeEach: typeof TestRunner.beforeEach;
  var beforeAll: typeof TestRunner.beforeAll;
  var afterAll: typeof TestRunner.afterAll;
  var expect: typeof TestRunner.expect;
}

(globalThis as any).describe = TestRunner.describe.bind(TestRunner);
(globalThis as any).it = TestRunner.it.bind(TestRunner);
(globalThis as any).beforeEach = TestRunner.beforeEach.bind(TestRunner);
(globalThis as any).beforeAll = TestRunner.beforeAll.bind(TestRunner);
(globalThis as any).afterAll = TestRunner.afterAll.bind(TestRunner);
(globalThis as any).expect = TestRunner.expect.bind(TestRunner);

export const createTestDataSource = (): DataSource => {
  return new DataSource({
    type: 'postgres',
    host: '172.16.0.2',
    port: 5432,
    username: 'defaultauthmladmin',
    password: 'FreeBSD10!',
    database: 'defaultauthmldb',
    entities: [User, Profile, Session, MagicSigninToken, AuditLog],
    synchronize: false,
    logging: false,
    extra: {
      max: 5,
      min: 1,
    },
  });
};

export const setupTestDatabase = async (): Promise<DataSource> => {
  const dataSource = createTestDataSource();
  await dataSource.initialize();
  return dataSource;
};

export const cleanupTestDatabase = async (dataSource: DataSource): Promise<void> => {
  if (dataSource?.isInitialized) {
    await dataSource.destroy();
  }
};

export const clearAllTables = async (dataSource: DataSource): Promise<void> => {
  // Delete in order to respect foreign key constraints
  await dataSource.query('DELETE FROM audit_logs');
  await dataSource.query('DELETE FROM sessions');
  await dataSource.query('DELETE FROM magic_signin_tokens');
  await dataSource.query('DELETE FROM profiles');
  await dataSource.query('DELETE FROM users');
};

// Test data helpers
export const TEST_USERS = {
  unverified: {
    email: 'colinbsd@yahoo.com',
    isVerified: false,
  },
  verified: {
    email: 'calinilie75@gmail.com', 
    isVerified: true,
  },
  deleted: {
    email: 'deleted@example.com',
    isVerified: true,
    // Note: deletedAt will be set by the entity method, not here
  },
};

export const TEST_PROFILES = {
  john: {
    firstName: 'John',
    lastName: 'Doe',
  },
  jane: {
    firstName: 'Jane',
    lastName: 'Smith',
  },
};

export const createTestUser = (data: Partial<any> = {}): Partial<any> => ({
  email: 'test@example.com',
  isVerified: false,
  ...data,
});

export const createTestProfile = (userId: string, data: Partial<any> = {}): Partial<any> => ({
  userId,
  firstName: 'Test',
  lastName: 'User',
  ...data,
});

// Helper to create a deleted user properly
export const createDeletedTestUser = async (repository: any, email: string): Promise<any> => {
  // First create the user
  const userData = {
    email,
    isVerified: true,
  };
  const user = repository.create(userData);
  const savedUser = await repository.save(user);
  
  // Then mark it as deleted
  savedUser.markAsDeleted();
  return await repository.save(savedUser);
};
