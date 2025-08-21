// tests/delete-account.test.ts
import 'reflect-metadata';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

import { AuthService } from '../src/services/auth-service';
import { UserRepository } from '../src/repositories/user-repository';
import { SessionRepository } from '../src/repositories/session-repository';
import { AuditLogRepository } from '../src/repositories/audit-log-repository';
import { AuditEvent } from '../src/entities/audit-log';
import { initializeDatabase, closeDatabase } from '../src/lib/config/database';
import { generateSessionToken, hashToken } from '../src/lib/utils/crypto';
import { createExpirationDate } from '../src/lib/utils/time';

// tests/delete-account.test.ts
import 'reflect-metadata';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

console.log('🚀 Script started - loading modules...');

try {
  console.log('📦 Importing modules...');
  
  const { AuthService } = require('../src/services/auth-service');
  const { UserRepository } = require('../src/repositories/user-repository');
  const { ProfileRepository } = require('../src/repositories/profile-repository');
  const { SessionRepository } = require('../src/repositories/session-repository');
  const { AuditLogRepository } = require('../src/repositories/audit-log-repository');
  const { AuditEvent } = require('../src/entities/audit-log');
  const { initializeDatabase, closeDatabase } = require('../src/lib/config/database');
  const { generateSessionToken, hashToken } = require('../src/lib/utils/crypto');
  const { createExpirationDate } = require('../src/lib/utils/time');

  console.log('✅ All modules imported successfully');

  async function testDeleteAccount() {
    console.log('🧪 Starting Enhanced Delete Account Integration Test');
    
    try {
      // Initialize database
      console.log('📊 Initializing database connection...');
      const dataSource = await initializeDatabase();
      
      const correlationId = 'test-delete-account-' + Date.now();
      
      // Create repositories
      const userRepo = new UserRepository(dataSource, correlationId);
      const profileRepo = new ProfileRepository(dataSource, correlationId);
      const sessionRepo = new SessionRepository(dataSource, correlationId);
      const auditRepo = new AuditLogRepository(dataSource, correlationId);
      
      // Create auth service
      const authService = AuthService.create(correlationId);
      
      console.log('✅ Database initialized, starting test...\n');

      // Step 1: Create a test user
      console.log('👤 Step 1: Creating test user...');
      const testEmail = `test-delete-${Date.now()}@example.com`;
      
      const user = await userRepo.create({
        email: testEmail,
        isVerified: true,
      });
      
      console.log(`✅ User created: ${user.id} (${user.email})`);

      // Step 2: Create a test profile
      console.log('👨‍💼 Step 2: Creating test profile...');
      
      const profile = await profileRepo.create({
        userId: user.id,
        firstName: 'Test',
        lastName: 'User',
      });
      
      console.log(`✅ Profile created: ${profile.id} (${profile.fullName})`);

      // Step 3: Create a test session
      console.log('🔐 Step 3: Creating test session...');
      const sessionToken = generateSessionToken();
      const sessionTokenHash = await hashToken(sessionToken);
      const sessionExpiresAt = createExpirationDate(3600); // 1 hour
      
      const session = await sessionRepo.create({
        userId: user.id,
        tokenHash: sessionTokenHash,
        expiresAt: sessionExpiresAt,
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
      });
      
      console.log(`✅ Session created: ${session.id}`);

      // Step 4: Verify initial state
      console.log('🔍 Step 4: Verifying initial state...');
      
      const foundUser = await userRepo.findById(user.id);
      const foundProfile = await profileRepo.findByUserId(user.id);
      const activeSessions = await sessionRepo.findActiveForUser(user.id);
      
      console.log(`✅ User found: ${!!foundUser} (isActive: ${foundUser?.isActive})`);
      console.log(`✅ Profile found: ${!!foundProfile} (isActive: ${foundProfile?.isActive})`);
      console.log(`✅ Active sessions: ${activeSessions.length}`);

      // Step 5: Delete the account
      console.log('🗑️  Step 5: Deleting account...');
      
      const deleteResult = await authService.deleteAccount(user.id, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        country: 'US',
        city: 'Test City',
      });
      
      console.log(`✅ Delete result: ${deleteResult.success} - ${deleteResult.message}`);

      // Step 6: Verify account deletion
      console.log('🔍 Step 6: Verifying account deletion...');
      
      const deletedUser = await userRepo.findById(user.id);
      const deletedProfile = await profileRepo.findByUserId(user.id);
      const activeSessionsAfter = await sessionRepo.findActiveForUser(user.id);
      
      console.log(`✅ User after deletion: ${!!deletedUser} (isActive: ${deletedUser?.isActive})`);
      console.log(`✅ Profile after deletion: ${!!deletedProfile} (isActive: ${deletedProfile?.isActive})`);
      console.log(`✅ Active sessions after deletion: ${activeSessionsAfter.length}`);

      // Step 7: Check actual database state (including deleted records)
      console.log('🔍 Step 7: Checking raw database state...');
      
      // Check user in database (including deleted)
      const userInDb = await dataSource.getRepository('User').findOne({
        where: { id: user.id }
      });
      
      // Check profile in database (including deleted)
      const profileInDb = await dataSource.getRepository('Profile').findOne({
        where: { userId: user.id }
      });
      
      console.log(`✅ User in DB: ${!!userInDb} (deletedAt: ${userInDb?.deletedAt ? 'SET' : 'NULL'})`);
      console.log(`✅ Profile in DB: ${!!profileInDb} (deletedAt: ${profileInDb?.deletedAt ? 'SET' : 'NULL'})`);

      // Step 8: Verify audit log
      console.log('📋 Step 8: Checking audit logs...');
      
      const auditLogs = await auditRepo.findRecentForUser(user.id, 5);
      const deleteAuditLog = auditLogs.find(log => log.event === AuditEvent.ACCOUNT_DELETED);
      
      console.log(`✅ Total audit logs: ${auditLogs.length}`);
      console.log(`✅ Account deleted audit log: ${!!deleteAuditLog}`);
      if (deleteAuditLog) {
        console.log(`   - Event: ${deleteAuditLog.event}`);
        console.log(`   - Success: ${deleteAuditLog.success}`);
        console.log(`   - Context: ${JSON.stringify(deleteAuditLog.context)}`);
      }

      // Step 9: Test session validation after deletion
      console.log('🔒 Step 9: Testing session validation after deletion...');
      
      const sessionValidation = await authService.validateSession(sessionToken);
      
      console.log(`✅ Session validation result: ${!!sessionValidation}`);

      // Step 10: Test profile access through auth service
      console.log('👨‍💼 Step 10: Testing profile access after deletion...');
      
      const profileAccess = await authService.getUserProfile(user.id);
      
      console.log(`✅ Profile access via auth service: ${!!profileAccess}`);

      // Step 11: Verify data consistency
      console.log('🔄 Step 11: Verifying data consistency...');
      
      const profileExists = await profileRepo.existsForUser(user.id);
      const userIsActive = userInDb && !userInDb.deletedAt;
      const profileIsActive = profileInDb && !profileInDb.deletedAt;
      
      console.log(`✅ Profile exists (repo method): ${profileExists}`);
      console.log(`✅ User is active: ${userIsActive}`);
      console.log(`✅ Profile is active: ${profileIsActive}`);

      console.log('\n🎉 Enhanced Test Summary:');
      console.log(`   ✅ User soft deleted: ${!!userInDb?.deletedAt}`);
      console.log(`   ✅ Profile soft deleted: ${!!profileInDb?.deletedAt}`);
      console.log(`   ✅ User marked inactive: ${!userIsActive}`);
      console.log(`   ✅ Profile marked inactive: ${!profileIsActive}`);
      console.log(`   ✅ Sessions revoked: ${activeSessionsAfter.length === 0}`);
      console.log(`   ✅ Audit log created: ${!!deleteAuditLog}`);
      console.log(`   ✅ Session invalidated: ${!sessionValidation}`);
      console.log(`   ✅ Profile access blocked: ${!profileAccess}`);
      console.log(`   ✅ Data consistency: ${!profileExists && !userIsActive && !profileIsActive}`);
      
      // Final validation
      const allTestsPassed = (
        !!userInDb?.deletedAt &&
        !!profileInDb?.deletedAt &&
        !userIsActive &&
        !profileIsActive &&
        activeSessionsAfter.length === 0 &&
        !!deleteAuditLog &&
        !sessionValidation &&
        !profileAccess &&
        !profileExists
      );
      
      if (allTestsPassed) {
        console.log('\n🎊 ALL TESTS PASSED! Enhanced delete account functionality working perfectly.');
        console.log('   • User and Profile both soft deleted with proper timestamps');
        console.log('   • Repository methods correctly exclude deleted records');
        console.log('   • Sessions properly revoked and invalidated');
        console.log('   • Audit trail complete and accurate');
        console.log('   • Data privacy and consistency maintained');
      } else {
        console.log('\n⚠️  Some tests failed - review the results above');
      }

    } catch (error) {
      console.error('❌ Test failed:', error);
      console.error('Error details:', {
        message: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    } finally {
      // Cleanup
      console.log('\n🧹 Cleaning up...');
      try {
        await closeDatabase();
        console.log('✅ Database connection closed');
      } catch (cleanupError) {
        console.error('❌ Cleanup error:', cleanupError);
      }
    }
  }

  // Run the test
  console.log('🏃 About to run enhanced test function...');
  testDeleteAccount()
    .then(() => {
      console.log('\n🏁 Enhanced test completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Test runner error:', error);
      process.exit(1);
    });

} catch (importError) {
  console.error('❌ Failed to import modules:', importError);
  console.error('Import error details:', {
    message: importError instanceof Error ? importError.message : 'Unknown error',
    stack: importError instanceof Error ? importError.stack : undefined,
  });
  process.exit(1);
}
