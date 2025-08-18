// src/scripts/test-phase3.ts
import 'reflect-metadata';
import { EmailService, MagicLinkEmailData } from '@/services/email-service';
import { generateCorrelationId } from '@/lib/utils/correlation-id';
import { generateMagicLinkToken } from '@/lib/utils/crypto';
import { defaultLogger } from '@/lib/config/logger';

// Test configuration
const TEST_EMAIL = process.env.TEST_EMAIL;
const correlationId = generateCorrelationId();

class Phase3Tester {
  private emailService: EmailService;

  constructor() {
    this.emailService = new EmailService(correlationId);
  }

  async testEmailServiceConfiguration(): Promise<void> {
    console.log('\n🔧 Testing Email Service Configuration...');
    
    try {
      // Test if email service initializes correctly
      console.log('✅ Email service initialized successfully');
      
      // Test connection verification
      const isConnected = await this.emailService.verifyConnection();
      console.log(`🔌 Email service connection: ${isConnected ? 'CONNECTED' : 'FAILED'}`);
      
      if (!isConnected) {
        throw new Error('Email service connection failed');
      }
    } catch (error) {
      console.error('❌ Email service configuration failed:', error);
      throw error;
    }
  }

  async testMagicLinkEmailForNewUser(): Promise<void> {
    console.log('\n🆕 Testing Magic Link Email for New User...');
    
    try {
      const magicToken = generateMagicLinkToken();
      const magicLink = `${process.env.NEXT_PUBLIC_APP_URL}/auth/verify?token=${magicToken}`;
      
      const emailData: MagicLinkEmailData = {
        email: TEST_EMAIL,
        magicLink,
        firstName: 'Test',
        isNewUser: true,
        expiresInMinutes: 15,
        redirectUrl: `${process.env.NEXT_PUBLIC_APP_URL}/dashboard`,
      };

      await this.emailService.sendMagicLinkEmail(emailData);
      
      console.log('✅ New user magic link email sent successfully');
      console.log(`📧 Sent to: ${emailData.email}`);
      console.log(`🔗 Magic link: ${magicLink.substring(0, 50)}...`);
    } catch (error) {
      console.error('❌ Failed to send new user magic link email:', error);
      throw error;
    }
  }

  async testMagicLinkEmailForExistingUser(): Promise<void> {
    console.log('\n👤 Testing Magic Link Email for Existing User...');
    
    try {
      const magicToken = generateMagicLinkToken();
      const magicLink = `${process.env.NEXT_PUBLIC_APP_URL}/auth/verify?token=${magicToken}`;
      
      const emailData: MagicLinkEmailData = {
        email: TEST_EMAIL,
        magicLink,
        firstName: 'John',
        isNewUser: false,
        expiresInMinutes: 15,
      };

      await this.emailService.sendMagicLinkEmail(emailData);
      
      console.log('✅ Existing user magic link email sent successfully');
      console.log(`📧 Sent to: ${emailData.email}`);
      console.log(`🔗 Magic link: ${magicLink.substring(0, 50)}...`);
    } catch (error) {
      console.error('❌ Failed to send existing user magic link email:', error);
      throw error;
    }
  }

  async testMagicLinkEmailWithoutName(): Promise<void> {
    console.log('\n📨 Testing Magic Link Email without Name...');
    
    try {
      const magicToken = generateMagicLinkToken();
      const magicLink = `${process.env.NEXT_PUBLIC_APP_URL}/auth/verify?token=${magicToken}`;
      
      const emailData: MagicLinkEmailData = {
        email: TEST_EMAIL,
        magicLink,
        isNewUser: false,
        expiresInMinutes: 15,
      };

      await this.emailService.sendMagicLinkEmail(emailData);
      
      console.log('✅ Magic link email without name sent successfully');
      console.log(`📧 Sent to: ${emailData.email}`);
    } catch (error) {
      console.error('❌ Failed to send magic link email without name:', error);
      throw error;
    }
  }

  async testEmailServiceCleanup(): Promise<void> {
    console.log('\n🧹 Testing Email Service Cleanup...');
    
    try {
      await this.emailService.close();
      console.log('✅ Email service connections closed successfully');
    } catch (error) {
      console.error('❌ Failed to close email service connections:', error);
      throw error;
    }
  }

  async runAllTests(): Promise<void> {
    try {
      await this.testEmailServiceConfiguration();
      await this.testMagicLinkEmailForNewUser();
      
      // Wait a bit between emails to avoid rate limiting
      console.log('⏱️ Waiting 2 seconds between emails...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      await this.testMagicLinkEmailForExistingUser();
      
      // Wait again
      console.log('⏱️ Waiting 2 seconds between emails...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      await this.testMagicLinkEmailWithoutName();
      await this.testEmailServiceCleanup();
      
      console.log('\n🎉 All Phase 3 tests completed successfully!');
    } catch (error) {
      console.error('\n❌ Phase 3 test failed:', error);
      throw error;
    }
  }

  async cleanup(): Promise<void> {
    try {
      await this.emailService.close();
    } catch (error) {
      console.log('⚠️ Warning: Could not close email service:', error);
    }
  }
}

async function main() {
  console.log('🧪 Starting Phase 3: Email Service Tests');
  console.log(`📧 Test email will be sent to: ${TEST_EMAIL}`);
  console.log(`🔗 Correlation ID: ${correlationId}`);
  
  // Validate required environment variables
  const requiredEnvVars = [
    'SMTP_HOST',
    'SMTP_PORT', 
    'SMTP_USER',
    'SMTP_PASSWORD',
    'EMAIL_FROM',
    'NEXT_PUBLIC_APP_URL'
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      console.error(`❌ Missing required environment variable: ${envVar}`);
      process.exit(1);
    }
  }

  const tester = new Phase3Tester();
  
  try {
    await tester.runAllTests();
  } catch (error) {
    console.error('❌ Phase 3 test failed:', error);
    process.exit(1);
  } finally {
    await tester.cleanup();
  }
  
  console.log('\n✅ Phase 3 testing completed successfully!');
  console.log('\n📋 What to check:');
  console.log('1. Check your email inbox for the magic link emails');
  console.log('2. Verify the email content and formatting looks correct');
  console.log('3. Test that the magic links are properly formatted');
  console.log('4. Check that different email types (new vs existing user) display correctly');
}

// Run the test
if (require.main === module) {
  main().catch(console.error);
}
