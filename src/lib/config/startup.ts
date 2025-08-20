// src/lib/config/startup.ts
import { EmailService } from '@/services/email-service';
import { Logger } from '@/lib/config/logger';

interface StartupCheckResult {
  service: string;
  success: boolean;
  error?: string;
}

/**
 * Run essential startup checks
 */
export async function runStartupChecks(): Promise<StartupCheckResult[]> {
  const logger = new Logger('startup');
  const results: StartupCheckResult[] = [];

  logger.info('Running startup checks...');

  // Test email service connectivity
  try {
    logger.debug('Testing email service connectivity...');
    const emailService = EmailService.create('startup');
    await emailService.verifyConnection();
    
    results.push({
      service: 'email',
      success: true,
    });
    
    logger.info('✅ Email service connectivity verified');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    results.push({
      service: 'email',
      success: false,
      error: errorMessage,
    });
    
    logger.error('❌ Email service connectivity failed', {
      error: errorMessage,
    });
  }

  const allPassed = results.every(result => result.success);
  
  if (allPassed) {
    logger.info('✅ All startup checks passed');
  } else {
    logger.warn('⚠️ Some startup checks failed', {
      failedChecks: results.filter(r => !r.success).map(r => r.service),
    });
  }

  return results;
}

/**
 * Run startup checks and optionally exit on failure
 */
export async function validateStartup(exitOnFailure: boolean = false): Promise<boolean> {
  const results = await runStartupChecks();
  const allPassed = results.every(result => result.success);
  
  if (!allPassed && exitOnFailure) {
    console.error('Critical startup checks failed. Exiting...');
    process.exit(1);
  }
  
  return allPassed;
}
