// src/lib/api/session.ts
import { apiClient } from './client';
import type {
  SessionValidationResponse,
  ApiResponse,
} from './types';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('session-api');

export class SessionApi {
  /**
   * Validate current session
   */
  static async validateSession(): Promise<ApiResponse<SessionValidationResponse>> {
    logger.debug('Validating current session');

    try {
      const response = await apiClient.get<SessionValidationResponse>('/api/auth/session');

      logger.debug('Session validation successful', {
        userId: response.data?.user?.id,
        sessionId: response.data?.session?.id,
        isActive: response.data?.session?.isActive,
      });

      return response;
    } catch (error) {
      logger.debug('Session validation failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Health check that checks if API is responding without generating error logs
   * Uses a simple HEAD request or lightweight endpoint instead of session validation
   */
  static async healthCheck(): Promise<boolean> {
    try {
      // Use a simple fetch to check if the API is responding
      // This avoids going through the full session validation logic
      const response = await fetch('/api/health', {
        method: 'HEAD',
        credentials: 'same-origin',
      });
      
      // If /api/health doesn't exist, that's okay - API is still responding
      const isHealthy = response.status < 500;
      
      logger.debug('API health check completed', {
        status: response.status,
        isHealthy,
      });
      
      return isHealthy;
    } catch (error: any) {
      // Network errors indicate unhealthy API
      logger.warn('API health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      
      return false;
    }
  }

  /**
   * Alternative health check using session endpoint (for specific use cases)
   * This method accepts that 401 responses are healthy for unauthenticated users
   */
  static async healthCheckWithSession(): Promise<boolean> {
    try {
      const response = await apiClient.get('/api/auth/session');
      
      // Any response means API is working
      logger.debug('API health check via session - got response', {
        success: response.success,
      });
      
      return true;
    } catch (error: any) {
      // 401 (unauthorized) is actually healthy - it means API is working
      if (error?.code === 'UNAUTHORIZED' || error?.message?.includes('401')) {
        logger.debug('API health check via session - 401 response (healthy)');
        return true;
      }
      
      // Network errors or server errors are unhealthy
      logger.warn('API health check via session failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      
      return false;
    }
  }
}
