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
   * Health check that treats 401 as healthy (unauthenticated is normal)
   */
  static async healthCheck(): Promise<boolean> {
    try {
      const response = await apiClient.get('/api/auth/session');
      
      // Any response means API is working
      logger.debug('API health check - got response', {
        success: response.success,
      });
      
      return true;
    } catch (error: any) {
      // 401 (unauthorized) is actually healthy - it means API is working
      if (error?.code === 'UNAUTHORIZED' || error?.message?.includes('401')) {
        logger.debug('API health check - 401 response (healthy)');
        return true;
      }
      
      // Network errors or server errors are unhealthy
      logger.warn('API health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      
      return false;
    }
  }
}
