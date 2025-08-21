// src/lib/api/auth.ts
import { apiClient } from './client';
import type {
  SendMagicLinkRequest,
  SendMagicLinkResponse,
  VerifyMagicLinkRequest,
  VerifyMagicLinkResponse,
  ApiResponse,
} from './types';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('auth-api');

export class AuthApi {
  /**
   * Send magic link to user's email
   */
  static async sendMagicLink(request: SendMagicLinkRequest): Promise<ApiResponse<SendMagicLinkResponse>> {
    logger.info('Sending magic link request', {
      email: request.email,
      hasRedirectUrl: !!request.redirectUrl,
    });

    try {
      const response = await apiClient.post<SendMagicLinkResponse>('/api/auth/send-link', request);

      logger.info('Magic link request successful', {
        email: request.email,
        isNewUser: response.data?.isNewUser,
        requiresProfile: response.data?.requiresProfile,
      });

      return response;
    } catch (error) {
      logger.error('Magic link request failed', error as Error, {
        email: request.email,
      });
      throw error;
    }
  }

  /**
   * Verify magic link token and create session
   */
  static async verifyMagicLink(request: VerifyMagicLinkRequest): Promise<ApiResponse<VerifyMagicLinkResponse>> {
    logger.info('Verifying magic link', {
      hasToken: !!request.token,
      tokenLength: request.token?.length,
      hasProfile: !!request.profile,
    });

    try {
      const response = await apiClient.post<VerifyMagicLinkResponse>('/api/auth/verify', request);

      logger.info('Magic link verification successful', {
        userId: response.data?.user?.id,
        email: response.data?.user?.email,
        isNewUser: response.data?.isNewUser,
        hasRedirectUrl: !!response.data?.redirectUrl,
      });

      return response;
    } catch (error) {
      logger.error('Magic link verification failed', error as Error, {
        tokenLength: request.token?.length,
        hasProfile: !!request.profile,
      });
      throw error;
    }
  }

  /**
   * Sign out current user
   */
  static async signOut(): Promise<ApiResponse<{ message: string }>> {
    logger.info('Signing out user');

    try {
      const response = await apiClient.post<{ message: string }>('/api/auth/signout', {});

      logger.info('Sign out successful');

      return response;
    } catch (error) {
      logger.error('Sign out failed', error as Error);
      throw error;
    }
  }

  /**
   * Delete user account
   */
  static async deleteAccount(): Promise<ApiResponse<{ message: string }>> {
    logger.info('Deleting user account');

    try {
      const response = await apiClient.post<{ message: string }>('/api/auth/delete-account', {});

      logger.info('Account deletion successful');

      return response;
    } catch (error) {
      logger.error('Account deletion failed', error as Error);
      throw error;
    }
  }
}
