// src/hooks/use-auth.ts
'use client';

import { useState, useCallback } from 'react';
import { useSession } from './use-session';
import { AuthApi } from '@/lib/api/auth';
import { clientLogger } from '@/lib/config/client-logger';
import type {
  SendMagicLinkRequest,
  VerifyMagicLinkRequest,
} from '@/lib/api/types';

const logger = clientLogger.withCorrelationId('use-auth');

export interface AuthResponse {
  success: boolean;
  message: string;
  data?: any;
}

export interface UseAuthReturn {
  isLoading: boolean;
  error: string | null;
  sendMagicLink: (request: SendMagicLinkRequest) => Promise<AuthResponse>;
  verifyMagicLink: (request: VerifyMagicLinkRequest) => Promise<AuthResponse>;
  signOut: () => Promise<void>;
  deleteAccount: () => Promise<AuthResponse>;
  clearError: () => void;
}

export function useAuth(): UseAuthReturn {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { signOut: sessionSignOut, refresh } = useSession();

  // Clear error
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Send magic link
  const sendMagicLink = useCallback(async (request: SendMagicLinkRequest): Promise<AuthResponse> => {
    setIsLoading(true);
    setError(null);

    try {
      logger.info('Sending magic link', {
        email: request.email,
        hasRedirectUrl: !!request.redirectUrl,
      });

      const response = await AuthApi.sendMagicLink(request);

      if (!response.success) {
        const errorMessage = response.error?.message || 'Failed to send magic link';
        setError(errorMessage);
        return {
          success: false,
          message: errorMessage,
        };
      }

      logger.info('Magic link sent successfully', {
        email: request.email,
        isNewUser: response.data?.isNewUser,
      });

      return {
        success: true,
        message: response.message || 'Magic link sent successfully',
        data: response.data,
      };
    } catch (error: any) {
      const errorMessage = error?.message || 'Network error occurred';
      
      logger.error('Magic link send failed', error as Error, {
        email: request.email,
      });
      
      setError(errorMessage);
      return {
        success: false,
        message: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Verify magic link
  const verifyMagicLink = useCallback(async (request: VerifyMagicLinkRequest): Promise<AuthResponse> => {
    setIsLoading(true);
    setError(null);

    try {
      logger.info('Verifying magic link', {
        hasToken: !!request.token,
        hasProfile: !!request.profile,
      });

      const response = await AuthApi.verifyMagicLink(request);

      if (!response.success) {
        const errorMessage = response.error?.message || 'Failed to verify magic link';
        setError(errorMessage);
        return {
          success: false,
          message: errorMessage,
        };
      }

      logger.info('Magic link verified successfully', {
        userId: response.data?.user?.id,
        isNewUser: response.data?.isNewUser,
      });

      // Refresh session data after successful verification
      await refresh();

      return {
        success: true,
        message: response.message || 'Signed in successfully',
        data: response.data,
      };
    } catch (error: any) {
      const errorMessage = error?.message || 'Network error occurred';
      
      logger.error('Magic link verification failed', error as Error);
      
      setError(errorMessage);
      return {
        success: false,
        message: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  }, [refresh]);

  // Delete account
  const deleteAccount = useCallback(async (): Promise<AuthResponse> => {
    setIsLoading(true);
    setError(null);

    try {
      logger.info('Deleting account');

      const response = await AuthApi.deleteAccount();

      if (!response.success) {
        const errorMessage = response.error?.message || 'Failed to delete account';
        setError(errorMessage);
        return {
          success: false,
          message: errorMessage,
        };
      }

      logger.info('Account deleted successfully');

      // Redirect to signin after successful deletion
      window.location.href = '/signin';

      return {
        success: true,
        message: response.message || 'Account deleted successfully',
      };
    } catch (error: any) {
      const errorMessage = error?.message || 'Network error occurred';
      
      logger.error('Account deletion failed', error as Error);
      
      setError(errorMessage);
      return {
        success: false,
        message: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Sign out
  const signOut = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      logger.info('Signing out');

      await AuthApi.signOut();

      logger.info('Sign out successful');

      // Clear session data and redirect
      setError(null);
      window.location.href = '/signin';
    } catch (error) {
      logger.error('Sign out error', error as Error);
      
      const errorMessage = error instanceof Error ? error.message : 'Failed to sign out';
      setError(errorMessage);
      
      // Still try to clear local session and redirect
      try {
        await sessionSignOut();
      } catch (sessionError) {
        logger.error('Session signout error', sessionError as Error);
        // Force redirect even if session cleanup fails
        window.location.href = '/signin';
      }
    } finally {
      setIsLoading(false);
    }
  }, [sessionSignOut]);

  return {
    isLoading,
    error,
    sendMagicLink,
    verifyMagicLink,
    signOut,
    deleteAccount,
    clearError,
  };
}
