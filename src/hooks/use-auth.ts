// src/hooks/use-auth.ts
'use client';

import { useState, useCallback } from 'react';
import { useSession } from './use-session';

export interface SendMagicLinkRequest {
  email: string;
  redirectUrl?: string;
}

export interface VerifyMagicLinkRequest {
  token: string;
  profile?: {
    firstName: string;
    lastName: string;
  };
}

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
      const response = await fetch('/api/auth/send-link', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(request),
      });

      const result = await response.json();

      if (!response.ok) {
        const errorMessage = result.error?.message || 'Failed to send magic link';
        setError(errorMessage);
        return {
          success: false,
          message: errorMessage,
        };
      }

      return {
        success: true,
        message: result.message,
        data: result.data,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Network error occurred';
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
      const response = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(request),
      });

      const result = await response.json();

      if (!response.ok) {
        const errorMessage = result.error?.message || 'Failed to verify magic link';
        setError(errorMessage);
        return {
          success: false,
          message: errorMessage,
        };
      }

      // Refresh session data after successful verification
      await refresh();

      return {
        success: true,
        message: result.message,
        data: result.data,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Network error occurred';
      setError(errorMessage);
      return {
        success: false,
        message: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  }, [refresh]);

  // Sign out
  const signOut = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      await sessionSignOut();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to sign out';
      setError(errorMessage);
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
    clearError,
  };
}
