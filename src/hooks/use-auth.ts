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
  deleteAccount: () => Promise<AuthResponse>;
  clearError: () => void;
}

/**
 * Get CSRF token from cookies
 */
function getCSRFToken(): string | null {
  if (typeof document === 'undefined') return null;
  
  const cookies = document.cookie.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      acc[name] = decodeURIComponent(value);
    }
    return acc;
  }, {} as Record<string, string>);
  
  return cookies['csrf-token'] || null;
}

/**
 * Make authenticated request with CSRF token
 */
async function makeAuthenticatedRequest(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const csrfToken = getCSRFToken();
  
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  
  // Add CSRF token for state-changing requests
  if (csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method?.toUpperCase() || 'GET')) {
    headers.set('X-CSRF-Token', csrfToken);
  }
  
  return fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });
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
      // Magic link sending doesn't require CSRF (it's not state-changing for the user's session)
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
      // First, get CSRF token if we don't have one
      let csrfToken = getCSRFToken();
      
      if (!csrfToken) {
        // Make a GET request to an auth endpoint to get CSRF token
        try {
          const csrfResponse = await fetch('/api/auth/session', {
            method: 'GET',
            credentials: 'include',
          });
          
          // Use csrfResponse to avoid unused variable warning
          if (csrfResponse.ok) {
            // CSRF token should now be in cookies
            csrfToken = getCSRFToken();
          }
        } catch (csrfError) {
          console.warn('Failed to get CSRF token:', csrfError);
        }
      }

      const response = await makeAuthenticatedRequest('/api/auth/verify', {
        method: 'POST',
        body: JSON.stringify(request),
      });

      const result = await response.json();

      if (!response.ok) {
        const errorMessage = result.error?.message || 'Failed to verify magic link';
        
        // If CSRF token was invalid, try to get a new one
        if (result.error?.code === 'CSRF_TOKEN_INVALID') {
          setError('Security token expired. Please try again.');
        } else {
          setError(errorMessage);
        }
        
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

  // Delete account
  const deleteAccount = useCallback(async (): Promise<AuthResponse> => {
    setIsLoading(true);
    setError(null);

    try {
      // Get CSRF token for delete account
      const csrfToken = getCSRFToken();
      
      if (!csrfToken) {
        setError('Security token not available. Please refresh and try again.');
        return {
          success: false,
          message: 'Security token not available. Please refresh and try again.',
        };
      }

      const response = await makeAuthenticatedRequest('/api/auth/delete-account', {
        method: 'POST',
        body: JSON.stringify({}),
      });

      const result = await response.json();

      if (!response.ok) {
        const errorMessage = result.error?.message || 'Failed to delete account';
        
        // If CSRF token was invalid, try to get a new one
        if (result.error?.code === 'CSRF_TOKEN_INVALID') {
          setError('Security token expired. Please refresh and try again.');
        } else {
          setError(errorMessage);
        }
        
        return {
          success: false,
          message: errorMessage,
        };
      }

      // Account deleted successfully - redirect to home/signin
      window.location.href = '/signin';

      return {
        success: true,
        message: result.message,
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

  // Sign out
  const signOut = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Get CSRF token for signout
      const csrfToken = getCSRFToken();
      
      if (!csrfToken) {
        // If no CSRF token, still try to sign out via session hook
        await sessionSignOut();
        return;
      }

      await makeAuthenticatedRequest('/api/auth/signout', {
        method: 'POST',
        body: JSON.stringify({}),
      });

      // Clear session data regardless of API response
      setError(null);

      // Redirect to signin page
      window.location.href = '/signin';
    } catch (error) {
      console.error('Sign out error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to sign out';
      setError(errorMessage);
      
      // Still try to clear local session and redirect
      try {
        await sessionSignOut();
      } catch (sessionError) {
        console.error('Session signout error:', sessionError);
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
