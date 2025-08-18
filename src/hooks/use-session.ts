// src/hooks/use-session.ts
'use client';

import { useState, useEffect, useCallback } from 'react';

export interface User {
  id: string;
  email: string;
  isVerified: boolean;
  profile: {
    id: string;
    firstName: string;
    lastName: string;
    fullName: string;
    initials: string;
  } | null;
}

export interface Session {
  id: string;
  expiresAt: string;
  lastAccessedAt?: string;
  isActive: boolean;
}

export interface SessionData {
  user: User;
  session: Session;
}

export interface UseSessionReturn {
  data: SessionData | null;
  isLoading: boolean;
  error: string | null;
  isAuthenticated: boolean;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

export function useSession(): UseSessionReturn {
  const [data, setData] = useState<SessionData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Validate current session
  const validateSession = useCallback(async (): Promise<SessionData | null> => {
    try {
      const response = await fetch('/api/auth/session', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const result = await response.json();
        if (result.success && result.data) {
          return result.data;
        }
      }

      // Session invalid or expired
      return null;
    } catch (error) {
      console.error('Session validation error:', error);
      return null;
    }
  }, []);

  // Refresh session data
  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const sessionData = await validateSession();
      setData(sessionData);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to refresh session';
      setError(errorMessage);
      setData(null);
    } finally {
      setIsLoading(false);
    }
  }, [validateSession]);

  // Sign out user
  const signOut = useCallback(async () => {
    try {
      setIsLoading(true);
      
      await fetch('/api/auth/signout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      // Clear session data regardless of API response
      setData(null);
      setError(null);

      // Redirect to signin page
      window.location.href = '/signin';
    } catch (error) {
      console.error('Sign out error:', error);
      // Still clear local session data on error
      setData(null);
      window.location.href = '/signin';
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initialize session on mount
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto-refresh session periodically (every 5 minutes)
  useEffect(() => {
    if (!data) return;

    const interval = setInterval(() => {
      validateSession().then(sessionData => {
        if (!sessionData) {
          // Session expired, clear data and redirect
          setData(null);
          window.location.href = '/signin';
        } else {
          setData(sessionData);
        }
      });
    }, 5 * 60 * 1000); // 5 minutes

    return () => clearInterval(interval);
  }, [data, validateSession]);

  // Check if session is expiring soon (within 30 minutes)
  const isExpiringSoon = data ? 
    new Date(data.session.expiresAt).getTime() - Date.now() < 30 * 60 * 1000 : 
    false;

  // Auto-extend session if expiring soon and user is active
  useEffect(() => {
    if (!data || !isExpiringSoon) return;

    // Simple activity detection
    const handleActivity = () => {
      refresh();
    };

    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach(event => {
      document.addEventListener(event, handleActivity, { passive: true });
    });

    return () => {
      events.forEach(event => {
        document.removeEventListener(event, handleActivity);
      });
    };
  }, [data, isExpiringSoon, refresh]);

  return {
    data,
    isLoading,
    error,
    isAuthenticated: !!data,
    refresh,
    signOut,
  };
}
