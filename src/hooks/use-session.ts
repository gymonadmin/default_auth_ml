// src/hooks/use-session.ts
'use client';

import { useState, useEffect, useCallback } from 'react';
import { SessionApi } from '@/lib/api/session';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('use-session');

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
      logger.debug('Validating session');

      const response = await SessionApi.validateSession();

      if (response.success && response.data) {
        logger.debug('Session validation successful', {
          userId: response.data.user.id,
          sessionId: response.data.session.id,
        });
        
        return response.data;
      }

      logger.debug('Session validation failed - no valid session');
      return null;
    } catch (error: any) {
      logger.debug('Session validation error', {
        error: error?.message || 'Unknown error',
      });
      return null;
    }
  }, []);

  // Refresh session data
  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      logger.debug('Refreshing session data');
      
      const sessionData = await validateSession();
      setData(sessionData);
      
      if (sessionData) {
        logger.debug('Session refresh successful', {
          userId: sessionData.user.id,
        });
      } else {
        logger.debug('Session refresh - no valid session');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to refresh session';
      
      logger.error('Session refresh failed', error as Error);
      
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
      
      logger.info('Signing out user');

      // Note: Actual API call is handled by useAuth hook
      // This just clears local session data
      setData(null);
      setError(null);

      logger.info('Local session cleared');
    } catch (error) {
      logger.error('Sign out error', error as Error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initialize session on mount
  useEffect(() => {
    logger.debug('Initializing session on mount');
    refresh();
  }, [refresh]);

  // Auto-refresh session periodically (every 5 minutes)
  useEffect(() => {
    if (!data) return;

    logger.debug('Setting up session auto-refresh');

    const interval = setInterval(() => {
      logger.debug('Auto-refreshing session');
      
      validateSession().then(sessionData => {
        if (!sessionData) {
          logger.info('Session expired during auto-refresh');
          // Session expired, clear data and redirect
          setData(null);
          window.location.href = '/signin';
        } else {
          setData(sessionData);
        }
      });
    }, 5 * 60 * 1000); // 5 minutes

    return () => {
      logger.debug('Clearing session auto-refresh interval');
      clearInterval(interval);
    };
  }, [data, validateSession]);

  // Check if session is expiring soon (within 30 minutes)
  const isExpiringSoon = data ? 
    new Date(data.session.expiresAt).getTime() - Date.now() < 30 * 60 * 1000 : 
    false;

  // Auto-extend session if expiring soon and user is active
  useEffect(() => {
    if (!data || !isExpiringSoon) return;

    logger.debug('Session expiring soon, setting up activity detection');

    // Simple activity detection
    const handleActivity = () => {
      logger.debug('User activity detected, refreshing session');
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
