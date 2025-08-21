// src/components/auth/auth-guard.tsx
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useSession } from '@/hooks/use-session';
import { Loading } from '@/components/ui/loading';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('auth-guard');

interface AuthGuardProps {
  children: React.ReactNode;
  redirectTo?: string;
  requireAuth?: boolean;
}

export function AuthGuard({ 
  children, 
  redirectTo = '/signin',
  requireAuth = true 
}: AuthGuardProps) {
  const router = useRouter();
  const { data: sessionData, isLoading, isAuthenticated } = useSession();

  useEffect(() => {
    if (isLoading) {
      logger.debug('Auth guard waiting for session loading');
      return;
    }

    if (requireAuth && !isAuthenticated) {
      logger.info('User not authenticated, redirecting to signin', {
        redirectTo,
        currentPath: window.location.pathname,
      });

      router.push(redirectTo);
      return;
    }

    if (!requireAuth && isAuthenticated) {
      logger.info('User already authenticated, redirecting to dashboard', {
        userId: sessionData?.user?.id,
        currentPath: window.location.pathname,
      });

      router.push('/dashboard');
      return;
    }

    logger.debug('Auth guard check passed', {
      requireAuth,
      isAuthenticated,
      userId: sessionData?.user?.id,
    });
  }, [isLoading, isAuthenticated, requireAuth, redirectTo, router, sessionData]);

  // Show loading while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loading size="lg" text="Checking authentication..." />
      </div>
    );
  }

  // Show loading while redirecting
  if ((requireAuth && !isAuthenticated) || (!requireAuth && isAuthenticated)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loading size="lg" text="Redirecting..." />
      </div>
    );
  }

  // Render children if auth check passes
  return <>{children}</>;
}
