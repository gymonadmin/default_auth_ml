// src/app/page.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ButtonLoading } from '@/components/ui/loading';
import { SessionApi } from '@/lib/api/session';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('homepage');

export default function HomePage() {
  const router = useRouter();
  const [isNavigating, setIsNavigating] = useState(false);
  const [isHealthy, setIsHealthy] = useState<boolean | null>(null);

  const handleContinueWithEmail = async () => {
    setIsNavigating(true);
    
    logger.info('User clicked Continue with Email');

    // Quick health check before navigation
    const healthy = await SessionApi.healthCheck();
    setIsHealthy(healthy);

    if (!healthy) {
      toast.error('Service temporarily unavailable');
      setIsNavigating(false);
      return;
    }

    try {
      await new Promise(resolve => setTimeout(resolve, 500));
      router.push('/signin');
      logger.info('Navigation to signin completed');
    } catch (error) {
      logger.error('Navigation failed', error as Error);
      toast.error('Navigation failed');
      setIsNavigating(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <div className="text-center space-y-2 mb-6">
          <h1 className="text-3xl font-bold tracking-tight">
            Welcome to DocsBox Auth
          </h1>
          <p className="text-muted-foreground">
            Secure authentication with magic links
          </p>
          {isHealthy === false && (
            <p className="text-sm text-red-600">Service temporarily unavailable</p>
          )}
        </div>

        <Card>
          <CardHeader className="text-center">
            <CardTitle>Get Started</CardTitle>
            <CardDescription>
              Continue with your email address
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button 
              onClick={handleContinueWithEmail}
              disabled={isNavigating}
              className="w-full"
              size="lg"
            >
              {isNavigating ? (
                <>
                  <ButtonLoading className="mr-2" />
                  Redirecting...
                </>
              ) : (
                'Continue with email'
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
