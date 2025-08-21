// src/app/page.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loading, ButtonLoading } from '@/components/ui/loading';
import { apiClient } from '@/lib/api/client';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('homepage');

export default function HomePage() {
  const router = useRouter();
  const [isTestingApi, setIsTestingApi] = useState(false);
  const [isNavigating, setIsNavigating] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    correlationId?: string;
  } | null>(null);

  const handleApiTest = async () => {
    setIsTestingApi(true);
    setTestResult(null);

    logger.info('Starting API connectivity test', {
      userInitiated: true,
    });

    try {
      const isHealthy = await apiClient.healthCheck();
      const correlationId = apiClient.getCorrelationId();

      if (isHealthy) {
        logger.info('API connectivity test successful', {
          correlationId,
          healthy: true,
        });

        setTestResult({
          success: true,
          message: 'API connection successful! Ready to proceed.',
          correlationId,
        });

        toast.success('API connection successful!', {
          description: 'The backend is responding correctly.',
        });
      } else {
        logger.warn('API connectivity test failed', {
          correlationId,
          healthy: false,
        });

        setTestResult({
          success: false,
          message: 'API connection failed. Please check server status.',
          correlationId,
        });

        toast.error('API connection failed', {
          description: 'Unable to connect to the backend server.',
        });
      }
    } catch (error) {
      const correlationId = apiClient.getCorrelationId();
      
      logger.error('API connectivity test error', error as Error, {
        correlationId,
      });

      setTestResult({
        success: false,
        message: `Connection error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        correlationId,
      });

      toast.error('Connection error', {
        description: error instanceof Error ? error.message : 'Unknown error occurred',
      });
    } finally {
      setIsTestingApi(false);
    }
  };

  const handleContinueWithEmail = async () => {
    setIsNavigating(true);
    
    logger.info('User clicked Continue with Email', {
      navigatingTo: '/signin',
    });

    // Show loading toast
    toast.loading('Redirecting to sign in...', {
      id: 'navigation',
    });

    try {
      // Simulate brief loading for UX
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // Navigate to signin page
      router.push('/signin');
      
      // Dismiss loading toast and show success
      toast.dismiss('navigation');
      toast.success('Redirected successfully');
      
      logger.info('Navigation to signin completed', {
        successful: true,
      });
    } catch (error) {
      logger.error('Navigation failed', error as Error);
      
      toast.dismiss('navigation');
      toast.error('Navigation failed', {
        description: 'Unable to redirect to sign in page',
      });
      
      setIsNavigating(false);
    }
  };

  const handleTestToast = () => {
    logger.info('User tested toast notifications');
    
    // Test different toast types
    toast.info('Test notification', {
      description: 'Toast system is working correctly!',
    });
    
    setTimeout(() => {
      toast.success('Toast test completed');
    }, 1000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">
            Welcome to DocsBox Auth
          </h1>
          <p className="text-muted-foreground">
            Secure authentication with magic links
          </p>
        </div>

        <Card>
          <CardHeader className="text-center">
            <CardTitle>Get Started</CardTitle>
            <CardDescription>
              Continue with your email address
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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

        {/* Build 2 Test Section */}
        <Card className="border-dashed border-blue-200">
          <CardHeader>
            <CardTitle className="text-sm text-blue-600">
              Build 2 - Navigation & Toast Test
            </CardTitle>
            <CardDescription className="text-xs">
              Test toast notifications and loading states
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <Button 
                onClick={handleTestToast}
                variant="outline"
                size="sm"
              >
                Test Toast
              </Button>
              
              <Button 
                onClick={() => toast.error('Error test', { description: 'This is a test error' })}
                variant="outline"
                size="sm"
              >
                Test Error
              </Button>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-medium">Loading Component Test:</p>
              <div className="flex gap-4 items-center">
                <Loading size="sm" />
                <Loading size="md" text="Loading..." />
                <Loading size="lg" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* API Test Section - From Build 1 */}
        <Card className="border-dashed border-orange-200">
          <CardHeader>
            <CardTitle className="text-sm text-orange-600">
              Build 1 - API Test
            </CardTitle>
            <CardDescription className="text-xs">
              Test API connectivity (remove in production)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button 
              onClick={handleApiTest}
              disabled={isTestingApi}
              variant="outline"
              size="sm"
              className="w-full"
            >
              {isTestingApi ? (
                <>
                  <ButtonLoading className="mr-2" />
                  Testing API...
                </>
              ) : (
                'Test API Connection'
              )}
            </Button>

            {testResult && (
              <div className={`p-3 rounded-md text-sm ${
                testResult.success 
                  ? 'bg-green-50 text-green-700 border border-green-200' 
                  : 'bg-red-50 text-red-700 border border-red-200'
              }`}>
                <div className="font-medium">
                  {testResult.success ? '✅ Success' : '❌ Failed'}
                </div>
                <div className="mt-1">{testResult.message}</div>
                {testResult.correlationId && (
                  <div className="mt-2 text-xs font-mono opacity-75">
                    ID: {testResult.correlationId}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
