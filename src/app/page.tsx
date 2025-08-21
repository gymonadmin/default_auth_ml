// src/app/page.tsx
'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { apiClient } from '@/lib/api/client';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('homepage');

export default function HomePage() {
  const [isTestingApi, setIsTestingApi] = useState(false);
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
    } finally {
      setIsTestingApi(false);
    }
  };

  const handleContinueWithEmail = () => {
    logger.info('User clicked Continue with Email', {
      navigatingTo: '/signin',
    });
    
    // For now, just log the action - will implement navigation in Build 2
    console.log('Navigating to /signin...');
    alert('Navigation will be implemented in Build 2');
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
              className="w-full"
              size="lg"
            >
              Continue with email
            </Button>
          </CardContent>
        </Card>

        {/* API Test Section - For Build 1 testing only */}
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
              {isTestingApi ? 'Testing API...' : 'Test API Connection'}
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

            <div className="text-xs text-muted-foreground space-y-1">
              <div>Check browser console for detailed logs</div>
              <div>Correlation IDs help track requests</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
