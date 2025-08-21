// src/components/auth/verify-form.tsx
'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loading, ButtonLoading } from '@/components/ui/loading';
import { useAuth } from '@/hooks/use-auth';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('verify-form');

const profileSchema = z.object({
  firstName: z
    .string()
    .min(1, 'First name is required')
    .max(50, 'First name is too long')
    .regex(/^[a-zA-Z\s'-]+$/, 'First name contains invalid characters'),
  lastName: z
    .string()
    .min(1, 'Last name is required')
    .max(50, 'Last name is too long')
    .regex(/^[a-zA-Z\s'-]+$/, 'Last name contains invalid characters'),
});

type ProfileFormData = z.infer<typeof profileSchema>;

interface VerifyFormProps {
  token?: string;
}

export function VerifyForm({ token: propToken }: VerifyFormProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isVerifying, setIsVerifying] = useState(false);
  const [needsProfile, setNeedsProfile] = useState(false);
  const [userData, setUserData] = useState<{ isNewUser: boolean; email?: string } | null>(null);
  const { verifyMagicLink, isLoading, error, clearError } = useAuth();

  // Get token from props or URL params
  const token = propToken || searchParams?.get('token') || '';
  const redirectUrl = searchParams?.get('redirect') || undefined;

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
  });

  // Auto-verify token for existing users
  useEffect(() => {
    if (!token) {
      logger.warn('No token provided for verification');
      toast.error('Invalid magic link', {
        description: 'No verification token found',
      });
      router.push('/signin');
      return;
    }

    logger.info('Starting automatic token verification', {
      tokenLength: token.length,
      hasRedirectUrl: !!redirectUrl,
    });

    const autoVerify = async () => {
      setIsVerifying(true);
      clearError();

      try {
        // Try verification without profile first (for existing users)
        const response = await verifyMagicLink({ token });

        if (response.success) {
          logger.info('Auto-verification successful', {
            isNewUser: response.data?.isNewUser,
            userId: response.data?.user?.id,
          });

          toast.success('Signed in successfully!');

          // Redirect to specified URL or dashboard
          const targetUrl = response.data?.redirectUrl || redirectUrl || '/dashboard';
          router.push(targetUrl);
        } else {
          // Check if this is a new user that needs profile
          if (response.message?.includes('Profile details are required') || 
              response.message?.includes('firstName') || 
              response.message?.includes('lastName')) {
            
            logger.info('New user detected, showing profile form');
            setNeedsProfile(true);
            setUserData({ 
              isNewUser: true, 
              email: response.data?.user?.email || 'user' 
            });
            
            toast.info('Complete your profile', {
              description: 'Please provide your name to finish account setup',
            });
          } else {
            logger.error('Auto-verification failed', {
              error: response.message,
            });

            toast.error('Verification failed', {
              description: response.message,
            });

            setTimeout(() => router.push('/signin'), 2000);
          }
        }
      } catch (error) {
        logger.error('Auto-verification error', error as Error);

        toast.error('Verification error', {
          description: 'Please try requesting a new magic link',
        });

        setTimeout(() => router.push('/signin'), 2000);
      } finally {
        setIsVerifying(false);
      }
    };

    autoVerify();
  }, [token, redirectUrl, verifyMagicLink, clearError, router]);

  const onProfileSubmit = async (data: ProfileFormData) => {
    logger.info('Profile form submitted', {
      firstName: data.firstName,
      lastName: data.lastName,
    });

    clearError();

    try {
      const response = await verifyMagicLink({
        token,
        profile: {
          firstName: data.firstName.trim(),
          lastName: data.lastName.trim(),
        },
      });

      if (response.success) {
        logger.info('Verification with profile successful', {
          userId: response.data?.user?.id,
          fullName: response.data?.user?.profile?.fullName,
        });

        toast.success('Account created successfully!', {
          description: `Welcome, ${data.firstName}!`,
        });

        // Redirect to specified URL or dashboard
        const targetUrl = response.data?.redirectUrl || redirectUrl || '/dashboard';
        router.push(targetUrl);
      } else {
        toast.error('Verification failed', {
          description: response.message,
        });

        logger.error('Verification with profile failed', {
          error: response.message,
        });
      }
    } catch (error) {
      toast.error('Network error', {
        description: 'Please check your connection and try again',
      });

      logger.error('Network error during profile verification', error as Error);
    }
  };

  // Show loading state during auto-verification
  if (isVerifying && !needsProfile) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>Verifying your magic link</CardTitle>
            <CardDescription>
              Please wait while we sign you in...
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center py-8">
            <Loading size="lg" text="Verifying..." />
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show profile form for new users
  if (needsProfile) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>Complete your profile</CardTitle>
            <CardDescription>
              {userData?.isNewUser 
                ? 'Tell us your name to finish setting up your account'
                : 'Please provide your name to continue'
              }
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onProfileSubmit)} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="firstName">First name</Label>
                  <Input
                    id="firstName"
                    type="text"
                    placeholder="John"
                    disabled={isLoading}
                    {...register('firstName')}
                    className={errors.firstName ? 'border-red-500' : ''}
                  />
                  {errors.firstName && (
                    <p className="text-sm text-red-500">{errors.firstName.message}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="lastName">Last name</Label>
                  <Input
                    id="lastName"
                    type="text"
                    placeholder="Doe"
                    disabled={isLoading}
                    {...register('lastName')}
                    className={errors.lastName ? 'border-red-500' : ''}
                  />
                  {errors.lastName && (
                    <p className="text-sm text-red-500">{errors.lastName.message}</p>
                  )}
                </div>
              </div>

              {error && (
                <div className="p-3 rounded-md bg-red-50 border border-red-200">
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              )}

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full"
                size="lg"
              >
                {isLoading ? (
                  <>
                    <ButtonLoading className="mr-2" />
                    Creating account...
                  </>
                ) : (
                  'Complete setup'
                )}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Fallback - should not reach here normally
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle>Invalid verification link</CardTitle>
          <CardDescription>
            This magic link is invalid or has expired
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button 
            onClick={() => router.push('/signin')} 
            className="w-full"
          >
            Request new magic link
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
