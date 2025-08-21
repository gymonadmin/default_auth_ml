// src/components/auth/email-form.tsx
'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ButtonLoading } from '@/components/ui/loading';
import { useAuth } from '@/hooks/use-auth';
import { clientLogger } from '@/lib/config/client-logger';

const logger = clientLogger.withCorrelationId('email-form');

const emailSchema = z.object({
  email: z
    .string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address')
    .max(254, 'Email is too long'),
});

type EmailFormData = z.infer<typeof emailSchema>;

interface EmailFormProps {
  redirectUrl?: string;
}

export function EmailForm({ redirectUrl }: EmailFormProps) {
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [submittedEmail, setSubmittedEmail] = useState<string>('');
  const { sendMagicLink, isLoading, error, clearError } = useAuth();

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<EmailFormData>({
    resolver: zodResolver(emailSchema),
  });

  const onSubmit = async (data: EmailFormData) => {
    logger.info('Email form submitted', {
      email: data.email,
      hasRedirectUrl: !!redirectUrl,
    });

    clearError();

    try {
      const response = await sendMagicLink({
        email: data.email,
        redirectUrl,
      });

      if (response.success) {
        setSubmittedEmail(data.email);
        setIsSubmitted(true);
        reset();

        toast.success('Magic link sent!', {
          description: `Check your inbox at ${data.email}`,
        });

        logger.info('Magic link sent successfully', {
          email: data.email,
          isNewUser: response.data?.isNewUser,
        });
      } else {
        toast.error('Failed to send magic link', {
          description: response.message,
        });

        logger.error('Magic link send failed', {
          email: data.email,
          error: response.message,
        });
      }
    } catch (error) {
      toast.error('Network error', {
        description: 'Please check your connection and try again',
      });

      logger.error('Network error during magic link send', error as Error, {
        email: data.email,
      });
    }
  };

  const handleTryAgain = () => {
    logger.info('User clicked try again');
    setIsSubmitted(false);
    setSubmittedEmail('');
    clearError();
  };

  if (isSubmitted) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-green-600">Check your email</CardTitle>
          <CardDescription>
            We sent a magic link to{' '}
            <span className="font-medium">{submittedEmail}</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="text-center text-sm text-muted-foreground space-y-2">
            <p>Click the link in your email to sign in.</p>
            <p>The link will expire in 15 minutes.</p>
          </div>
          
          <div className="space-y-2">
            <Button
              onClick={handleTryAgain}
              variant="outline"
              className="w-full"
              size="sm"
            >
              Try different email
            </Button>
            
            <p className="text-xs text-center text-muted-foreground">
              Did not receive the email? Check your spam folder.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="text-center">
        <CardTitle>Sign in to DocsBox</CardTitle>
        <CardDescription>
          Enter your email to receive a magic link
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email address</Label>
            <Input
              id="email"
              type="email"
              placeholder="Enter your email"
              disabled={isLoading}
              {...register('email')}
              className={errors.email ? 'border-red-500' : ''}
            />
            {errors.email && (
              <p className="text-sm text-red-500">{errors.email.message}</p>
            )}
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
                Sending magic link...
              </>
            ) : (
              'Continue with email'
            )}
          </Button>
        </form>
        
        <div className="mt-6 text-center">
          <p className="text-xs text-muted-foreground">
            By continuing, you agree to our terms of service and privacy policy.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
