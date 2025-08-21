// src/components/auth/signin-form.tsx
'use client';

import { EmailForm } from './email-form';

interface SignInFormProps {
  redirectUrl?: string;
}

export function SignInForm({ redirectUrl }: SignInFormProps) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <EmailForm redirectUrl={redirectUrl} />
    </div>
  );
}
