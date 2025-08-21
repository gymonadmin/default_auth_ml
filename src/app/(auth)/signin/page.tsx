// src/app/(auth)/signin/page.tsx
import { Suspense } from 'react';
import { SignInForm } from '@/components/auth/signin-form';
import { Loading } from '@/components/ui/loading';
import type { Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

function SignInPageContent() {
  return <SignInForm />;
}

export default function SignInPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loading size="lg" text="Loading..." />
      </div>
    }>
      <SignInPageContent />
    </Suspense>
  );
}
