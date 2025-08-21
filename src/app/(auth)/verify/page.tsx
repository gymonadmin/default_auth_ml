// src/app/(auth)/verify/page.tsx
import { Suspense } from 'react';
import { VerifyForm } from '@/components/auth/verify-form';
import { Loading } from '@/components/ui/loading';
import type { Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

function VerifyPageContent() {
  return <VerifyForm />;
}

export default function VerifyPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loading size="lg" text="Loading..." />
      </div>
    }>
      <VerifyPageContent />
    </Suspense>
  );
}
