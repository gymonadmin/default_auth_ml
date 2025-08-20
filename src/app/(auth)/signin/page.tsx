// src/app/(auth)/signin/page.tsx
import type { Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function SignInPage() {
  return (
    <div>
      <h1>Sign In</h1>
      <p>Sign in page - to be implemented</p>
    </div>
  );
}
