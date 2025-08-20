// src/app/(auth)/verify/page.tsx
import type { Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function VerifyPage() {
  return (
    <div>
      <h1>Verify</h1>
      <p>Magic link verification page - to be implemented</p>
    </div>
  );
}
