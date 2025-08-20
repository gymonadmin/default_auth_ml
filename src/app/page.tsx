// src/app/page.tsx
import type { Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function HomePage() {
  return (
    <div>
      <h1>Home</h1>
      <p>Home page - to be implemented</p>
    </div>
  );
}
