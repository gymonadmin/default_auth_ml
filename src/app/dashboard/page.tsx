// src/app/dashboard/page.tsx
import type { Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function DashboardPage() {
  return (
    <div>
      <h1>Dashboard</h1>
      <p>User dashboard - to be implemented</p>
    </div>
  );
}
