// src/app/layout.tsx
import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import './globals.css';
import { ThemeProvider } from '@/components/providers/theme-provider';
import { ToastProvider } from '@/components/providers/toast-provider';

export const metadata: Metadata = {
  title: 'DocsBox Auth',
  description: 'Magic link authentication system',
  robots: 'noindex, nofollow', // Prevent indexing of auth system
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Get CSP nonce from headers if available
  const headersList = headers();
  const nonce = headersList.get('X-CSP-Nonce') || undefined;

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Meta tags for security */}
        <meta name="robots" content="noindex, nofollow" />
        <meta name="referrer" content="strict-origin-when-cross-origin" />
        
        {/* CSP nonce meta tag for client-side scripts if needed */}
        {nonce && (
          <meta name="csp-nonce" content={nonce} />
        )}
      </head>
      <body>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <ToastProvider />
        </ThemeProvider>
        
        {/* Any inline scripts would need the nonce */}
        {nonce && (
          <script
            nonce={nonce}
            dangerouslySetInnerHTML={{
              __html: `
                // Client-side initialization code if needed
                window.__CSP_NONCE__ = '${nonce}';
              `,
            }}
          />
        )}
      </body>
    </html>
  );
}
