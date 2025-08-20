// src/app/layout.tsx
import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import './globals.css';

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
    <html lang="en">
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
        {children}
        
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
