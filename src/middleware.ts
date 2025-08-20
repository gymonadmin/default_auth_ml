// src/middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { generateCSPNonce, buildCSPHeader } from '@/lib/utils/csp';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  // Generate nonce for each request
  const nonce = generateCSPNonce();
  
  // Set CSP header with nonce for HTML pages
  const isPageRequest = 
    request.nextUrl.pathname.startsWith('/') && 
    !request.nextUrl.pathname.startsWith('/api/') &&
    !request.nextUrl.pathname.startsWith('/_next/') &&
    !request.nextUrl.pathname.includes('.');

  if (isPageRequest) {
    response.headers.set('Content-Security-Policy', buildCSPHeader(nonce));
    response.headers.set('X-CSP-Nonce', nonce);
  }

  // Add security headers for API routes
  if (request.nextUrl.pathname.startsWith('/api/')) {
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Stricter CSP for API routes
    response.headers.set('Content-Security-Policy', "default-src 'none'");
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public assets (images, etc.)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
