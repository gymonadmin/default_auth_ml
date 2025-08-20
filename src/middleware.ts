// src/middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { generateCSPNonce, setCSPHeaders } from '@/lib/utils/csp';
import { generateCorrelationId } from '@/lib/utils/correlation-id';
import { getClientIP } from '@/lib/utils/ip';
import { Logger } from '@/lib/config/logger';

// Configuration from environment variables
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || ['http://localhost:3000'];
const ALLOW_CREDENTIALS = process.env.ALLOW_CREDENTIALS === 'true';
const RATE_LIMIT_COUNT = parseInt(process.env.RATE_LIMIT_COUNT || '100');
const RATE_LIMIT_WINDOW_SECONDS = parseInt(process.env.RATE_LIMIT_WINDOW_SECONDS || '60');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Light in-memory rate limiter for Edge (conservative thresholds)
interface RateLimitEntry {
  count: number;
  resetTime: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

/**
 * Clean up expired rate limit entries
 */
function cleanupRateLimitStore(): void {
  const now = Date.now();
  const keysToDelete: string[] = [];
  
  rateLimitStore.forEach((entry, key) => {
    if (now > entry.resetTime) {
      keysToDelete.push(key);
    }
  });
  
  keysToDelete.forEach(key => rateLimitStore.delete(key));
}

/**
 * Light rate limit check for Edge (burst protection only)
 */
function checkEdgeRateLimit(ip: string): { allowed: boolean; remaining: number; resetTime: number } {
  const now = Date.now();
  const windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;
  
  // Periodic cleanup (1% chance per request)
  if (Math.random() < 0.01) {
    cleanupRateLimitStore();
  }
  
  const entry = rateLimitStore.get(ip);
  
  if (!entry || now > entry.resetTime) {
    const newEntry: RateLimitEntry = {
      count: 1,
      resetTime: now + windowMs
    };
    rateLimitStore.set(ip, newEntry);
    return {
      allowed: true,
      remaining: RATE_LIMIT_COUNT - 1,
      resetTime: newEntry.resetTime
    };
  }
  
  entry.count += 1;
  
  return {
    allowed: entry.count <= RATE_LIMIT_COUNT,
    remaining: Math.max(0, RATE_LIMIT_COUNT - entry.count),
    resetTime: entry.resetTime
  };
}

/**
 * Check if origin is allowed
 */
function isOriginAllowed(origin: string): boolean {
  if (ALLOWED_ORIGINS.includes('*')) {
    return true;
  }
  return ALLOWED_ORIGINS.includes(origin);
}

/**
 * Add CORS headers to response
 */
function addCorsHeaders(response: NextResponse, request: NextRequest): void {
  const origin = request.headers.get('origin');
  
  if (origin && isOriginAllowed(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin);
  } else if (ALLOWED_ORIGINS.includes('*') && !ALLOW_CREDENTIALS) {
    response.headers.set('Access-Control-Allow-Origin', '*');
  }
  
  if (ALLOW_CREDENTIALS) {
    response.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  response.headers.set('Access-Control-Allow-Headers', 
    'Content-Type, Authorization, X-Requested-With, Accept, Origin, X-Correlation-ID'
  );
  response.headers.set('Access-Control-Max-Age', '86400'); // 24 hours
}

/**
 * Add security headers to response
 */
function addSecurityHeaders(response: NextResponse, correlationId: string, nonce: string): void {
  if (IS_PRODUCTION) {
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    response.headers.set('X-XSS-Protection', '1; mode=block');
  }
  
  // Base security headers for all environments
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()');
  
  // CSP headers with nonce (use the nonce generated in middleware)
  setCSPHeaders(response.headers, correlationId, nonce);
}

/**
 * Add rate limit headers to response
 */
function addRateLimitHeaders(
  response: NextResponse, 
  remaining: number, 
  resetTime: number
): void {
  response.headers.set('X-RateLimit-Limit', RATE_LIMIT_COUNT.toString());
  response.headers.set('X-RateLimit-Remaining', remaining.toString());
  response.headers.set('X-RateLimit-Reset', Math.ceil(resetTime / 1000).toString());
  
  if (remaining === 0) {
    const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);
    response.headers.set('Retry-After', retryAfter.toString());
  }
}

/**
 * Main middleware function
 */
export function middleware(request: NextRequest) {
  const startTime = Date.now();
  const pathname = request.nextUrl.pathname;
  
  // Generate correlation ID and nonce for request tracking and CSP
  const correlationId = generateCorrelationId();
  const nonce = generateCSPNonce();
  const logger = new Logger(correlationId);
  
  logger.debug('Middleware processing request', {
    method: request.method,
    pathname,
    userAgent: request.headers.get('user-agent'),
    origin: request.headers.get('origin'),
  });
  
  // Handle preflight OPTIONS requests early
  if (request.method === 'OPTIONS') {
    logger.debug('Handling OPTIONS preflight request');
    const response = new NextResponse(null, { status: 200 });
    addCorsHeaders(response, request);
    addSecurityHeaders(response, correlationId, nonce);
    response.headers.set('X-Correlation-ID', correlationId);
    response.headers.set('X-Response-Time', `${Date.now() - startTime}ms`);
    return response;
  }
  
  // Get client IP for rate limiting and logging
  const clientIP = getClientIP(request);
  
  // Light Edge rate limiting (burst protection)
  const rateLimit = checkEdgeRateLimit(clientIP);
  
  let response: NextResponse;
  
  if (!rateLimit.allowed) {
    logger.warn('Rate limit exceeded', {
      clientIP,
      pathname,
      count: RATE_LIMIT_COUNT,
      window: RATE_LIMIT_WINDOW_SECONDS,
    });
    
    // Rate limit exceeded
    response = NextResponse.json(
      {
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later',
          correlationId,
        },
        timestamp: new Date().toISOString()
      },
      { status: 429 }
    );
  } else {
    // Rate limit OK, continue with request
    response = NextResponse.next({
      request: {
        headers: new Headers({
          ...Object.fromEntries(request.headers.entries()),
          'X-Correlation-ID': correlationId,
          'X-Client-IP': clientIP,
          'X-CSP-Nonce': nonce, // Forward nonce to API routes if needed
        })
      }
    });
  }
  
  // Add all standard headers to response
  addCorsHeaders(response, request);
  addSecurityHeaders(response, correlationId, nonce);
  addRateLimitHeaders(response, rateLimit.remaining, rateLimit.resetTime);
  
  // Add correlation ID and timing headers
  response.headers.set('X-Correlation-ID', correlationId);
  response.headers.set('X-Response-Time', `${Date.now() - startTime}ms`);
  
  logger.debug('Middleware completed', {
    statusCode: response.status,
    duration: Date.now() - startTime,
    rateLimitRemaining: rateLimit.remaining,
  });
  
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
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js)$).*)',
  ],
};

// Specify Edge Runtime for better performance
export const runtime = 'experimental-edge';
