// src/lib/utils/csrf.ts
import { serialize } from 'cookie';

// Edge Runtime compatible crypto functions
function getRandomBytes(length: number): Uint8Array {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
    // Browser/Edge Runtime
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  } else if (typeof require !== 'undefined') {
    // Node.js runtime fallback
    try {
      const { randomBytes } = require('crypto');
      return new Uint8Array(randomBytes(length));
    } catch (error) {
      console.warn('Crypto not available, using fallback');
    }
  }
  
  // Fallback for environments without crypto (not recommended for production)
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

const CSRF_TOKEN_HEADER = 'X-CSRF-Token';
const CSRF_COOKIE_NAME = 'csrf-token';
const CSRF_TOKEN_LENGTH = 32; // 32 bytes = 64 hex characters

/**
 * Generate a CSRF token
 */
export function generateCSRFToken(): string {
  return bytesToHex(getRandomBytes(CSRF_TOKEN_LENGTH));
}

/**
 * Create a secure CSRF cookie
 */
export function createCSRFCookie(token: string): string {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return serialize(CSRF_COOKIE_NAME, token, {
    httpOnly: false, // Client needs to read this to include in requests
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 3600, // 1 hour
  });
}

/**
 * Clear CSRF cookie
 */
export function clearCSRFCookie(): string {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return serialize(CSRF_COOKIE_NAME, '', {
    httpOnly: false,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    expires: new Date(0),
    maxAge: 0,
  });
}

/**
 * Extract CSRF token from request headers
 */
export function getCSRFTokenFromHeaders(headers: Headers): string | null {
  return headers.get(CSRF_TOKEN_HEADER) || headers.get(CSRF_TOKEN_HEADER.toLowerCase());
}

/**
 * Extract CSRF token from cookies
 */
export function getCSRFTokenFromCookies(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      acc[name] = decodeURIComponent(value);
    }
    return acc;
  }, {} as Record<string, string>);
  
  return cookies[CSRF_COOKIE_NAME] || null;
}

/**
 * Validate CSRF token using timing-safe comparison
 */
export function validateCSRFToken(headerToken: string | null, cookieToken: string | null): boolean {
  if (!headerToken || !cookieToken) {
    return false;
  }
  
  // Check token format (should be 64 hex characters)
  if (!/^[0-9a-f]{64}$/i.test(headerToken) || !/^[0-9a-f]{64}$/i.test(cookieToken)) {
    return false;
  }
  
  try {
    const headerBuffer = hexToBytes(headerToken);
    const cookieBuffer = hexToBytes(cookieToken);
    
    if (headerBuffer.length !== cookieBuffer.length) {
      return false;
    }
    
    return timingSafeEqual(headerBuffer, cookieBuffer);
  } catch {
    return false;
  }
}

/**
 * Create CSRF token pair (for cookie and client use)
 */
export function createCSRFTokenPair(): { token: string; cookie: string } {
  const token = generateCSRFToken();
  const cookie = createCSRFCookie(token);
  
  return { token, cookie };
}

/**
 * Check if method requires CSRF protection
 */
export function methodRequiresCSRF(method: string): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase());
}

/**
 * Check if route requires CSRF protection
 */
export function routeRequiresCSRF(pathname: string): boolean {
  const protectedRoutes = [
    '/api/auth/verify',
    '/api/auth/signout',
  ];
  
  return protectedRoutes.some(route => pathname.startsWith(route));
}

/**
 * Get CSRF header name
 */
export function getCSRFHeaderName(): string {
  return CSRF_TOKEN_HEADER;
}

/**
 * Get CSRF cookie name
 */
export function getCSRFCookieName(): string {
  return CSRF_COOKIE_NAME;
}
