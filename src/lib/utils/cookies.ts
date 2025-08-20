// src/lib/utils/cookies.ts
import { RequestCookies } from 'next/dist/compiled/@edge-runtime/cookies';
import { serialize } from 'cookie';
import crypto from 'crypto';

const SESSION_COOKIE_NAME = 'auth-session';

// Get cookie secret with fallback
function getCookieSecret(): string {
  const secret = process.env.COOKIE_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development') {
      // Use a default secret for testing/development
      return 'test-cookie-secret-for-development-only';
    }
    throw new Error('COOKIE_SECRET environment variable is required');
  }
  return secret;
}

function signValue(value: string): string {
  const secret = getCookieSecret();
  const sig = crypto.createHmac('sha256', secret).update(value).digest('hex');
  return `${value}.${sig}`;
}

function verifySignedValue(signed: string): string | null {
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const secret = getCookieSecret();
  const expected = crypto.createHmac('sha256', secret).update(value).digest('hex');
  // Use timing-safe compare
  if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return value;
  }
  return null;
}

export interface SessionCookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  path?: string;
  domain?: string;
}

/**
 * Create a secure session cookie header
 */
export function createSecureSessionCookie(
  sessionToken: string,
  expiresAt: Date,
  options: SessionCookieOptions = {}
): string {
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Sign the token before storing in cookie so client-side tampering can be detected.
  const signed = signValue(sessionToken);

  const cookieOptions = {
    httpOnly: options.httpOnly ?? true,
    secure: options.secure ?? isProduction,
    sameSite: options.sameSite ?? 'lax' as const,
    path: options.path ?? '/',
    domain: options.domain,
    expires: expiresAt,
    // Add max-age as fallback (in seconds)
    maxAge: Math.floor((expiresAt.getTime() - Date.now()) / 1000),
  };

  return serialize(SESSION_COOKIE_NAME, signed, cookieOptions);
}

/**
 * Create a cookie header to clear the session cookie
 */
export function clearSessionCookie(options: SessionCookieOptions = {}): string {
  const isProduction = process.env.NODE_ENV === 'production';
  
  const cookieOptions = {
    httpOnly: options.httpOnly ?? true,
    secure: options.secure ?? isProduction,
    sameSite: options.sameSite ?? 'lax' as const,
    path: options.path ?? '/',
    domain: options.domain,
    expires: new Date(0), // Expire immediately
    maxAge: 0,
  };

  return serialize(SESSION_COOKIE_NAME, '', cookieOptions);
}

// helper used by server-side cookie parsing middleware to extract the original token
export function extractSessionTokenFromSignedCookie(signedValue?: string | null): string | null {
  if (!signedValue) return null;
  try {
    return verifySignedValue(signedValue) || null;
  } catch (err) {
    return null;
  }
}

/**
 * Get session token from request cookies
 */
export function getSessionTokenFromCookies(cookies: RequestCookies): string | null {
  try {
    const sessionCookie = cookies.get(SESSION_COOKIE_NAME);
    if (!sessionCookie?.value) return null;
    
    // Extract and verify the signed token
    return extractSessionTokenFromSignedCookie(sessionCookie.value);
  } catch (error) {
    return null;
  }
}

/**
 * Validate session cookie format
 */
export function validateSessionCookie(cookieValue: string): boolean {
  if (!cookieValue || typeof cookieValue !== 'string') {
    return false;
  }

  // Session tokens should be hex strings of specific length (64 characters)
  const sessionTokenPattern = /^[0-9a-f]{64}$/i;
  return sessionTokenPattern.test(cookieValue);
}

/**
 * Parse session cookie with validation
 */
export function parseSessionCookie(cookies: RequestCookies): {
  token: string | null;
  isValid: boolean;
} {
  const token = getSessionTokenFromCookies(cookies);
  
  if (!token) {
    return { token: null, isValid: false };
  }

  const isValid = validateSessionCookie(token);
  
  return {
    token: isValid ? token : null,
    isValid,
  };
}

/**
 * Get cookie options for the current environment
 */
export function getDefaultCookieOptions(): SessionCookieOptions {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    // Don't set domain in development to allow localhost
    domain: isProduction ? undefined : undefined,
  };
}

/**
 * Create a temporary cookie for development/testing
 */
export function createTestCookie(
  name: string,
  value: string,
  maxAgeSeconds: number = 3600
): string {
  const options = {
    httpOnly: false, // Allow JS access for testing
    secure: false, // Allow HTTP for testing
    sameSite: 'lax' as const,
    path: '/',
    maxAge: maxAgeSeconds,
  };

  return serialize(name, value, options);
}

/**
 * Extract cookie value from Set-Cookie header
 */
export function extractCookieValue(setCookieHeader: string, cookieName: string): string | null {
  try {
    // Parse the Set-Cookie header
    const parts = setCookieHeader.split(';')[0]; // Get the name=value part
    const [name, value] = parts.split('=');
    
    if (name?.trim() === cookieName) {
      return decodeURIComponent(value?.trim() || '');
    }
    
    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Check if cookie is expired
 */
export function isCookieExpired(expiresAt: Date): boolean {
  return new Date() > expiresAt;
}

/**
 * Get cookie expiration from Max-Age or Expires
 */
export function getCookieExpiration(setCookieHeader: string): Date | null {
  try {
    const parts = setCookieHeader.split(';');
    
    // Look for Max-Age first
    for (const part of parts) {
      const trimmed = part.trim().toLowerCase();
      if (trimmed.startsWith('max-age=')) {
        const maxAge = parseInt(trimmed.split('=')[1]);
        if (!isNaN(maxAge)) {
          return new Date(Date.now() + maxAge * 1000);
        }
      }
    }
    
    // Look for Expires
    for (const part of parts) {
      const trimmed = part.trim().toLowerCase();
      if (trimmed.startsWith('expires=')) {
        const expiresStr = trimmed.split('=')[1];
        const expiresDate = new Date(expiresStr);
        if (!isNaN(expiresDate.getTime())) {
          return expiresDate;
        }
      }
    }
    
    return null;
  } catch (error) {
    return null;
  }
}
