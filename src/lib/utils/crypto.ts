// src/lib/utils/crypto.ts
import { randomBytes, createHash, timingSafeEqual } from 'crypto';

/**
 * Generate a cryptographically secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Generate a magic link token (URL-safe base64)
 */
export function generateMagicLinkToken(): string {
  // Generate 32 random bytes and encode as URL-safe base64
  return randomBytes(32)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a session token (hex encoded)
 */
export function generateSessionToken(): string {
  return generateSecureToken(32); // 32 bytes = 64 hex characters
}

/**
 * Hash a token using SHA-256
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Compare two tokens in constant time to prevent timing attacks
 */
export function compareTokens(token1: string, token2: string): boolean {
  if (token1.length !== token2.length) {
    return false;
  }
  
  try {
    const buffer1 = Buffer.from(token1, 'utf8');
    const buffer2 = Buffer.from(token2, 'utf8');
    return timingSafeEqual(buffer1, buffer2);
  } catch {
    return false;
  }
}

/**
 * Compare a plain token with its hash
 */
export function verifyTokenHash(plainToken: string, hashedToken: string): boolean {
  const hashedPlainToken = hashToken(plainToken);
  return compareTokens(hashedPlainToken, hashedToken);
}

/**
 * Generate a random verification code (numeric)
 */
export function generateVerificationCode(length: number = 6): string {
  const digits = '0123456789';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = randomBytes(1)[0] % digits.length;
    result += digits[randomIndex];
  }
  
  return result;
}

/**
 * Generate a cryptographically secure random string
 */
export function generateRandomString(length: number, charset?: string): string {
  const defaultCharset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const chars = charset || defaultCharset;
  let result = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = randomBytes(1)[0] % chars.length;
    result += chars[randomIndex];
  }
  
  return result;
}

/**
 * Validate token format (hex string of expected length)
 */
export function validateTokenFormat(token: string, expectedLength?: number): boolean {
  const hexPattern = /^[0-9a-f]+$/i;
  
  if (!hexPattern.test(token)) {
    return false;
  }
  
  if (expectedLength && token.length !== expectedLength) {
    return false;
  }
  
  return true;
}

/**
 * Validate magic link token format (URL-safe base64)
 */
export function validateMagicLinkTokenFormat(token: string): boolean {
  const base64UrlPattern = /^[A-Za-z0-9_-]+$/;
  return base64UrlPattern.test(token) && token.length >= 32;
}
