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
 * Always generates 43 characters (32 bytes -> base64 -> remove padding)
 */
export function generateMagicLinkToken(): string {
  // Generate 32 random bytes and encode as URL-safe base64
  return randomBytes(32)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, ''); // Remove padding
}

/**
 * Generate a session token (hex encoded)
 * Always generates 64 characters (32 bytes -> hex)
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
 * Validate session token format (hex string, exactly 64 characters)
 */
export function validateSessionTokenFormat(token: string): boolean {
  if (!token || typeof token !== 'string') {
    return false;
  }
  
  // Session tokens are exactly 64 hex characters (32 bytes)
  const sessionTokenPattern = /^[0-9a-f]{64}$/i;
  return sessionTokenPattern.test(token);
}

/**
 * Validate magic link token format (URL-safe base64, exactly 43 characters)
 */
export function validateMagicLinkTokenFormat(token: string): boolean {
  if (!token || typeof token !== 'string') {
    return false;
  }
  
  // Magic link tokens are exactly 43 characters (32 bytes base64 without padding)
  // Contains only URL-safe base64 characters: A-Z, a-z, 0-9, -, _
  const magicLinkTokenPattern = /^[A-Za-z0-9_-]{43}$/;
  return magicLinkTokenPattern.test(token);
}

/**
 * Validate token format (generic hex string validation)
 * @deprecated Use validateSessionTokenFormat or validateMagicLinkTokenFormat instead
 */
export function validateTokenFormat(token: string, expectedLength?: number): boolean {
  if (!token || typeof token !== 'string') {
    return false;
  }
  
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
 * Validate any token type based on format detection
 */
export function validateAnyTokenFormat(token: string): { 
  isValid: boolean; 
  type: 'session' | 'magic-link' | 'unknown';
} {
  if (!token || typeof token !== 'string') {
    return { isValid: false, type: 'unknown' };
  }
  
  // Check if it's a session token (64 hex characters)
  if (validateSessionTokenFormat(token)) {
    return { isValid: true, type: 'session' };
  }
  
  // Check if it's a magic link token (43 base64url characters)
  if (validateMagicLinkTokenFormat(token)) {
    return { isValid: true, type: 'magic-link' };
  }
  
  return { isValid: false, type: 'unknown' };
}

/**
 * Convert base64url to regular base64
 */
export function base64urlToBase64(base64url: string): string {
  // Replace URL-safe characters
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '=';
  }
  
  return base64;
}

/**
 * Convert regular base64 to base64url
 */
export function base64ToBase64url(base64: string): string {
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decode magic link token to raw bytes (for validation purposes)
 */
export function decodeMagicLinkToken(token: string): Buffer | null {
  try {
    if (!validateMagicLinkTokenFormat(token)) {
      return null;
    }
    
    const base64 = base64urlToBase64(token);
    return Buffer.from(base64, 'base64');
  } catch {
    return null;
  }
}

/**
 * Decode session token to raw bytes (for validation purposes)
 */
export function decodeSessionToken(token: string): Buffer | null {
  try {
    if (!validateSessionTokenFormat(token)) {
      return null;
    }
    
    return Buffer.from(token, 'hex');
  } catch {
    return null;
  }
}

/**
 * Check if token has sufficient entropy (at least 128 bits)
 */
export function hasValidEntropy(token: string): boolean {
  const validation = validateAnyTokenFormat(token);
  
  if (!validation.isValid) {
    return false;
  }
  
  let bytes: Buffer | null = null;
  
  if (validation.type === 'session') {
    bytes = decodeSessionToken(token);
  } else if (validation.type === 'magic-link') {
    bytes = decodeMagicLinkToken(token);
  }
  
  // Check if we have at least 16 bytes (128 bits) of entropy
  return bytes !== null && bytes.length >= 16;
}

/**
 * Sanitize token for logging (show only first/last few characters)
 */
export function sanitizeTokenForLogging(token: string, showChars: number = 8): string {
  if (!token || typeof token !== 'string') {
    return '***';
  }
  
  if (token.length <= showChars * 2) {
    return '*'.repeat(token.length);
  }
  
  const start = token.substring(0, showChars);
  const end = token.substring(token.length - showChars);
  const middle = '*'.repeat(Math.max(0, token.length - showChars * 2));
  
  return `${start}${middle}${end}`;
}

/**
 * Token validation constants
 */
export const TOKEN_VALIDATION = {
  SESSION_TOKEN_LENGTH: 64,
  MAGIC_LINK_TOKEN_LENGTH: 43,
  MIN_ENTROPY_BYTES: 16,
  SESSION_TOKEN_PATTERN: /^[0-9a-f]{64}$/i,
  MAGIC_LINK_TOKEN_PATTERN: /^[A-Za-z0-9_-]{43}$/,
} as const;
