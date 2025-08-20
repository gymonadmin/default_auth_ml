// src/lib/utils/csp.ts

/**
 * Generate a cryptographically secure nonce for CSP
 */
export function generateCSPNonce(): string {
  // Use Web Crypto API when available (Edge Runtime, browsers)
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    
    // Convert to base64 using btoa in Edge/browser environment
    if (typeof btoa !== 'undefined') {
      // Convert Uint8Array to string without spread operator
      let binaryString = '';
      for (let i = 0; i < bytes.length; i++) {
        binaryString += String.fromCharCode(bytes[i]);
      }
      return btoa(binaryString);
    }
    
    // Fallback manual base64 encoding if btoa not available
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i];
      const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      
      const bitmap = (a << 16) | (b << 8) | c;
      
      result += chars.charAt((bitmap >> 18) & 63);
      result += chars.charAt((bitmap >> 12) & 63);
      result += i + 1 < bytes.length ? chars.charAt((bitmap >> 6) & 63) : '=';
      result += i + 2 < bytes.length ? chars.charAt(bitmap & 63) : '=';
    }
    return result;
  }
  
  // Node.js fallback (avoid static import for Edge Runtime compatibility)
  if (typeof require !== 'undefined') {
    try {
      const crypto = require('crypto');
      return crypto.randomBytes(16).toString('base64');
    } catch (error) {
      // If require fails, fall back to a less secure but functional approach
      console.warn('Crypto not available, using fallback nonce generation');
    }
  }
  
  // Ultimate fallback for environments without crypto (not recommended for production)
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let result = '';
  for (let i = 0; i < 24; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Build CSP header value with nonces
 */
export function buildCSPHeader(nonce: string): string {
  const isProduction = process.env.NODE_ENV === 'production';
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://docsbox.ro';
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || [appUrl];
  
  // Base directives that apply to all environments
  const baseDirectives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data: https:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ];

  // Connect-src: allow API calls to same origin and configured origins
  const connectSrc = [
    "'self'",
    ...allowedOrigins
  ].join(' ');
  
  baseDirectives.push(`connect-src ${connectSrc}`);

  // Development-specific directives
  if (!isProduction) {
    // Allow webpack HMR and Next.js dev features
    const devScriptSrc = `script-src 'self' 'nonce-${nonce}' 'unsafe-eval'`;
    const devConnectSrc = `connect-src ${connectSrc} ws: wss:`;
    
    // Replace the production directives with dev versions
    const devDirectives = baseDirectives.map(directive => {
      if (directive.startsWith('script-src')) return devScriptSrc;
      if (directive.startsWith('connect-src')) return devConnectSrc;
      return directive;
    });
    
    return devDirectives.join('; ');
  }

  return baseDirectives.join('; ');
}

/**
 * CSP middleware for Next.js API routes and pages
 */
export function setCSPHeaders(headers: Headers, correlationId?: string, providedNonce?: string): void {
  const cspNonce = providedNonce || generateCSPNonce();
  headers.set('Content-Security-Policy', buildCSPHeader(cspNonce));
  
  // Set nonce in a custom header for client access if needed
  headers.set('X-CSP-Nonce', cspNonce);
  
  // Add correlation ID if provided
  if (correlationId) {
    headers.set('X-Correlation-ID', correlationId);
  }
}

/**
 * Validate nonce format
 */
export function validateNonce(nonce: string): boolean {
  // Base64 string, 16 bytes = 24 characters when base64 encoded (with potential padding)
  const nonceRegex = /^[A-Za-z0-9+/]{21,24}={0,2}$/;
  return nonceRegex.test(nonce);
}
