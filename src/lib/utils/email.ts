// src/lib/utils/email.ts
import { ValidationError, ErrorCode } from '@/lib/errors/error-codes';

/**
 * Validate email address format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Normalize email address (lowercase and trim)
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Extract domain from email address
 */
export function extractEmailDomain(email: string): string {
  const normalizedEmail = normalizeEmail(email);
  const parts = normalizedEmail.split('@');
  
  if (parts.length !== 2) {
    throw new ValidationError(
      'Invalid email format',
      { email },
      undefined,
      'Please enter a valid email address'
    );
  }
  
  return parts[1];
}

/**
 * Check if email domain is disposable/temporary
 */
export function isDisposableEmailDomain(domain: string): boolean {
  const disposableDomains = [
    '10minutemail.com',
    'guerrillamail.com',
    'mailinator.com',
    'tempmail.org',
    'throwaway.email',
    'temp-mail.org',
    'maildrop.cc',
    'getairmail.com',
    'sharklasers.com',
    'yopmail.com',
  ];
  
  return disposableDomains.includes(domain.toLowerCase());
}

/**
 * Validate email for business use (reject disposable emails)
 */
export function validateBusinessEmail(email: string): void {
  const normalizedEmail = normalizeEmail(email);
  
  if (!isValidEmail(normalizedEmail)) {
    throw new ValidationError(
      'Invalid email format',
      { email: normalizedEmail },
      undefined,
      'Please enter a valid email address'
    );
  }
  
  const domain = extractEmailDomain(normalizedEmail);
  
  if (isDisposableEmailDomain(domain)) {
    throw new ValidationError(
      'Disposable email addresses are not allowed',
      { email: normalizedEmail, domain },
      undefined,
      'Please use a permanent email address'
    );
  }
}

/**
 * Generate magic link URL
 */
export function generateMagicLinkUrl(
  baseUrl: string,
  token: string,
  redirectUrl?: string
): string {
  const url = new URL('/auth/verify', baseUrl);
  url.searchParams.set('token', token);
  
  if (redirectUrl) {
    // Validate redirect URL is from same origin or allowed domain
    try {
      const redirectUrlObj = new URL(redirectUrl);
      const baseUrlObj = new URL(baseUrl);
      
      // Allow same origin redirects
      if (redirectUrlObj.origin === baseUrlObj.origin) {
        url.searchParams.set('redirect', redirectUrl);
      } else {
        // Check if redirect domain is in allowed list
        const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
        const isAllowed = allowedOrigins.some(origin => 
          redirectUrlObj.origin === origin.trim()
        );
        
        if (isAllowed) {
          url.searchParams.set('redirect', redirectUrl);
        }
      }
    } catch (error) {
      // Invalid redirect URL, ignore it
    }
  }
  
  return url.toString();
}

/**
 * Validate magic link URL format
 */
export function validateMagicLinkUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    
    // Must have token parameter
    const token = urlObj.searchParams.get('token');
    if (!token || token.length < 32) {
      return false;
    }
    
    // Must be HTTPS in production
    if (process.env.NODE_ENV === 'production' && urlObj.protocol !== 'https:') {
      return false;
    }
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract token from magic link URL
 */
export function extractTokenFromMagicLink(url: string): string | null {
  try {
    const urlObj = new URL(url);
    return urlObj.searchParams.get('token');
  } catch {
    return null;
  }
}

/**
 * Extract redirect URL from magic link
 */
export function extractRedirectFromMagicLink(url: string): string | null {
  try {
    const urlObj = new URL(url);
    const redirect = urlObj.searchParams.get('redirect');
    
    if (redirect && validateRedirectUrl(redirect)) {
      return redirect;
    }
    
    return null;
  } catch {
    return null;
  }
}

/**
 * Validate redirect URL is safe
 */
export function validateRedirectUrl(redirectUrl: string): boolean {
  try {
    const url = new URL(redirectUrl);
    
    // Must be HTTPS in production
    if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
      return false;
    }
    
    // Check against allowed origins
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    const isAllowed = allowedOrigins.some(origin => 
      url.origin === origin.trim()
    );
    
    return isAllowed;
  } catch {
    return false;
  }
}

/**
 * Mask email for logging (keep first 2 chars and domain)
 */
export function maskEmailForLogging(email: string): string {
  const [local, domain] = email.split('@');
  
  if (!local || !domain) {
    return '***@***.***';
  }
  
  const maskedLocal = local.length > 2 
    ? local.substring(0, 2) + '*'.repeat(local.length - 2)
    : local;
    
  return `${maskedLocal}@${domain}`;
}

/**
 * Get email provider from domain
 */
export function getEmailProvider(email: string): string {
  const domain = extractEmailDomain(email).toLowerCase();
  
  const providers: Record<string, string> = {
    'gmail.com': 'Gmail',
    'yahoo.com': 'Yahoo',
    'outlook.com': 'Outlook',
    'hotmail.com': 'Hotmail',
    'icloud.com': 'iCloud',
    'protonmail.com': 'ProtonMail',
    'aol.com': 'AOL',
  };
  
  return providers[domain] || 'Other';
}
