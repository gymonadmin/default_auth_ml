// src/app/api/auth/delete-account/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { handleApiError } from '@/lib/errors/error-handler';
import { generateCorrelationId } from '@/lib/utils/correlation-id';
import { getClientIP } from '@/lib/utils/ip';
import { initializeDatabase } from '@/lib/config/database';
import { Logger } from '@/lib/config/logger';
import { getSessionTokenFromCookies, clearSessionCookie } from '@/lib/utils/cookies';
import { setCSPHeaders } from '@/lib/utils/csp';
import { 
  validateCSRFToken, 
  getCSRFTokenFromHeaders, 
  getCSRFTokenFromCookies,
  clearCSRFCookie
} from '@/lib/utils/csrf';
import { AuthError, ErrorCode } from '@/lib/errors/error-codes';

export async function POST(request: NextRequest) {
  // Get correlation ID from middleware or generate new one
  const correlationId = request.headers.get('X-Correlation-ID') || generateCorrelationId();
  const logger = new Logger(correlationId);
  
  try {
    logger.info('Delete account request received', {
      method: request.method,
      url: request.url,
      userAgent: request.headers.get('user-agent'),
      origin: request.headers.get('origin'),
    });

    // Validate CSRF token (middleware should have caught this, but double-check)
    const headerToken = getCSRFTokenFromHeaders(request.headers);
    const cookieToken = getCSRFTokenFromCookies(request.headers.get('cookie'));
    
    if (!validateCSRFToken(headerToken, cookieToken)) {
      logger.warn('CSRF token validation failed in delete account route', {
        hasHeaderToken: !!headerToken,
        hasCookieToken: !!cookieToken,
        correlationId,
      });
      
      throw new AuthError(
        ErrorCode.FORBIDDEN,
        'Invalid CSRF token',
        403,
        undefined,
        correlationId,
        'Security validation failed. Please refresh and try again.'
      );
    }

    // Get session token from cookies
    const sessionToken = getSessionTokenFromCookies(request.cookies);
    
    if (!sessionToken) {
      logger.debug('No session token found in cookies');
      
      throw new AuthError(
        ErrorCode.UNAUTHORIZED,
        'No session found',
        401,
        undefined,
        correlationId,
        'Please sign in to continue'
      );
    }

    // Extract client information from middleware headers or fallback  
    const ipAddress = request.headers.get('X-Client-IP') || getClientIP(request);
    const userAgent = request.headers.get('user-agent');
    
    // Ensure database connection is available
    await initializeDatabase();
    
    // Create auth service instance with correlation ID
    const authService = AuthService.create(correlationId);

    // Validate session first to get user ID
    const sessionData = await authService.validateSession(sessionToken);
    
    if (!sessionData || !sessionData.user) {
      logger.debug('Invalid or expired session token');
      
      throw new AuthError(
        ErrorCode.SESSION_EXPIRED,
        'Session expired or invalid',
        401,
        undefined,
        correlationId,
        'Your session has expired. Please sign in again'
      );
    }

    // Delete the account
    const result = await authService.deleteAccount(sessionData.user.id, {
      ipAddress: ipAddress || undefined,
      userAgent: userAgent || undefined,
      country: undefined,
      city: undefined,
    });

    logger.info('Account deleted successfully', {
      userId: sessionData.user.id,
      email: sessionData.user.email,
      ipAddress,
      userAgent,
    });

    // Create success response
    const response = NextResponse.json({
      success: true,
      message: result.message,
    });

    // Clear both session and CSRF cookies since account is deleted
    const clearSessionCookieHeader = clearSessionCookie();
    const clearCSRFHeader = clearCSRFCookie();
    
    response.headers.set('Set-Cookie', clearSessionCookieHeader);
    response.headers.append('Set-Cookie', clearCSRFHeader);
    
    // Add correlation ID header
    response.headers.set('X-Correlation-ID', correlationId);
    
    // Add security headers including CSP
    setCSPHeaders(response.headers, correlationId);
    
    return response;

  } catch (error) {
    logger.error('Delete account request failed', {
      correlationId,
      error: error instanceof Error ? {
        message: error.message,
        name: error.name,
        stack: error.stack,
      } : { message: String(error) },
    });

    // Clear both cookies on error (account might have been deleted)
    const errorResponse = handleApiError(error, correlationId);
    const clearSessionCookieHeader = clearSessionCookie();
    const clearCSRFHeader = clearCSRFCookie();
    
    errorResponse.headers.set('Set-Cookie', clearSessionCookieHeader);
    errorResponse.headers.append('Set-Cookie', clearCSRFHeader);
    
    return errorResponse;
  }
}

// Handle unsupported methods
export async function GET() {
  const response = NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'POST' } }
  );
  setCSPHeaders(response.headers);
  return response;
}

export async function PUT() {
  const response = NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'POST' } }
  );
  setCSPHeaders(response.headers);
  return response;
}

export async function DELETE() {
  const response = NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'POST' } }
  );
  setCSPHeaders(response.headers);
  return response;
}
