// src/app/api/auth/verify/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { verifyMagicLinkSchema } from '@/lib/validation/schemas';
import { AuthService } from '@/services/auth-service';
import { handleApiError } from '@/lib/errors/error-handler';
import { generateCorrelationId } from '@/lib/utils/correlation-id';
import { getClientIP } from '@/lib/utils/ip';
import { initializeDatabase } from '@/lib/config/database';
import { Logger } from '@/lib/config/logger';
import { createSecureSessionCookie, clearSessionCookie } from '@/lib/utils/cookies';
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
    logger.info('Magic link verification request received', {
      method: request.method,
      url: request.url,
      userAgent: request.headers.get('user-agent'),
      origin: request.headers.get('origin'),
    });

    // Validate CSRF token (middleware should have caught this, but double-check)
    const headerToken = getCSRFTokenFromHeaders(request.headers);
    const cookieToken = getCSRFTokenFromCookies(request.headers.get('cookie'));
    
    if (!validateCSRFToken(headerToken, cookieToken)) {
      logger.warn('CSRF token validation failed in verify route', {
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

    // Parse and validate request body
    const body = await request.json();
    const validatedData = verifyMagicLinkSchema.parse(body);

    logger.debug('Verification request data validated', {
      tokenLength: validatedData.token.length,
      hasProfile: !!validatedData.profile,
    });

    // Extract client information from middleware headers or fallback
    const ipAddress = request.headers.get('X-Client-IP') || getClientIP(request);
    const userAgent = request.headers.get('user-agent');
    
    // Ensure database connection is available
    await initializeDatabase();
    
    // Create auth service instance with correlation ID
    const authService = AuthService.create(correlationId);

    // Verify magic link and create session
    const result = await authService.verifyMagicLink({
      token: validatedData.token,
      profile: validatedData.profile,
      ipAddress: ipAddress || undefined,
      userAgent: userAgent || undefined,
      // Note: In production, you might want to get geo location from IP
      country: undefined,
      city: undefined,
    });

    logger.info('Magic link verified successfully', {
      userId: result.user.id,
      email: result.user.email,
      isNewUser: result.isNewUser,
      sessionId: result.session.id,
    });

    // Create response with user data
    const responseData = {
      success: true,
      message: result.message,
      data: {
        user: {
          id: result.user.id,
          email: result.user.email,
          isVerified: result.user.isVerified,
          profile: result.user.profile ? {
            id: result.user.profile.id,
            firstName: result.user.profile.firstName,
            lastName: result.user.profile.lastName,
            fullName: result.user.profile.fullName,
            initials: result.user.profile.initials,
          } : null,
        },
        session: {
          id: result.session.id,
          expiresAt: result.session.expiresAt.toISOString(),
        },
        isNewUser: result.isNewUser,
        redirectUrl: result.redirectUrl,
      },
    };

    // Create response
    const response = NextResponse.json(responseData);

    // Set secure session cookie (always signed)
    const sessionToken = (result.session as any).token;
    const sessionCookieHeader = createSecureSessionCookie(sessionToken, result.session.expiresAt);
    
    // Clear CSRF cookie since we're establishing a new session
    const clearCSRFHeader = clearCSRFCookie();
    
    // Set multiple cookies using array syntax
    response.headers.set('Set-Cookie', sessionCookieHeader);
    response.headers.append('Set-Cookie', clearCSRFHeader);

    // Add correlation ID header
    response.headers.set('X-Correlation-ID', correlationId);
    
    // Add security headers including CSP
    setCSPHeaders(response.headers, correlationId);
    
    return response;

  } catch (error) {
    logger.error('Magic link verification request failed', {
      correlationId,
      error: error instanceof Error ? {
        message: error.message,
        name: error.name,
        stack: error.stack,
      } : { message: String(error) },
    });

    // Clear any existing cookies on error
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
