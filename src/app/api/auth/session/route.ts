// src/app/api/auth/session/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { SessionService } from '@/services/session-service';
import { handleApiError } from '@/lib/errors/error-handler';
import { generateCorrelationId } from '@/lib/utils/correlation-id';
import { initializeDatabase } from '@/lib/config/database';
import { Logger } from '@/lib/config/logger';
import { getSessionTokenFromCookies, clearSessionCookie, createSecureSessionCookie } from '@/lib/utils/cookies';
import { AuthError, ErrorCode } from '@/lib/errors/error-codes';
import { setCSPHeaders } from '@/lib/utils/csp';

export async function GET(request: NextRequest) {
  // Get correlation ID from middleware or generate new one
  const correlationId = request.headers.get('X-Correlation-ID') || generateCorrelationId();
  const logger = new Logger(correlationId);
  
  try {
    logger.debug('Session validation request received', {
      method: request.method,
      url: request.url,
      userAgent: request.headers.get('user-agent'),
    });

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

    // Ensure database connection is available
    await initializeDatabase();
    
    // Create session service instance with correlation ID
    const sessionService = SessionService.create(correlationId);

    // Validate session
    const sessionData = await sessionService.validateSession(sessionToken);
    
    if (!sessionData || !sessionData.isValid) {
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

    // Check if session should be extended
    let updatedSession = sessionData.session;
    if (sessionData.shouldExtend) {
      logger.debug('Extending session due to threshold', {
        sessionId: sessionData.session.id,
        timeUntilExpiry: sessionData.session.timeUntilExpiry,
      });
      
      try {
        updatedSession = await sessionService.extendSession(sessionData.session.id);
      } catch (error) {
        // Log but don't fail the request if extension fails
        logger.warn('Failed to extend session', {
          sessionId: sessionData.session.id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    logger.debug('Session validated successfully', {
      userId: sessionData.user.id,
      sessionId: sessionData.session.id,
      isActive: sessionData.session.isActive,
      expiresAt: updatedSession.expiresAt,
      wasExtended: updatedSession.id !== sessionData.session.id,
    });

    // Return user and session data
    const responseData = {
      success: true,
      data: {
        user: {
          id: sessionData.user.id,
          email: sessionData.user.email,
          isVerified: sessionData.user.isVerified,
          profile: sessionData.user.profile ? {
            id: sessionData.user.profile.id,
            firstName: sessionData.user.profile.firstName,
            lastName: sessionData.user.profile.lastName,
            fullName: sessionData.user.profile.fullName,
            initials: sessionData.user.profile.initials,
          } : null,
        },
        session: {
          id: updatedSession.id,
          expiresAt: updatedSession.expiresAt.toISOString(),
          lastAccessedAt: updatedSession.lastAccessedAt?.toISOString(),
          isActive: updatedSession.isActive,
        },
      },
    };

    const response = NextResponse.json(responseData);
    
    // Update session cookie if it was extended
    if (sessionData.shouldExtend && updatedSession.expiresAt !== sessionData.session.expiresAt) {
      const cookieHeader = createSecureSessionCookie(sessionToken, updatedSession.expiresAt);
      response.headers.set('Set-Cookie', cookieHeader);
      
      logger.debug('Session cookie updated with new expiration', {
        sessionId: updatedSession.id,
        newExpiresAt: updatedSession.expiresAt,
      });
    }
    
    // Add correlation ID header
    response.headers.set('X-Correlation-ID', correlationId);
    
    // Add security headers including CSP
    setCSPHeaders(response.headers, correlationId);
    
    return response;

  } catch (error) {
    logger.error('Session validation failed', {
      correlationId,
      error: error instanceof Error ? {
        message: error.message,
        name: error.name,
        stack: error.stack,
      } : { message: String(error) },
    });

    // Clear session cookie on validation failure
    const errorResponse = handleApiError(error, correlationId);
    
    if (error instanceof AuthError && 
        (error.code === ErrorCode.SESSION_EXPIRED || error.code === ErrorCode.UNAUTHORIZED)) {
      const clearCookieHeader = clearSessionCookie();
      errorResponse.headers.set('Set-Cookie', clearCookieHeader);
    }
    
    return errorResponse;
  }
}

// Handle unsupported methods
export async function POST() {
  const response = NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'GET' } }
  );
  setCSPHeaders(response.headers);
  return response;
}

export async function PUT() {
  const response = NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'GET' } }
  );
  setCSPHeaders(response.headers);
  return response;
}

export async function DELETE() {
  const response = NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'GET' } }
  );
  setCSPHeaders(response.headers);
  return response;
}
