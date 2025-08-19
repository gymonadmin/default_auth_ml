// src/app/api/auth/session/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { handleApiError } from '@/lib/errors/error-handler';
import { generateCorrelationId, getCorrelationIdFromHeaders } from '@/lib/utils/correlation-id';
import { initializeDatabase } from '@/lib/config/database';
import { Logger } from '@/lib/config/logger';
import { getSessionTokenFromCookies, clearSessionCookie } from '@/lib/utils/cookies';
import { AuthError, ErrorCode } from '@/lib/errors/error-codes';

export async function GET(request: NextRequest) {
  const correlationId = getCorrelationIdFromHeaders(request.headers) || generateCorrelationId();
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

    // Initialize database connection
    const dataSource = await initializeDatabase();
    
    // Create auth service instance
    const authService = new AuthService(dataSource, correlationId);

    // Validate session
    const sessionData = await authService.validateSession(sessionToken);
    
    if (!sessionData) {
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

    logger.debug('Session validated successfully', {
      userId: sessionData.user.id,
      sessionId: sessionData.session.id,
      isActive: sessionData.session.isActive,
      expiresAt: sessionData.session.expiresAt,
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
          id: sessionData.session.id,
          expiresAt: sessionData.session.expiresAt.toISOString(),
          lastAccessedAt: sessionData.session.lastAccessedAt?.toISOString(),
          isActive: sessionData.session.isActive,
        },
      },
    };

    const response = NextResponse.json(responseData);
    
    // Add correlation ID header
    response.headers.set('x-correlation-id', correlationId);
    
    // Add security headers
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    
    return response;

  } catch (error) {
    logger.error('Session validation failed', error instanceof Error ? error : new Error(String(error)), {
      correlationId,
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
  return NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'GET' } }
  );
}

export async function PUT() {
  return NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'GET' } }
  );
}

export async function DELETE() {
  return NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'GET' } }
  );
}
