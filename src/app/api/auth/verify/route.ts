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
    
    // Initialize database connection
    const dataSource = await initializeDatabase();
    
    // Create auth service instance
    const authService = new AuthService(dataSource, correlationId);

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

    // Set secure session cookie
    const sessionToken = (result.session as any).token;
    const cookieHeader = createSecureSessionCookie(sessionToken, result.session.expiresAt);
    response.headers.set('Set-Cookie', cookieHeader);

    // Add correlation ID header
    response.headers.set('X-Correlation-ID', correlationId);
    
    // Add security headers including CSP
    setCSPHeaders(response.headers, correlationId);
    
    return response;

  } catch (error) {
    logger.error('Magic link verification request failed', error instanceof Error ? error : new Error(String(error)), {
      correlationId,
    });

    // Clear any existing session cookie on error
    const errorResponse = handleApiError(error, correlationId);
    const clearCookieHeader = clearSessionCookie();
    errorResponse.headers.set('Set-Cookie', clearCookieHeader);
    
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
