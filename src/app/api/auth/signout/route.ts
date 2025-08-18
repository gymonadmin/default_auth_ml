// src/app/api/auth/signout/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { AuthService } from '@/services/auth-service';
import { handleApiError } from '@/lib/errors/error-handler';
import { generateCorrelationId, getCorrelationIdFromHeaders } from '@/lib/utils/correlation-id';
import { getClientIP } from '@/lib/utils/ip';
import { initializeDatabase } from '@/lib/config/database';
import { Logger } from '@/lib/config/logger';
import { getSessionTokenFromCookies, clearSessionCookie } from '@/lib/utils/cookies';

export async function POST(request: NextRequest) {
  const correlationId = getCorrelationIdFromHeaders(request.headers) || generateCorrelationId();
  const logger = new Logger(correlationId);
  
  try {
    logger.info('Sign out request received', {
      method: request.method,
      url: request.url,
      userAgent: request.headers.get('user-agent'),
      origin: request.headers.get('origin'),
    });

    // Get session token from cookies
    const sessionToken = getSessionTokenFromCookies(request.cookies);
    
    if (!sessionToken) {
      logger.debug('No session token found in cookies');
      
      // Still return success and clear any existing cookies
      const response = NextResponse.json({
        success: true,
        message: 'Signed out successfully',
      });
      
      // Clear session cookie
      const clearCookieHeader = clearSessionCookie();
      response.headers.set('Set-Cookie', clearCookieHeader);
      response.headers.set('x-correlation-id', correlationId);
      
      return response;
    }

    // Extract client information
    const ipAddress = getClientIP(request);
    const userAgent = request.headers.get('user-agent');
    
    // Initialize database connection
    const dataSource = await initializeDatabase();
    
    // Create auth service instance
    const authService = new AuthService(dataSource, correlationId);

    // Sign out user and revoke session
    await authService.signOut(
      sessionToken,
      ipAddress || undefined,
      userAgent || undefined
    );

    logger.info('User signed out successfully', {
      sessionTokenLength: sessionToken.length,
    });

    // Create success response
    const response = NextResponse.json({
      success: true,
      message: 'Signed out successfully',
    });

    // Clear session cookie
    const clearCookieHeader = clearSessionCookie();
    response.headers.set('Set-Cookie', clearCookieHeader);
    
    // Add correlation ID header
    response.headers.set('x-correlation-id', correlationId);
    
    // Add security headers
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    
    return response;

  } catch (error) {
    logger.error('Sign out request failed', error, {
      correlationId,
    });

    // Even on error, clear the session cookie
    const errorResponse = handleApiError(error, correlationId);
    const clearCookieHeader = clearSessionCookie();
    errorResponse.headers.set('Set-Cookie', clearCookieHeader);
    
    return errorResponse;
  }
}

// Handle unsupported methods
export async function GET() {
  return NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'POST' } }
  );
}

export async function PUT() {
  return NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'POST' } }
  );
}

export async function DELETE() {
  return NextResponse.json(
    { success: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } },
    { status: 405, headers: { 'Allow': 'POST' } }
  );
}
