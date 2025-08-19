// src/app/api/auth/send-link/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { sendMagicLinkSchema } from '@/lib/validation/schemas';
import { AuthService } from '@/services/auth-service';
import { handleApiError } from '@/lib/errors/error-handler';
import { generateCorrelationId, getCorrelationIdFromHeaders } from '@/lib/utils/correlation-id';
import { getClientIP } from '@/lib/utils/ip';
import { initializeDatabase } from '@/lib/config/database';
import { Logger } from '@/lib/config/logger';

export async function POST(request: NextRequest) {
  const correlationId = getCorrelationIdFromHeaders(request.headers) || generateCorrelationId();
  const logger = new Logger(correlationId);
  
  try {
    logger.info('Magic link send request received', {
      method: request.method,
      url: request.url,
      userAgent: request.headers.get('user-agent'),
      origin: request.headers.get('origin'),
    });

    // Parse and validate request body
    const body = await request.json();
    const validatedData = sendMagicLinkSchema.parse(body);

    logger.debug('Request data validated', {
      email: validatedData.email,
      hasRedirectUrl: !!validatedData.redirectUrl,
    });

    // Extract client information
    const ipAddress = getClientIP(request);
    const userAgent = request.headers.get('user-agent');
    
    // Initialize database connection
    const dataSource = await initializeDatabase();
    
    // Create auth service instance
    const authService = new AuthService(dataSource, correlationId);

    // Send magic link
    const result = await authService.sendMagicLink({
      email: validatedData.email,
      redirectUrl: validatedData.redirectUrl,
      ipAddress: ipAddress || undefined,
      userAgent: userAgent || undefined,
      // Note: In production, you might want to get geo location from IP
      country: undefined,
      city: undefined,
    });

    logger.info('Magic link sent successfully', {
      email: validatedData.email,
      isNewUser: result.isNewUser,
      success: result.success,
    });

    // Return success response
    const response = NextResponse.json({
      success: true,
      message: result.message,
      data: {
        isNewUser: result.isNewUser,
        requiresProfile: result.requiresProfile,
      },
    });

    // Add correlation ID header
    response.headers.set('x-correlation-id', correlationId);
    
    return response;

  } catch (error) {
   logger.error('Magic link send request failed', error instanceof Error ? error : new Error(String(error)), {
      correlationId,
    });

    return handleApiError(error, correlationId);
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
