// src/lib/errors/error-handler.ts
import { NextResponse } from 'next/server';
import { ZodError } from 'zod';
import { AppError, ErrorCode, ValidationError, DatabaseError, ServiceError } from './error-codes';
import { Logger } from '@/lib/config/logger';

export interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
    correlationId?: string;
  };
}

export class ErrorHandler {
  private logger: Logger;

  constructor(correlationId?: string) {
    this.logger = new Logger(correlationId);
  }

  /**
   * Handle and format errors for API responses
   */
  public handleError(error: unknown): NextResponse<ErrorResponse> {
    const appError = this.normalizeError(error);
    
    // Log the error
    this.logger.error(
      `API Error: ${appError.code}`,
      {
        code: appError.code,
        message: appError.message,
        statusCode: appError.statusCode,
        details: appError.details,
        stack: appError.stack,
      }
    );

    // Create response
    const response: ErrorResponse = {
      success: false,
      error: {
        code: appError.code,
        message: appError.userMessage || appError.message,
        correlationId: appError.correlationId,
        ...(process.env.NODE_ENV === 'development' && { details: appError.details }),
      },
    };

    return NextResponse.json(response, { status: appError.statusCode });
  }

  /**
   * Normalize different error types to AppError
   */
  private normalizeError(error: unknown): AppError {
    // Already an AppError
    if (this.isAppError(error)) {
      return error;
    }

    // Zod validation error
    if (error instanceof ZodError) {
      return new ValidationError(
        'Validation failed',
        { issues: error.issues },
        this.logger['correlationId'],
        'Please check your input and try again.'
      );
    }

    // Database/TypeORM errors
    if (this.isDatabaseError(error)) {
      return this.handleDatabaseError(error as Error);
    }

    // Generic Error
    if (error instanceof Error) {
      this.logger.error('Unhandled error', error);
      return new ServiceError(
        ErrorCode.INTERNAL_SERVER_ERROR,
        error.message,
        500,
        { originalError: error.name },
        this.logger['correlationId']
      );
    }

    // Unknown error type
    this.logger.error('Unknown error type', { error });
    return new ServiceError(
      ErrorCode.INTERNAL_SERVER_ERROR,
      'An unexpected error occurred',
      500,
      undefined,
      this.logger['correlationId']
    );
  }

  /**
   * Check if error is an AppError
   */
  private isAppError(error: unknown): error is AppError {
    return (
      error instanceof Error &&
      'code' in error &&
      'statusCode' in error
    );
  }

  /**
   * Check if error is a database-related error
   */
  private isDatabaseError(error: unknown): boolean {
    if (!(error instanceof Error)) return false;
    
    const dbErrorNames = [
      'QueryFailedError',
      'EntityNotFoundError',
      'CannotCreateEntityIdMapError',
      'OptimisticLockVersionMismatchError',
      'OptimisticLockCannotBeUsedError',
      'NoVersionOrUpdateDateColumnError',
      'OptimisticLockVersionMismatchError',
    ];

    return dbErrorNames.includes(error.constructor.name) || 
           error.message.includes('database') ||
           error.message.includes('relation') ||
           error.message.includes('constraint');
  }

  /**
   * Handle database-specific errors
   */
  private handleDatabaseError(error: Error): DatabaseError {
    // PostgreSQL error codes
    if ('code' in error) {
      const pgCode = (error as any).code;
      
      switch (pgCode) {
        case '23505': // unique_violation
          return new DatabaseError(
            ErrorCode.DUPLICATE_RECORD,
            'Record already exists',
            { pgCode },
            this.logger['correlationId']
          );
        
        case '23503': // foreign_key_violation
          return new DatabaseError(
            ErrorCode.CONSTRAINT_VIOLATION,
            'Foreign key constraint violation',
            { pgCode },
            this.logger['correlationId']
          );
        
        case '23514': // check_violation
          return new DatabaseError(
            ErrorCode.CONSTRAINT_VIOLATION,
            'Check constraint violation',
            { pgCode },
            this.logger['correlationId']
          );
      }
    }

    // TypeORM specific errors
    if (error.constructor.name === 'EntityNotFoundError') {
      return new DatabaseError(
        ErrorCode.RECORD_NOT_FOUND,
        'Record not found',
        { originalError: error.constructor.name },
        this.logger['correlationId']
      );
    }

    // Generic database error
    return new DatabaseError(
      ErrorCode.DATABASE_ERROR,
      error.message,
      { originalError: error.constructor.name },
      this.logger['correlationId']
    );
  }

  /**
   * Create error handler for API routes
   */
  public static forRequest(correlationId?: string) {
    return new ErrorHandler(correlationId);
  }
}

/**
 * Utility function for handling errors in API routes
 */
export function handleApiError(error: unknown, correlationId?: string): NextResponse<ErrorResponse> {
  return ErrorHandler.forRequest(correlationId).handleError(error);
}
