// src/lib/errors/error-codes.ts

export enum ErrorCode {
  // Authentication errors
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  INVALID_TOKEN = 'INVALID_TOKEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_ALREADY_USED = 'TOKEN_ALREADY_USED',
  ACCOUNT_NOT_VERIFIED = 'ACCOUNT_NOT_VERIFIED',
  ACCOUNT_DELETED = 'ACCOUNT_DELETED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_NOT_FOUND = 'SESSION_NOT_FOUND',
  
  // Validation errors
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  INVALID_EMAIL = 'INVALID_EMAIL',
  INVALID_INPUT = 'INVALID_INPUT',
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  INVALID_FORMAT = 'INVALID_FORMAT',
  FIELD_TOO_LONG = 'FIELD_TOO_LONG',
  FIELD_TOO_SHORT = 'FIELD_TOO_SHORT',
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  TOO_MANY_REQUESTS = 'TOO_MANY_REQUESTS',
  
  // Database errors
  DATABASE_ERROR = 'DATABASE_ERROR',
  RECORD_NOT_FOUND = 'RECORD_NOT_FOUND',
  DUPLICATE_RECORD = 'DUPLICATE_RECORD',
  CONSTRAINT_VIOLATION = 'CONSTRAINT_VIOLATION',
  CONNECTION_ERROR = 'CONNECTION_ERROR',
  TRANSACTION_ERROR = 'TRANSACTION_ERROR',
  QUERY_ERROR = 'QUERY_ERROR',
  
  // External service errors
  EMAIL_SERVICE_ERROR = 'EMAIL_SERVICE_ERROR',
  REDIS_ERROR = 'REDIS_ERROR',
  
  // Server errors
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  CONFIGURATION_ERROR = 'CONFIGURATION_ERROR',
  
  // Security errors
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  
  // Operation errors
  OPERATION_FAILED = 'OPERATION_FAILED',
  RESOURCE_CONFLICT = 'RESOURCE_CONFLICT',
  RESOURCE_LOCKED = 'RESOURCE_LOCKED',
  OPERATION_TIMEOUT = 'OPERATION_TIMEOUT',
}

export interface AppError extends Error {
  code: ErrorCode;
  statusCode: number;
  details?: Record<string, any>;
  correlationId?: string;
  userMessage?: string;
}

export class AuthError extends Error implements AppError {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, any>;
  public readonly correlationId?: string;
  public readonly userMessage?: string;

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 401,
    details?: Record<string, any>,
    correlationId?: string,
    userMessage?: string
  ) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.correlationId = correlationId;
    this.userMessage = userMessage;
  }
}

export class ValidationError extends Error implements AppError {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, any>;
  public readonly correlationId?: string;
  public readonly userMessage?: string;

  constructor(
    message: string,
    details?: Record<string, any>,
    correlationId?: string,
    userMessage?: string
  ) {
    super(message);
    this.name = 'ValidationError';
    this.code = ErrorCode.VALIDATION_ERROR;
    this.statusCode = 400;
    this.details = details;
    this.correlationId = correlationId;
    this.userMessage = userMessage;
  }
}

export class DatabaseError extends Error implements AppError {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, any>;
  public readonly correlationId?: string;
  public readonly userMessage?: string;

  constructor(
    code: ErrorCode,
    message: string,
    details?: Record<string, any>,
    correlationId?: string
  ) {
    super(message);
    this.name = 'DatabaseError';
    this.code = code;
    this.statusCode = 500;
    this.details = details;
    this.correlationId = correlationId;
    this.userMessage = 'A database error occurred. Please try again later.';
  }
}

export class RateLimitError extends Error implements AppError {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, any>;
  public readonly correlationId?: string;
  public readonly userMessage?: string;

  constructor(
    message: string,
    details?: Record<string, any>,
    correlationId?: string
  ) {
    super(message);
    this.name = 'RateLimitError';
    this.code = ErrorCode.RATE_LIMIT_EXCEEDED;
    this.statusCode = 429;
    this.details = details;
    this.correlationId = correlationId;
    this.userMessage = 'Too many requests. Please wait before trying again.';
  }
}

export class ServiceError extends Error implements AppError {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, any>;
  public readonly correlationId?: string;
  public readonly userMessage?: string;

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 500,
    details?: Record<string, any>,
    correlationId?: string
  ) {
    super(message);
    this.name = 'ServiceError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.correlationId = correlationId;
    this.userMessage = 'A service error occurred. Please try again later.';
  }
}

/**
 * Helper function to determine the appropriate DatabaseError code from database-specific errors
 */
export function mapDatabaseErrorCode(error: any): ErrorCode {
  // PostgreSQL error codes
  if (error && typeof error === 'object' && 'code' in error) {
    switch (error.code) {
      case '23505': // unique_violation
        return ErrorCode.DUPLICATE_RECORD;
      case '23503': // foreign_key_violation
      case '23514': // check_violation
      case '23502': // not_null_violation
        return ErrorCode.CONSTRAINT_VIOLATION;
      case '08000': // connection_exception
      case '08003': // connection_does_not_exist
      case '08006': // connection_failure
        return ErrorCode.CONNECTION_ERROR;
      case '25001': // active_sql_transaction
      case '25002': // branch_transaction_already_active
      case '25008': // held_cursor_requires_same_isolation_level
        return ErrorCode.TRANSACTION_ERROR;
      case '42000': // syntax_error_or_access_rule_violation
      case '42601': // syntax_error
      case '42501': // insufficient_privilege
        return ErrorCode.QUERY_ERROR;
      default:
        return ErrorCode.DATABASE_ERROR;
    }
  }

  // TypeORM specific errors
  if (error && error.constructor) {
    switch (error.constructor.name) {
      case 'EntityNotFoundError':
        return ErrorCode.RECORD_NOT_FOUND;
      case 'QueryFailedError':
        return ErrorCode.QUERY_ERROR;
      case 'CannotCreateEntityIdMapError':
      case 'OptimisticLockVersionMismatchError':
      case 'OptimisticLockCannotBeUsedError':
      case 'NoVersionOrUpdateDateColumnError':
        return ErrorCode.OPERATION_FAILED;
      case 'ConnectionNotFoundError':
      case 'CannotConnectAlreadyConnectedError':
        return ErrorCode.CONNECTION_ERROR;
      case 'TransactionAlreadyStartedError':
      case 'TransactionNotStartedError':
        return ErrorCode.TRANSACTION_ERROR;
      default:
        return ErrorCode.DATABASE_ERROR;
    }
  }

  // Check error message for common patterns
  if (error && error.message) {
    const message = error.message.toLowerCase();
    if (message.includes('not found') || message.includes('does not exist')) {
      return ErrorCode.RECORD_NOT_FOUND;
    }
    if (message.includes('duplicate') || message.includes('already exists')) {
      return ErrorCode.DUPLICATE_RECORD;
    }
    if (message.includes('constraint') || message.includes('violation')) {
      return ErrorCode.CONSTRAINT_VIOLATION;
    }
    if (message.includes('connection') || message.includes('connect')) {
      return ErrorCode.CONNECTION_ERROR;
    }
    if (message.includes('timeout') || message.includes('timed out')) {
      return ErrorCode.OPERATION_TIMEOUT;
    }
  }

  return ErrorCode.DATABASE_ERROR;
}
