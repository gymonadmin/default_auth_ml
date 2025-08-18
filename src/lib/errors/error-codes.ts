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
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  TOO_MANY_REQUESTS = 'TOO_MANY_REQUESTS',
  
  // Database errors
  DATABASE_ERROR = 'DATABASE_ERROR',
  RECORD_NOT_FOUND = 'RECORD_NOT_FOUND',
  DUPLICATE_RECORD = 'DUPLICATE_RECORD',
  CONSTRAINT_VIOLATION = 'CONSTRAINT_VIOLATION',
  
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
