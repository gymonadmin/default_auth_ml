// src/types/auth.ts

// Base API response structure
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ApiError;
  message?: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, any>;
  correlationId?: string;
}

// Pagination metadata
export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  meta: PaginationMeta;
}

// HTTP status codes
export enum HttpStatus {
  OK = 200,
  CREATED = 201,
  NO_CONTENT = 204,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  METHOD_NOT_ALLOWED = 405,
  CONFLICT = 409,
  TOO_MANY_REQUESTS = 429,
  INTERNAL_SERVER_ERROR = 500,
  SERVICE_UNAVAILABLE = 503,
}

// Request metadata
export interface RequestMetadata {
  correlationId: string;
  timestamp: string;
  userAgent?: string;
  ipAddress?: string;
  method: string;
  path: string;
}

// API endpoint responses
export interface SendMagicLinkApiResponse extends ApiResponse {
  data: {
    isNewUser: boolean;
    requiresProfile: boolean;
  };
}

export interface VerifyMagicLinkApiResponse extends ApiResponse {
  data: {
    user: {
      id: string;
      email: string;
      isVerified: boolean;
      profile: {
        id: string;
        firstName: string;
        lastName: string;
        fullName: string;
        initials: string;
      } | null;
    };
    session: {
      id: string;
      expiresAt: string;
    };
    isNewUser: boolean;
    redirectUrl?: string;
  };
}

export interface SessionValidationApiResponse extends ApiResponse {
  data: {
    user: {
      id: string;
      email: string;
      isVerified: boolean;
      profile: {
        id: string;
        firstName: string;
        lastName: string;
        fullName: string;
        initials: string;
      } | null;
    };
    session: {
      id: string;
      expiresAt: string;
      lastAccessedAt?: string;
      isActive: boolean;
    };
  };
}

export interface SignOutApiResponse extends ApiResponse {
  message: string;
}

export interface DeleteAccountApiResponse extends ApiResponse {
  message: string;
}

// Error response types
export interface ValidationErrorResponse extends ApiResponse {
  error: {
    code: 'VALIDATION_ERROR';
    message: string;
    details: {
      issues: Array<{
        path: string[];
        message: string;
        code: string;
      }>;
    };
  };
}

export interface RateLimitErrorResponse extends ApiResponse {
  error: {
    code: 'RATE_LIMIT_EXCEEDED';
    message: string;
    details: {
      retryAfter: number;
      resetTime: string;
    };
  };
}

export interface AuthErrorResponse extends ApiResponse {
  error: {
    code: 'INVALID_TOKEN' | 'TOKEN_EXPIRED' | 'TOKEN_ALREADY_USED' | 'SESSION_EXPIRED' | 'UNAUTHORIZED';
    message: string;
    details?: Record<string, any>;
  };
}

// Client-side fetch wrapper types
export interface FetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: any;
  credentials?: RequestCredentials;
  signal?: AbortSignal;
}

export interface FetchResponse<T = any> {
  data: T | null;
  error: ApiError | null;
  status: number;
  headers: Headers;
  ok: boolean;
}

// Cookie types for session management
export interface SessionCookie {
  name: string;
  value: string;
  expires?: Date;
  maxAge?: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  domain?: string;
}

export interface CookieParseResult {
  token: string | null;
  isValid: boolean;
  error?: string;
}
