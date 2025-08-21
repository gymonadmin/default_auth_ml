// src/lib/api/types.ts

// Base API response structure
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ApiErrorDetails;
  message?: string;
}

export interface ApiErrorDetails {
  code: string;
  message: string;
  details?: Record<string, any>;
  correlationId?: string;
}

// Auth API types
export interface SendMagicLinkRequest {
  email: string;
  redirectUrl?: string;
}

export interface SendMagicLinkResponse {
  isNewUser: boolean;
  requiresProfile: boolean;
}

export interface VerifyMagicLinkRequest {
  token: string;
  profile?: {
    firstName: string;
    lastName: string;
  };
}

export interface UserProfile {
  id: string;
  firstName: string;
  lastName: string;
  fullName: string;
  initials: string;
}

export interface User {
  id: string;
  email: string;
  isVerified: boolean;
  profile: UserProfile | null;
}

export interface SessionInfo {
  id: string;
  expiresAt: string;
  lastAccessedAt?: string;
  isActive: boolean;
}

export interface VerifyMagicLinkResponse {
  user: User;
  session: SessionInfo;
  isNewUser: boolean;
  redirectUrl?: string;
}

// Session API types
export interface SessionValidationResponse {
  user: User;
  session: SessionInfo;
}

// Error types
export interface ValidationError {
  code: 'VALIDATION_ERROR';
  message: string;
  details: {
    issues: Array<{
      path: string[];
      message: string;
      code: string;
    }>;
  };
}

export interface RateLimitError {
  code: 'RATE_LIMIT_EXCEEDED';
  message: string;
  details: {
    retryAfter: number;
    resetTime: string;
  };
}

export interface AuthError {
  code: 'INVALID_TOKEN' | 'TOKEN_EXPIRED' | 'TOKEN_ALREADY_USED' | 'SESSION_EXPIRED' | 'UNAUTHORIZED';
  message: string;
  details?: Record<string, any>;
}

// Request metadata
export interface RequestContext {
  correlationId: string;
  timestamp: string;
  userAgent?: string;
  ipAddress?: string;
}
