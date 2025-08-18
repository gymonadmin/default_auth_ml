// src/types/session.ts

export interface User {
  id: string;
  email: string;
  isVerified: boolean;
  verifiedAt: string | null;
  createdAt: string;
  updatedAt: string;
  profile: UserProfile | null;
}

export interface UserProfile {
  id: string;
  userId: string;
  firstName: string;
  lastName: string;
  fullName: string;
  initials: string;
  createdAt: string;
  updatedAt: string;
}

export interface Session {
  id: string;
  userId: string;
  expiresAt: string;
  isActive: boolean;
  lastAccessedAt: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  country: string | null;
  city: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SessionData {
  user: User;
  session: Session;
}

export interface SessionValidationResponse {
  success: boolean;
  data?: SessionData;
  error?: {
    code: string;
    message: string;
    correlationId?: string;
  };
}

export interface SessionCookieConfig {
  name: string;
  maxAge: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  domain?: string;
}

export interface SessionState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  session: Session | null;
  error: string | null;
}

export interface SessionContextValue extends SessionState {
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
  clearError: () => void;
}

// Session events for tracking
export enum SessionEvent {
  SESSION_STARTED = 'session_started',
  SESSION_REFRESHED = 'session_refreshed',
  SESSION_EXPIRED = 'session_expired',
  SESSION_ENDED = 'session_ended',
  SESSION_ERROR = 'session_error',
}

export interface SessionEventData {
  event: SessionEvent;
  timestamp: Date;
  sessionId?: string;
  userId?: string;
  details?: Record<string, any>;
}

// Activity tracking for session extension
export interface UserActivity {
  lastActivity: Date;
  isActive: boolean;
  activityCount: number;
}

export interface SessionMetrics {
  duration: number;
  activityCount: number;
  lastActivity: Date;
  ipChanges: number;
  userAgentChanges: number;
}
