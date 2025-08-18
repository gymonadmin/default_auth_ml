// src/lib/validation/schemas.ts
import { z } from 'zod';

// Email validation schema
export const emailSchema = z
  .string()
  .min(1, 'Email is required')
  .max(254, 'Email is too long')
  .email('Please enter a valid email address')
  .transform(email => email.toLowerCase().trim());

// Magic link token schema
export const magicLinkTokenSchema = z
  .string()
  .min(32, 'Invalid token format')
  .regex(/^[A-Za-z0-9_-]+$/, 'Invalid token format');

// Session token schema (hex string)
export const sessionTokenSchema = z
  .string()
  .length(64, 'Invalid session token format')
  .regex(/^[0-9a-f]+$/i, 'Invalid session token format');

// UUID schema
export const uuidSchema = z
  .string()
  .uuid('Invalid UUID format');

// Profile schemas
export const profileNameSchema = z
  .string()
  .min(1, 'Name is required')
  .max(50, 'Name is too long')
  .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters')
  .transform(name => name.trim());

export const createProfileSchema = z.object({
  firstName: profileNameSchema,
  lastName: profileNameSchema,
});

// Auth request schemas
export const sendMagicLinkSchema = z.object({
  email: emailSchema,
  redirectUrl: z
    .string()
    .url('Invalid redirect URL')
    .optional()
    .refine(
      (url) => {
        if (!url) return true;
        const allowedDomains = process.env.ALLOWED_ORIGINS?.split(',') || [];
        return allowedDomains.some(domain => url.startsWith(domain.trim()));
      },
      'Redirect URL not allowed'
    ),
});

export const verifyMagicLinkSchema = z.object({
  token: magicLinkTokenSchema,
  profile: createProfileSchema.optional(),
});

// Pagination schemas
export const paginationSchema = z.object({
  page: z
    .string()
    .transform(val => parseInt(val, 10))
    .refine(val => val > 0, 'Page must be greater than 0')
    .default('1'),
  limit: z
    .string()
    .transform(val => parseInt(val, 10))
    .refine(val => val > 0 && val <= 100, 'Limit must be between 1 and 100')
    .default('10'),
});

// Search schemas
export const searchSchema = z.object({
  query: z
    .string()
    .min(1, 'Search query is required')
    .max(100, 'Search query is too long')
    .transform(query => query.trim()),
  ...paginationSchema.shape,
});

// Audit log schemas
export const auditEventSchema = z.enum([
  'account_confirmed',
  'signin_success',
  'signin_failed',
  'signout',
  'magic_link_sent',
  'magic_link_verified',
  'magic_link_expired',
  'session_created',
  'session_expired',
  'rate_limit_exceeded',
]);

export const createAuditLogSchema = z.object({
  userId: uuidSchema.optional(),
  email: emailSchema,
  event: auditEventSchema,
  context: z.record(z.any()).optional(),
  ipAddress: z.string().ip().optional(),
  userAgent: z.string().max(500).optional(),
  country: z.string().length(2).optional(),
  city: z.string().max(100).optional(),
  success: z.boolean().default(true),
  errorMessage: z.string().optional(),
});

// Request validation schemas
export const correlationIdSchema = z
  .string()
  .uuid('Invalid correlation ID format')
  .optional();

export const requestMetadataSchema = z.object({
  correlationId: correlationIdSchema,
  ipAddress: z.string().ip().optional(),
  userAgent: z.string().max(500).optional(),
  timestamp: z.date().default(() => new Date()),
});

// Environment variable schemas
export const envSchema = z.object({
  // Database
  DATABASE_URL: z.string().url(),
  DB_HOST: z.string().min(1),
  DB_PORT: z.string().transform(val => parseInt(val, 10)),
  DB_USERNAME: z.string().min(1),
  DB_PASSWORD: z.string().min(1),
  DB_NAME: z.string().min(1),
  
  // Redis
  REDIS_URL: z.string().url(),
  
  // Application
  NEXT_PUBLIC_APP_URL: z.string().url(),
  NODE_ENV: z.enum(['development', 'production', 'test']),
  
  // Email
  SMTP_HOST: z.string().min(1),
  SMTP_PORT: z.string().transform(val => parseInt(val, 10)),
  SMTP_USER: z.string().min(1),
  SMTP_PASSWORD: z.string().min(1),
  EMAIL_FROM: z.string().email(),
  
  // Security
  BCRYPT_ROUNDS: z.string().transform(val => parseInt(val, 10)),
  COOKIE_SECRET: z.string().min(32),
  
  // TTL
  MAGIC_LINK_TTL_SECONDS: z.string().transform(val => parseInt(val, 10)),
  SESSION_TTL_SECONDS: z.string().transform(val => parseInt(val, 10)),
  
  // CORS
  ALLOWED_ORIGINS: z.string().min(1),
  ALLOW_CREDENTIALS: z.string().transform(val => val === 'true'),
  
  // Rate Limiting
  RATE_LIMIT_COUNT: z.string().transform(val => parseInt(val, 10)),
  RATE_LIMIT_WINDOW_SECONDS: z.string().transform(val => parseInt(val, 10)),
  RATE_LIMIT_AUTH_COUNT: z.string().transform(val => parseInt(val, 10)),
  RATE_LIMIT_AUTH_WINDOW_SECONDS: z.string().transform(val => parseInt(val, 10)),
  
  // Additional Security
  USER_HEADER_SIGNATURE_SECRET: z.string().min(32),
});

// Type exports
export type SendMagicLinkRequest = z.infer<typeof sendMagicLinkSchema>;
export type VerifyMagicLinkRequest = z.infer<typeof verifyMagicLinkSchema>;
export type CreateProfileRequest = z.infer<typeof createProfileSchema>;
export type PaginationParams = z.infer<typeof paginationSchema>;
export type SearchParams = z.infer<typeof searchSchema>;
export type AuditEvent = z.infer<typeof auditEventSchema>;
export type CreateAuditLogRequest = z.infer<typeof createAuditLogSchema>;
export type RequestMetadata = z.infer<typeof requestMetadataSchema>;
export type EnvConfig = z.infer<typeof envSchema>;
