// src/services/rate-limit-service.ts
import Redis from 'ioredis';
import { ServiceError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface RateLimitResult {
  allowed: boolean;
  count: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

export class RateLimitService {
  private redis: Redis;
  private logger: Logger;
  private correlationId: string;

  constructor(correlationId?: string) {
    this.correlationId = correlationId || 'unknown';
    this.logger = new Logger(this.correlationId);
    this.redis = this.createRedisConnection();

    this.logger.debug('RateLimitService initialized', {
      correlationId: this.correlationId,
    });
  }

  /**
   * Create Redis connection
   */
  private createRedisConnection(): Redis {
    try {
      const redisUrl = process.env.REDIS_URL;
      if (!redisUrl) {
        this.logger.error('Missing Redis URL configuration', {
          correlationId: this.correlationId,
        });
        throw new Error('REDIS_URL environment variable is required');
      }

      this.logger.debug('Creating Redis connection', { 
        redisUrl: redisUrl.replace(/\/\/.*@/, '//***@'),
        correlationId: this.correlationId,
      });

      const redis = new Redis(redisUrl, {
        maxRetriesPerRequest: 3,
        connectTimeout: 10000,
        lazyConnect: true,
        // Connection pool settings
        keepAlive: 30000,
        // Error handling
        enableAutoPipelining: true,
      });

      // Handle connection events
      redis.on('connect', () => {
        this.logger.info('Redis connected successfully', {
          correlationId: this.correlationId,
        });
      });

      redis.on('error', (error) => {
        this.logger.error('Redis connection error', {
          correlationId: this.correlationId,
          error: error instanceof Error ? {
            message: error.message,
            name: error.name,
            stack: error.stack,
          } : { message: String(error) },
        });
      });

      redis.on('close', () => {
        this.logger.warn('Redis connection closed', {
          correlationId: this.correlationId,
        });
      });

      redis.on('reconnecting', () => {
        this.logger.info('Redis reconnecting', {
          correlationId: this.correlationId,
        });
      });

      return redis;
    } catch (error) {
      this.logger.error('Failed to create Redis connection', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw new ServiceError(
        ErrorCode.REDIS_ERROR,
        'Failed to initialize rate limiting service',
        500,
        { error: error instanceof Error ? error.message : 'Unknown error' },
        this.correlationId
      );
    }
  }

  /**
   * Check if a key is rate limited using sliding window
   */
  async isRateLimited(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<boolean> {
    try {
      this.logger.debug('Checking rate limit', {
        key: this.maskKey(key),
        limit,
        windowSeconds,
        correlationId: this.correlationId,
      });

      const result = await this.getRateLimitStatus(key, limit, windowSeconds);
      
      this.logger.debug('Rate limit check result', {
        key: this.maskKey(key),
        allowed: result.allowed,
        count: result.count,
        remaining: result.remaining,
        correlationId: this.correlationId,
      });

      return !result.allowed;
    } catch (error) {
      this.logger.error('Rate limit check error', {
        key: this.maskKey(key),
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      
      // In case of Redis error, allow the request (fail open)
      return false;
    }
  }

  /**
   * Increment rate limit counter
   */
  async incrementRateLimit(key: string, windowSeconds: number): Promise<number> {
    try {
      this.logger.debug('Incrementing rate limit', {
        key: this.maskKey(key),
        windowSeconds,
        correlationId: this.correlationId,
      });

      const currentTime = Date.now();
      const windowStart = currentTime - (windowSeconds * 1000);

      // Use Redis transaction to ensure atomicity
      const pipeline = this.redis.pipeline();
      
      // Remove old entries outside the window
      pipeline.zremrangebyscore(key, 0, windowStart);
      
      // Add current request with correlation ID for tracking
      pipeline.zadd(key, currentTime, `${currentTime}-${this.correlationId}-${Math.random()}`);
      
      // Set expiration for the key
      pipeline.expire(key, windowSeconds);
      
      // Get count of requests in window
      pipeline.zcard(key);

      const results = await pipeline.exec();
      
      if (!results) {
        throw new Error('Redis pipeline execution failed');
      }

      // Get the count from the last command (zcard)
      const count = results[results.length - 1][1] as number;

      this.logger.debug('Rate limit incremented', {
        key: this.maskKey(key),
        count,
        correlationId: this.correlationId,
      });

      return count;
    } catch (error) {
      this.logger.error('Rate limit increment error', {
        key: this.maskKey(key),
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      
      throw new ServiceError(
        ErrorCode.REDIS_ERROR,
        'Failed to update rate limit',
        500,
        { key: this.maskKey(key) },
        this.correlationId
      );
    }
  }

  /**
   * Get detailed rate limit status
   */
  async getRateLimitStatus(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<RateLimitResult> {
    try {
      const currentTime = Date.now();
      const windowStart = currentTime - (windowSeconds * 1000);

      // Use Redis transaction for consistency
      const pipeline = this.redis.pipeline();
      
      // Remove old entries
      pipeline.zremrangebyscore(key, 0, windowStart);
      
      // Get current count
      pipeline.zcard(key);
      
      // Get oldest entry to calculate reset time
      pipeline.zrange(key, 0, 0, 'WITHSCORES');

      const results = await pipeline.exec();
      
      if (!results) {
        throw new Error('Redis pipeline execution failed');
      }

      const count = results[1][1] as number;
      const oldestEntry = results[2][1] as string[];
      
      const remaining = Math.max(0, limit - count);
      const allowed = count < limit;
      
      // Calculate reset time (when the oldest entry will expire)
      let resetTime = currentTime + (windowSeconds * 1000);
      if (oldestEntry && oldestEntry.length >= 2) {
        const oldestTimestamp = parseFloat(oldestEntry[1]);
        resetTime = oldestTimestamp + (windowSeconds * 1000);
      }

      const result: RateLimitResult = {
        allowed,
        count,
        remaining,
        resetTime,
        retryAfter: allowed ? undefined : Math.ceil((resetTime - currentTime) / 1000),
      };

      this.logger.debug('Rate limit status retrieved', {
        key: this.maskKey(key),
        result: {
          ...result,
          retryAfter: result.retryAfter,
        },
        correlationId: this.correlationId,
      });

      return result;
    } catch (error) {
      this.logger.error('Rate limit status error', {
        key: this.maskKey(key),
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      
      // Return permissive result on error (fail open)
      return {
        allowed: true,
        count: 0,
        remaining: limit,
        resetTime: Date.now() + (windowSeconds * 1000),
      };
    }
  }

  /**
   * Reset rate limit for a key
   */
  async resetRateLimit(key: string): Promise<void> {
    try {
      this.logger.debug('Resetting rate limit', {
        key: this.maskKey(key),
        correlationId: this.correlationId,
      });

      await this.redis.del(key);

      this.logger.info('Rate limit reset successfully', {
        key: this.maskKey(key),
        correlationId: this.correlationId,
      });
    } catch (error) {
      this.logger.error('Rate limit reset error', {
        key: this.maskKey(key),
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      
      throw new ServiceError(
        ErrorCode.REDIS_ERROR,
        'Failed to reset rate limit',
        500,
        { key: this.maskKey(key) },
        this.correlationId
      );
    }
  }

  /**
   * Get all rate limit keys matching a pattern
   */
  async getRateLimitKeys(pattern: string): Promise<string[]> {
    try {
      this.logger.debug('Getting rate limit keys', { 
        pattern,
        correlationId: this.correlationId,
      });

      const keys = await this.redis.keys(pattern);

      this.logger.debug('Rate limit keys found', {
        pattern,
        count: keys.length,
        correlationId: this.correlationId,
      });

      return keys;
    } catch (error) {
      this.logger.error('Get rate limit keys error', {
        pattern,
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      return [];
    }
  }

  /**
   * Clean up expired rate limit entries
   */
  async cleanupExpired(): Promise<number> {
    try {
      this.logger.debug('Starting rate limit cleanup', {
        correlationId: this.correlationId,
      });

      // Get all rate limit keys
      const keys = await this.redis.keys('*');
      let cleanedCount = 0;

      if (keys.length === 0) {
        return 0;
      }

      const currentTime = Date.now();
      const pipeline = this.redis.pipeline();

      for (const key of keys) {
        // For each key, remove entries older than reasonable time (1 hour)
        const maxAge = 60 * 60 * 1000; // 1 hour in milliseconds
        const cutoff = currentTime - maxAge;
        
        pipeline.zremrangebyscore(key, 0, cutoff);
      }

      const results = await pipeline.exec();
      
      if (results) {
        cleanedCount = results.reduce((total, result) => {
          return total + (result[1] as number || 0);
        }, 0);
      }

      this.logger.info('Rate limit cleanup completed', {
        keysProcessed: keys.length,
        entriesRemoved: cleanedCount,
        correlationId: this.correlationId,
      });

      return cleanedCount;
    } catch (error) {
      this.logger.error('Rate limit cleanup error', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      return 0;
    }
  }

  /**
   * Check Redis connection health
   */
  async healthCheck(): Promise<boolean> {
    try {
      this.logger.debug('Performing Redis health check', {
        correlationId: this.correlationId,
      });

      const result = await this.redis.ping();
      const isHealthy = result === 'PONG';

      this.logger.debug('Redis health check result', { 
        isHealthy,
        correlationId: this.correlationId,
      });

      return isHealthy;
    } catch (error) {
      this.logger.error('Redis health check failed', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      return false;
    }
  }

  /**
   * Get Redis connection info
   */
  async getConnectionInfo(): Promise<Record<string, any>> {
    try {
      const info = await this.redis.info('server');
      const memory = await this.redis.info('memory');
      const stats = await this.redis.info('stats');

      const connectionInfo = {
        server: this.parseRedisInfo(info),
        memory: this.parseRedisInfo(memory),
        stats: this.parseRedisInfo(stats),
        status: this.redis.status,
        correlationId: this.correlationId,
      };

      this.logger.debug('Redis connection info retrieved', {
        status: this.redis.status,
        correlationId: this.correlationId,
      });

      return connectionInfo;
    } catch (error) {
      this.logger.error('Failed to get Redis connection info', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      return { 
        error: 'Failed to get connection info',
        correlationId: this.correlationId,
      };
    }
  }

  /**
   * Parse Redis INFO command output
   */
  private parseRedisInfo(info: string): Record<string, string> {
    const result: Record<string, string> = {};
    
    info.split('\r\n').forEach(line => {
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split(':');
        if (key && value) {
          result[key] = value;
        }
      }
    });

    return result;
  }

  /**
   * Mask sensitive parts of rate limit keys for logging
   */
  private maskKey(key: string): string {
    // Mask email addresses and IP addresses in keys
    return key.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, '***@***.***')
              .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, '***.***.***.***');
  }

  /**
   * Get correlation ID for this service instance
   */
  getCorrelationId(): string {
    return this.correlationId;
  }

  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    try {
      this.logger.debug('Closing Redis connection', {
        correlationId: this.correlationId,
      });
      await this.redis.quit();
      this.logger.info('Redis connection closed', {
        correlationId: this.correlationId,
      });
    } catch (error) {
      this.logger.error('Error closing Redis connection', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
    }
  }

  /**
   * Create rate limit service instance
   */
  static create(correlationId?: string): RateLimitService {
    return new RateLimitService(correlationId);
  }
}
