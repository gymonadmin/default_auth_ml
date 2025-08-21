// src/lib/config/client-logger.ts
/**
 * Browser-compatible logger for client-side logging
 * Uses console API with structured logging format
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlationId?: string;
  context?: Record<string, any>;
  error?: {
    message: string;
    name: string;
    stack?: string;
  };
}

export class ClientLogger {
  private correlationId?: string;
  private isDevelopment: boolean;

  constructor(correlationId?: string) {
    this.correlationId = correlationId;
    this.isDevelopment = process.env.NODE_ENV === 'development';
  }

  private formatLogEntry(
    level: LogLevel,
    message: string,
    context?: Record<string, any>,
    error?: Error
  ): LogEntry {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase() as LogLevel,
      message,
      correlationId: this.correlationId || 'N/A',
    };

    if (context) {
      entry.context = context;
    }

    if (error) {
      entry.error = {
        message: error.message,
        name: error.name,
        stack: this.isDevelopment ? error.stack : undefined,
      };
    }

    return entry;
  }

  private shouldLog(level: LogLevel): boolean {
    if (this.isDevelopment) {
      return true; // Log everything in development
    }

    // In production, only log info, warn, error
    return ['info', 'warn', 'error'].includes(level);
  }

  private log(level: LogLevel, message: string, context?: Record<string, any>, error?: Error): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const logEntry = this.formatLogEntry(level, message, context, error);
    
    // Use appropriate console method
    switch (level) {
      case 'debug':
        console.debug(`[${logEntry.timestamp}] DEBUG:`, logEntry.message, logEntry);
        break;
      case 'info':
        console.info(`[${logEntry.timestamp}] INFO:`, logEntry.message, logEntry);
        break;
      case 'warn':
        console.warn(`[${logEntry.timestamp}] WARN:`, logEntry.message, logEntry);
        break;
      case 'error':
        console.error(`[${logEntry.timestamp}] ERROR:`, logEntry.message, logEntry);
        break;
    }

    // In production, could send logs to external service
    if (!this.isDevelopment && level === 'error') {
      this.sendToExternalService(logEntry);
    }
  }

  private sendToExternalService(logEntry: LogEntry): void {
    // TODO: Implement external logging service integration
    // For now, store in sessionStorage for potential debugging
    try {
      if (typeof window !== 'undefined' && window.sessionStorage) {
        const logs = JSON.parse(sessionStorage.getItem('app_error_logs') || '[]');
        logs.push(logEntry);
        // Keep only last 10 error logs to avoid storage bloat
        if (logs.length > 10) {
          logs.shift();
        }
        sessionStorage.setItem('app_error_logs', JSON.stringify(logs));
      }
      
      // Could send to services like LogRocket, Sentry, etc.
      // fetch('/api/logs', { method: 'POST', body: JSON.stringify(logEntry) });
    } catch (error) {
      // Silently fail to prevent logging errors from breaking the app
      console.warn('Failed to store error log:', error);
    }
  }

  debug(message: string, context?: Record<string, any>): void {
    this.log('debug', message, context);
  }

  info(message: string, context?: Record<string, any>): void {
    this.log('info', message, context);
  }

  warn(message: string, context?: Record<string, any>): void {
    this.log('warn', message, context);
  }

  error(message: string, error?: Error | Record<string, any>, context?: Record<string, any>): void {
    const errorObj = error instanceof Error ? error : undefined;
    const errorContext = error instanceof Error ? context : { ...error, ...context };
    
    this.log('error', message, errorContext, errorObj);
  }

  // Create a new logger instance with correlation ID
  withCorrelationId(correlationId: string): ClientLogger {
    return new ClientLogger(correlationId);
  }

  // Get current correlation ID
  getCorrelationId(): string | undefined {
    return this.correlationId;
  }
}

// Export default logger instance for client-side use
export const clientLogger = new ClientLogger();
