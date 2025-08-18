// src/lib/config/logger.ts
import winston from 'winston';

const isProduction = process.env.NODE_ENV === 'production';

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ level, message, timestamp, correlationId, ...meta }) => {
    const logEntry = {
      timestamp,
      level: level.toUpperCase(),
      message,
      correlationId: correlationId || 'N/A',
      ...meta,
    };
    return JSON.stringify(logEntry);
  })
);

// Create the logger
const logger = winston.createLogger({
  level: isProduction ? 'info' : 'debug',
  format: logFormat,
  defaultMeta: {
    service: 'magic-link-auth',
    environment: process.env.NODE_ENV || 'development',
  },
  transports: [
    // Console transport (always enabled)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    
    // File transport for errors
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 5,
    }),
    
    // File transport for all logs
    new winston.transports.File({
      filename: 'logs/combined.log',
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 10,
    }),
  ],
  exceptionHandlers: [
    new winston.transports.File({ filename: 'logs/exceptions.log' }),
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: 'logs/rejections.log' }),
  ],
});

// Logger with correlation ID support
export class Logger {
  private correlationId?: string;

  constructor(correlationId?: string) {
    this.correlationId = correlationId;
  }

  private log(level: string, message: string, meta?: Record<string, any>) {
    logger.log(level, message, {
      correlationId: this.correlationId,
      ...meta,
    });
  }

  debug(message: string, meta?: Record<string, any>) {
    this.log('debug', message, meta);
  }

  info(message: string, meta?: Record<string, any>) {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: Record<string, any>) {
    this.log('warn', message, meta);
  }

  error(message: string, error?: Error | Record<string, any>, meta?: Record<string, any>) {
    const errorMeta = error instanceof Error 
      ? { error: { message: error.message, stack: error.stack, name: error.name } }
      : { error };
    
    this.log('error', message, { ...errorMeta, ...meta });
  }

  // Method to create a new logger instance with correlation ID
  withCorrelationId(correlationId: string): Logger {
    return new Logger(correlationId);
  }
}

// Export default logger instance
export const defaultLogger = new Logger();

// Export the winston logger for direct access if needed
export { logger as winstonLogger };
