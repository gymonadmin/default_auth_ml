// src/services/email-service.ts

import * as nodemailer from 'nodemailer';
import { ServiceError, ErrorCode } from '@/lib/errors/error-codes';
import { Logger } from '@/lib/config/logger';

export interface MagicLinkEmailData {
  email: string;
  magicLink: string;
  firstName?: string;
  isNewUser: boolean;
  expiresInMinutes: number;
  redirectUrl?: string;
}

export interface EmailServiceConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  from: string;
}

export interface RetryConfig {
  maxRetries: number;
  baseDelay: number; // milliseconds
  maxDelay: number; // milliseconds
}

export class EmailService {
  private transporter: nodemailer.Transporter;
  private config: EmailServiceConfig;
  private retryConfig: RetryConfig;
  private logger: Logger;
  private correlationId: string;

  constructor(correlationId?: string) {
    this.correlationId = correlationId || 'unknown';
    this.logger = new Logger(this.correlationId);
    
    // Validate required environment variables
    this.config = this.validateConfig();
    
    // Configure retry settings
    this.retryConfig = {
      maxRetries: 3,
      baseDelay: 1000, // 1 second
      maxDelay: 10000, // 10 seconds
    };
    
    // Create transporter
    this.transporter = this.createTransporter();

    this.logger.debug('EmailService initialized', {
      correlationId: this.correlationId,
      config: {
        host: this.config.host,
        port: this.config.port,
        user: this.config.user,
        from: this.config.from,
      },
      retryConfig: this.retryConfig,
    });
  }

  /**
   * Validate email service configuration
   */
  private validateConfig(): EmailServiceConfig {
    const requiredEnvVars = {
      SMTP_HOST: process.env.SMTP_HOST,
      SMTP_PORT: process.env.SMTP_PORT,
      SMTP_USER: process.env.SMTP_USER,
      SMTP_PASSWORD: process.env.SMTP_PASSWORD,
      EMAIL_FROM: process.env.EMAIL_FROM,
    };

    for (const [key, value] of Object.entries(requiredEnvVars)) {
      if (!value) {
        this.logger.error('Missing required environment variable', {
          missingVar: key,
          correlationId: this.correlationId,
        });
        throw new ServiceError(
          ErrorCode.CONFIGURATION_ERROR,
          `Missing required environment variable: ${key}`,
          500,
          { missingVar: key },
          this.correlationId
        );
      }
    }

    return {
      host: requiredEnvVars.SMTP_HOST!,
      port: parseInt(requiredEnvVars.SMTP_PORT!, 10),
      user: requiredEnvVars.SMTP_USER!,
      password: requiredEnvVars.SMTP_PASSWORD!,
      from: requiredEnvVars.EMAIL_FROM!,
    };
  }

  /**
   * Create nodemailer transporter
   */
  private createTransporter(): nodemailer.Transporter {
    try {
      this.logger.debug('Creating email transporter', {
        host: this.config.host,
        port: this.config.port,
        user: this.config.user,
        correlationId: this.correlationId,
      });

      const transporter = nodemailer.createTransport({
        host: this.config.host,
        port: this.config.port,
        secure: this.config.port === 465, // true for 465, false for other ports
        auth: {
          user: this.config.user,
          pass: this.config.password,
        },
        // Connection pool settings
        pool: true,
        maxConnections: 5,
        maxMessages: 100,
        // Timeout settings
        connectionTimeout: 10000, // 10 seconds
        greetingTimeout: 5000, // 5 seconds
        socketTimeout: 30000, // 30 seconds
      });

      this.logger.info('Email transporter created successfully', {
        correlationId: this.correlationId,
      });
      return transporter;
    } catch (error) {
      this.logger.error('Failed to create email transporter', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw new ServiceError(
        ErrorCode.EMAIL_SERVICE_ERROR,
        'Failed to initialize email service',
        500,
        { error: error instanceof Error ? error.message : 'Unknown error' },
        this.correlationId
      );
    }
  }

  /**
   * Verify email service connection
   */
  async verifyConnection(): Promise<boolean> {
    try {
      this.logger.debug('Verifying email service connection', {
        correlationId: this.correlationId,
      });
      
      const verified = await this.transporter.verify();
      
      if (verified) {
        this.logger.info('Email service connection verified successfully', {
          correlationId: this.correlationId,
        });
        return true;
      } else {
        this.logger.error('Email service connection verification failed', {
          correlationId: this.correlationId,
        });
        return false;
      }
    } catch (error) {
      this.logger.error('Email service connection verification error', {
        correlationId: this.correlationId,
        error: error instanceof Error ? {
          message: error.message,
          name: error.name,
          stack: error.stack,
        } : { message: String(error) },
      });
      throw new ServiceError(
        ErrorCode.EMAIL_SERVICE_ERROR,
        'Failed to verify email service connection',
        500,
        { error: error instanceof Error ? error.message : 'Unknown error' },
        this.correlationId
      );
    }
  }

  /**
   * Send magic link email with retry logic
   *
   * Throws ServiceError(ErrorCode.EMAIL_SERVICE_ERROR, ...) on failure so callers
   * can reliably detect email delivery problems.
   */
  async sendMagicLinkEmail(data: MagicLinkEmailData): Promise<void> {
    const { subject, html, text } = this.generateMagicLinkEmailContent(data);

    const mailOptions = {
      from: `"${this.getFromName()}" <${this.config.from}>`,
      to: data.email,
      subject,
      text,
      html,
      // Email headers for better deliverability
      headers: {
        'X-Priority': '1',
        'X-MSMail-Priority': 'High',
        'Importance': 'high',
        'X-Correlation-ID': this.correlationId,
      },
      // Tracking
      messageId: this.generateMessageId(),
    };

    await this.sendWithRetry(mailOptions, data.email);
  }

  /**
   * Send email with retry logic
   */
  private async sendWithRetry(mailOptions: any, email: string): Promise<void> {
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= this.retryConfig.maxRetries; attempt++) {
      try {
        this.logger.debug(`Sending email attempt ${attempt}/${this.retryConfig.maxRetries}`, {
          email,
          attempt,
          correlationId: this.correlationId,
        });

        const info = await this.transporter.sendMail(mailOptions);

        this.logger.info('Magic link email sent successfully', {
          email,
          messageId: info.messageId,
          response: info.response,
          attempt,
          correlationId: this.correlationId,
        });

        return; // Success, exit retry loop
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        this.logger.warn(`Email send attempt ${attempt} failed`, {
          email,
          attempt,
          maxRetries: this.retryConfig.maxRetries,
          error: lastError.message,
          correlationId: this.correlationId,
        });

        // Don't retry on the last attempt
        if (attempt === this.retryConfig.maxRetries) {
          break;
        }

        // Wait before retry with exponential backoff
        const delay = Math.min(
          this.retryConfig.baseDelay * Math.pow(2, attempt - 1),
          this.retryConfig.maxDelay
        );

        this.logger.debug(`Waiting ${delay}ms before retry ${attempt + 1}`, {
          email,
          delay,
          correlationId: this.correlationId,
        });

        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    // All retries failed
    this.logger.error('Failed to send magic link email after all retries', {
      email,
      maxRetries: this.retryConfig.maxRetries,
      lastError: lastError?.message,
      correlationId: this.correlationId,
    });

    // Wrap underlying transporter error in a ServiceError so higher layers can react
    throw new ServiceError(
      ErrorCode.EMAIL_SERVICE_ERROR,
      `Failed to send magic link email after ${this.retryConfig.maxRetries} attempts`,
      500,
      { 
        email,
        attempts: this.retryConfig.maxRetries,
        lastError: lastError?.message
      },
      this.correlationId
    );
  }

  /**
   * Generate magic link email content
   */
  private generateMagicLinkEmailContent(data: MagicLinkEmailData): {
    subject: string;
    html: string;
    text: string;
  } {
    const appName = this.getAppName();
    const greeting = data.firstName ? `Hi ${data.firstName}` : 'Hello';
    const actionText = data.isNewUser ? 'Complete your account setup' : 'Sign in to your account';
    const welcomeText = data.isNewUser 
      ? 'Welcome! Click the link below to complete your account setup.'
      : 'Click the link below to sign in to your account.';

    const subject = data.isNewUser 
      ? `Welcome to ${appName} - Complete your account setup`
      : `Sign in to ${appName}`;

    this.logger.debug('Generating email content', {
      subject,
      greeting,
      actionText,
      isNewUser: data.isNewUser,
      correlationId: this.correlationId,
    });

    // HTML email template
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${subject}</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8fafc;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 40px auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        .header {
            background: #1f2937;
            color: white;
            padding: 40px 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }
        .content {
            padding: 40px 30px;
        }
        .greeting {
            font-size: 18px;
            margin-bottom: 20px;
            color: #1f2937;
        }
        .message {
            font-size: 16px;
            margin-bottom: 30px;
            color: #4b5563;
        }
        .button-container {
            text-align: center;
            margin: 40px 0;
        }
        .magic-button {
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 16px 32px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            transition: background-color 0.2s;
        }
        .magic-button:hover {
            background: #2563eb;
        }
        .expiry-notice {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 16px;
            margin: 30px 0;
            color: #92400e;
            font-size: 14px;
        }
        .footer {
            background: #f9fafb;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
        .security-notice {
            margin-top: 20px;
            padding: 20px;
            background: #f3f4f6;
            border-radius: 6px;
            font-size: 14px;
            color: #6b7280;
        }
        .correlation-id {
            margin-top: 20px;
            font-size: 12px;
            color: #9ca3af;
            font-family: monospace;
        }
        @media only screen and (max-width: 600px) {
            .container {
                margin: 20px;
            }
            .header, .content, .footer {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>${appName}</h1>
        </div>
        <div class="content">
            <div class="greeting">${greeting}!</div>
            <div class="message">${welcomeText}</div>
            
            <div class="button-container">
                <a href="${data.magicLink}" class="magic-button">${actionText}</a>
            </div>
            
            <div class="expiry-notice">
                ⏰ This link will expire in ${data.expiresInMinutes} minutes for security purposes.
            </div>
            
            <div class="security-notice">
                <strong>Security Notice:</strong> If you didn't request this email, you can safely ignore it. This link can only be used once and will expire automatically.
            </div>
        </div>
        <div class="footer">
            <p>This email was sent from ${appName}</p>
            <p>If you have trouble clicking the button, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #3b82f6;">${data.magicLink}</p>
            <div class="correlation-id">
                Request ID: ${this.correlationId}
            </div>
        </div>
    </div>
</body>
</html>`;

    // Plain text version
    const text = `
${greeting}!

${welcomeText}

${actionText}: ${data.magicLink}

⏰ This link will expire in ${data.expiresInMinutes} minutes for security purposes.

Security Notice: If you didn't request this email, you can safely ignore it. This link can only be used once and will expire automatically.

---
${appName}

Request ID: ${this.correlationId}
`;

    return { subject, html, text };
  }

  /**
   * Get application name from environment or default
   */
  private getAppName(): string {
    return process.env.NEXT_PUBLIC_APP_NAME || 'Magic Link Auth';
  }

  /**
   * Get sender name for emails
   */
  private getFromName(): string {
    return process.env.EMAIL_FROM_NAME || this.getAppName();
  }

  /**
   * Generate unique message ID for email tracking
   */
  private generateMessageId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);
    const domain = this.config.from.split('@')[1] || 'localhost';
    const messageId = `<${timestamp}.${random}.${this.correlationId}@${domain}>`;
    
    this.logger.debug('Generated message ID', {
      messageId,
      correlationId: this.correlationId,
    });
    
    return messageId;
  }

  /**
   * Get correlation ID for this service instance
   */
  getCorrelationId(): string {
    return this.correlationId;
  }

  /**
   * Close email service connections
   */
  async close(): Promise<void> {
    try {
      this.logger.debug('Closing email service connections', {
        correlationId: this.correlationId,
      });
      this.transporter.close();
      this.logger.info('Email service connections closed', {
        correlationId: this.correlationId,
      });
    } catch (error) {
      this.logger.error('Error closing email service connections', {
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
   * Create email service instance with correlation ID
   */
  static create(correlationId?: string): EmailService {
    return new EmailService(correlationId);
  }
}
