// src/lib/api/client.ts
import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios';
import { generateCorrelationId } from '@/lib/utils/correlation-id';
import { ClientLogger } from '@/lib/config/client-logger';

// Create logger instance for API client
const logger = new ClientLogger();

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
    correlationId?: string;
  };
  message?: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, any>;
  correlationId?: string;
}

export class ApiClient {
  private client: AxiosInstance;
  private correlationId: string;

  constructor() {
    this.correlationId = generateCorrelationId();
    this.client = this.createAxiosInstance();
    this.setupInterceptors();

    logger.info('API Client initialized', {
      correlationId: this.correlationId,
      baseURL: this.client.defaults.baseURL,
    });
  }

  private createAxiosInstance(): AxiosInstance {
    const baseURL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
    
    logger.debug('Creating axios instance', {
      baseURL,
      correlationId: this.correlationId,
    });

    return axios.create({
      baseURL,
      timeout: 30000, // 30 seconds
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true, // Include cookies for session management
    });
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Generate new correlation ID for each request
        const requestCorrelationId = generateCorrelationId();
        
        // Add correlation ID to headers
        config.headers['X-Correlation-ID'] = requestCorrelationId;
        
        // Add CSRF token if available (from cookies)
        const csrfToken = this.getCSRFToken();
        if (csrfToken && ['post', 'put', 'patch', 'delete'].includes(config.method?.toLowerCase() || '')) {
          config.headers['X-CSRF-Token'] = csrfToken;
        }

        logger.debug('API Request initiated', {
          method: config.method?.toUpperCase(),
          url: config.url,
          correlationId: requestCorrelationId,
          hasCSRFToken: !!csrfToken,
          hasData: !!config.data,
        });

        return config;
      },
      (error) => {
        logger.error('API Request setup failed', error, {
          correlationId: this.correlationId,
        });
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        const correlationId = response.headers['x-correlation-id'] || 'unknown';
        
        logger.info('API Request successful', {
          method: response.config.method?.toUpperCase(),
          url: response.config.url,
          status: response.status,
          correlationId,
          responseTime: this.getResponseTime(response),
        });

        return response;
      },
      (error: AxiosError) => {
        const correlationId = error.response?.headers['x-correlation-id'] || 'unknown';
        
        logger.error('API Request failed', {
          method: error.config?.method?.toUpperCase(),
          url: error.config?.url,
          status: error.response?.status,
          correlationId,
          errorCode: error.code,
          message: error.message,
          responseData: error.response?.data,
        });

        return Promise.reject(this.handleApiError(error));
      }
    );
  }

  private getCSRFToken(): string | null {
    if (typeof document === 'undefined') return null;
    
    const cookies = document.cookie.split(';').reduce((acc, cookie) => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        acc[name] = decodeURIComponent(value);
      }
      return acc;
    }, {} as Record<string, string>);
    
    return cookies['csrf-token'] || null;
  }

  private getResponseTime(response: AxiosResponse): string {
    const responseTime = response.headers['x-response-time'];
    return responseTime || 'unknown';
  }

  private handleApiError(error: AxiosError): ApiError {
    const correlationId = error.response?.headers['x-correlation-id'] || 'unknown';
    
    // Handle different error scenarios
    if (error.response) {
      // Server responded with error status
      const responseData = error.response.data as any;
      
      return {
        code: responseData?.error?.code || 'API_ERROR',
        message: responseData?.error?.message || responseData?.message || 'An error occurred',
        details: responseData?.error?.details,
        correlationId,
      };
    } else if (error.request) {
      // Network error - no response received
      logger.error('Network error - no response received', {
        correlationId,
        timeout: error.code === 'ECONNABORTED',
        url: error.config?.url,
      });
      
      return {
        code: 'NETWORK_ERROR',
        message: 'Unable to connect to the server. Please check your internet connection.',
        correlationId,
      };
    } else {
      // Request setup error
      return {
        code: 'REQUEST_ERROR', 
        message: error.message || 'Failed to make request',
        correlationId,
      };
    }
  }

  // Generic request method
  async request<T = any>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
    url: string,
    data?: any
  ): Promise<ApiResponse<T>> {
    try {
      const response = await this.client.request<ApiResponse<T>>({
        method,
        url,
        data,
      });

      return response.data;
    } catch (error) {
      // Error is already handled by interceptor
      throw error;
    }
  }

  // Convenience methods
  async get<T = any>(url: string): Promise<ApiResponse<T>> {
    return this.request<T>('GET', url);
  }

  async post<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    return this.request<T>('POST', url, data);
  }

  async put<T = any>(url: string, data?: any): Promise<ApiResponse<T>> {
    return this.request<T>('PUT', url, data);
  }

  async delete<T = any>(url: string): Promise<ApiResponse<T>> {
    return this.request<T>('DELETE', url);
  }

  // Health check method for testing
  async healthCheck(): Promise<boolean> {
    try {
      logger.debug('Performing API health check', {
        correlationId: this.correlationId,
      });

      const response = await this.get('/api/auth/session');
      
      logger.info('API health check completed', {
        success: response.success !== false,
        responseReceived: !!response,
        correlationId: this.correlationId,
      });

      // Consider it healthy if we get any response (even errors are expected for unauthenticated requests)
      return true;
    } catch (error) {
      logger.warn('API health check failed', {
        success: false,
        correlationId: this.correlationId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      // Health check failure is not fatal - API might still be working
      return false;
    }
  }

  // Get current correlation ID
  getCorrelationId(): string {
    return this.correlationId;
  }
}

// Singleton instance
export const apiClient = new ApiClient();

// Export for testing and specific use cases
export default apiClient;
