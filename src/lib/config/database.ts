// src/lib/config/database.ts
import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { User } from '@/entities/user';
import { Profile } from '@/entities/profile';
import { Session } from '@/entities/session';
import { MagicSigninToken } from '@/entities/magic-signin-token';
import { AuditLog } from '@/entities/audit-log';

// Validate environment variables
const requiredEnvVars = [
  'DB_HOST',
  'DB_PORT', 
  'DB_USERNAME',
  'DB_PASSWORD',
  'DB_NAME'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

// Database connection state management
interface DatabaseState {
  dataSource: DataSource | null;
  isInitialized: boolean;
  isInitializing: boolean;
  connectionAttempts: number;
  lastConnectionError: Error | null;
  healthCheckInterval: NodeJS.Timeout | null;
}

const databaseState: DatabaseState = {
  dataSource: null,
  isInitialized: false,
  isInitializing: false,
  connectionAttempts: 0,
  lastConnectionError: null,
  healthCheckInterval: null,
};

// Configuration constants
const MAX_CONNECTION_ATTEMPTS = 5;
const CONNECTION_RETRY_DELAY = 5000; // 5 seconds
const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
const CONNECTION_TIMEOUT = 10000; // 10 seconds
const QUERY_TIMEOUT = 30000; // 30 seconds

// Create TypeORM DataSource configuration
function createDataSourceConfig(): DataSource {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return new DataSource({
    type: 'postgres',
    host: process.env.DB_HOST!,
    port: parseInt(process.env.DB_PORT!),
    username: process.env.DB_USERNAME!,
    password: process.env.DB_PASSWORD!,
    database: process.env.DB_NAME!,
    
    // Entities
    entities: [User, Profile, Session, MagicSigninToken, AuditLog],
    
    // Migrations
    migrations: ['src/migrations/*.ts'],
    migrationsTableName: 'typeorm_migrations',
    
    // Settings
    synchronize: false, // Never use true in production
    logging: isProduction ? ['error'] : ['query', 'error'],
    
    // Connection pool settings (moved to extra for PostgreSQL)
    extra: {
      // Connection pool size
      max: 20,
      min: 2,
      // Connection timeout
      connectionTimeoutMillis: CONNECTION_TIMEOUT,
      // Idle timeout
      idleTimeoutMillis: 30000,
      // Query timeout
      query_timeout: QUERY_TIMEOUT,
      // Statement timeout
      statement_timeout: QUERY_TIMEOUT,
      // Keep alive
      keepAlive: true,
      keepAliveInitialDelayMillis: 10000,
      // Pool acquire timeout
      acquireTimeoutMillis: CONNECTION_TIMEOUT,
      // SSL settings for production
      ...(isProduction && {
        ssl: {
          rejectUnauthorized: false,
        },
      }),
    },
    
    // TypeORM specific options
    maxQueryExecutionTime: QUERY_TIMEOUT,
  });
}

/**
 * Initialize database connection with retry logic and health monitoring
 */
export async function initializeDatabase(): Promise<DataSource> {
  // Return existing connection if already initialized
  if (databaseState.isInitialized && databaseState.dataSource?.isInitialized) {
    return databaseState.dataSource;
  }

  // Prevent multiple initialization attempts
  if (databaseState.isInitializing) {
    return waitForInitialization();
  }

  databaseState.isInitializing = true;
  
  try {
    // Create new DataSource if needed
    if (!databaseState.dataSource) {
      databaseState.dataSource = createDataSourceConfig();
    }

    // Attempt connection with retry logic
    await connectWithRetry();
    
    databaseState.isInitialized = true;
    databaseState.isInitializing = false;
    databaseState.connectionAttempts = 0;
    databaseState.lastConnectionError = null;

    console.log('✅ Database connection established successfully');
    
    // Start health monitoring
    startHealthMonitoring();
    
    // Set up graceful shutdown handlers
    setupGracefulShutdown();
    
    return databaseState.dataSource;
  } catch (error) {
    databaseState.isInitializing = false;
    databaseState.lastConnectionError = error instanceof Error ? error : new Error(String(error));
    
    console.error('❌ Database connection failed after all attempts:', error);
    throw error;
  }
}

/**
 * Connect with retry logic
 */
async function connectWithRetry(): Promise<void> {
  const dataSource = databaseState.dataSource!;
  
  for (let attempt = 1; attempt <= MAX_CONNECTION_ATTEMPTS; attempt++) {
    try {
      databaseState.connectionAttempts = attempt;
      
      console.log(`🔄 Database connection attempt ${attempt}/${MAX_CONNECTION_ATTEMPTS}`);
      
      if (dataSource.isInitialized) {
        await dataSource.destroy();
      }
      
      await dataSource.initialize();
      
      // Test the connection
      await dataSource.query('SELECT 1');
      
      console.log(`✅ Database connected successfully on attempt ${attempt}`);
      return;
    } catch (error) {
      console.error(`❌ Database connection attempt ${attempt} failed:`, error);
      
      if (attempt === MAX_CONNECTION_ATTEMPTS) {
        throw new Error(`Failed to connect to database after ${MAX_CONNECTION_ATTEMPTS} attempts. Last error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
      
      // Wait before retry
      if (attempt < MAX_CONNECTION_ATTEMPTS) {
        console.log(`⏳ Waiting ${CONNECTION_RETRY_DELAY}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, CONNECTION_RETRY_DELAY));
      }
    }
  }
}

/**
 * Wait for ongoing initialization to complete
 */
async function waitForInitialization(): Promise<DataSource> {
  const maxWait = 30000; // 30 seconds
  const checkInterval = 100; // 100ms
  let waited = 0;
  
  while (databaseState.isInitializing && waited < maxWait) {
    await new Promise(resolve => setTimeout(resolve, checkInterval));
    waited += checkInterval;
  }
  
  if (databaseState.isInitialized && databaseState.dataSource?.isInitialized) {
    return databaseState.dataSource;
  }
  
  throw new Error('Database initialization timeout or failed');
}

/**
 * Start health monitoring
 */
function startHealthMonitoring(): void {
  if (databaseState.healthCheckInterval) {
    clearInterval(databaseState.healthCheckInterval);
  }
  
  databaseState.healthCheckInterval = setInterval(async () => {
    try {
      await checkDatabaseHealth();
    } catch (error) {
      console.error('🚨 Database health check failed:', error);
      // Could implement reconnection logic here
    }
  }, HEALTH_CHECK_INTERVAL);
}

/**
 * Check database health
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    if (!databaseState.dataSource?.isInitialized) {
      return false;
    }
    
    const result = await databaseState.dataSource.query('SELECT 1 as health_check');
    return result && result.length > 0 && result[0].health_check === 1;
  } catch (error) {
    console.error('Database health check error:', error);
    return false;
  }
}

/**
 * Get database connection statistics
 */
export async function getDatabaseStats(): Promise<Record<string, any>> {
  try {
    if (!databaseState.dataSource?.isInitialized) {
      return { status: 'disconnected' };
    }
    
    // Get connection pool stats if available
    const driver = databaseState.dataSource.driver as any;
    const pool = driver.master || driver.pool;
    
    const stats = {
      status: 'connected',
      isInitialized: databaseState.dataSource.isInitialized,
      connectionAttempts: databaseState.connectionAttempts,
      hasError: !!databaseState.lastConnectionError,
      lastError: databaseState.lastConnectionError?.message,
      pool: pool ? {
        totalCount: pool.totalCount || 'unknown',
        idleCount: pool.idleCount || 'unknown',
        waitingCount: pool.waitingCount || 'unknown',
      } : null,
    };
    
    return stats;
  } catch (error) {
    return {
      status: 'error',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Close database connection gracefully
 */
export async function closeDatabase(): Promise<void> {
  try {
    console.log('🔄 Closing database connection...');
    
    // Stop health monitoring
    if (databaseState.healthCheckInterval) {
      clearInterval(databaseState.healthCheckInterval);
      databaseState.healthCheckInterval = null;
    }
    
    // Close connection
    if (databaseState.dataSource?.isInitialized) {
      await databaseState.dataSource.destroy();
    }
    
    // Reset state
    databaseState.dataSource = null;
    databaseState.isInitialized = false;
    databaseState.isInitializing = false;
    databaseState.connectionAttempts = 0;
    databaseState.lastConnectionError = null;
    
    console.log('📴 Database connection closed successfully');
  } catch (error) {
    console.error('❌ Error closing database connection:', error);
    throw error;
  }
}

/**
 * Get current database connection (throws if not initialized)
 */
export function getDataSource(): DataSource {
  if (!databaseState.isInitialized || !databaseState.dataSource?.isInitialized) {
    throw new Error('Database not initialized. Call initializeDatabase() first.');
  }
  return databaseState.dataSource;
}

/**
 * Check if database is connected
 */
export function isDatabaseConnected(): boolean {
  return databaseState.isInitialized && !!databaseState.dataSource?.isInitialized;
}

/**
 * Force reconnect (useful for error recovery)
 */
export async function reconnectDatabase(): Promise<DataSource> {
  console.log('🔄 Force reconnecting to database...');
  
  // Close existing connection
  if (databaseState.dataSource?.isInitialized) {
    await databaseState.dataSource.destroy();
  }
  
  // Reset state
  databaseState.isInitialized = false;
  databaseState.isInitializing = false;
  databaseState.dataSource = null;
  
  // Reinitialize
  return initializeDatabase();
}

/**
 * Setup graceful shutdown handlers
 */
function setupGracefulShutdown(): void {
  const handleShutdown = async (signal: string) => {
    console.log(`🛑 Received ${signal}, shutting down gracefully...`);
    
    try {
      await closeDatabase();
      process.exit(0);
    } catch (error) {
      console.error('Error during graceful shutdown:', error);
      process.exit(1);
    }
  };
  
  // Handle various shutdown signals
  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  process.on('SIGINT', () => handleShutdown('SIGINT'));
  process.on('SIGUSR2', () => handleShutdown('SIGUSR2')); // Nodemon restart
  
  // Handle uncaught exceptions
  process.on('uncaughtException', async (error) => {
    console.error('Uncaught Exception:', error);
    try {
      await closeDatabase();
    } catch (closeError) {
      console.error('Error closing database during uncaught exception:', closeError);
    }
    process.exit(1);
  });
  
  // Handle unhandled promise rejections
  process.on('unhandledRejection', async (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    try {
      await closeDatabase();
    } catch (closeError) {
      console.error('Error closing database during unhandled rejection:', closeError);
    }
    process.exit(1);
  });
}

// Export the original DataSource for migration commands
export const AppDataSource = createDataSourceConfig();

// Export for migration commands and backward compatibility
export default AppDataSource;
