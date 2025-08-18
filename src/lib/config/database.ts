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

// Create TypeORM DataSource
export const AppDataSource = new DataSource({
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
  logging: process.env.NODE_ENV === 'development' ? ['query', 'error'] : ['error'],
  
  // Connection pool settings
  extra: {
    // Connection pool size
    max: 20,
    min: 2,
    // Connection timeout
    connectionTimeoutMillis: 10000,
    // Idle timeout
    idleTimeoutMillis: 30000,
    // SSL settings for production
    ...(process.env.NODE_ENV === 'production' && {
      ssl: {
        rejectUnauthorized: false,
      },
    }),
  },
});

// Initialize connection
let isInitialized = false;

export async function initializeDatabase(): Promise<DataSource> {
  if (!isInitialized) {
    try {
      await AppDataSource.initialize();
      isInitialized = true;
      console.log('✅ Database connection established successfully');
    } catch (error) {
      console.error('❌ Database connection failed:', error);
      throw error;
    }
  }
  return AppDataSource;
}

// Close connection
export async function closeDatabase(): Promise<void> {
  if (isInitialized && AppDataSource.isInitialized) {
    await AppDataSource.destroy();
    isInitialized = false;
    console.log('📴 Database connection closed');
  }
}

// Get connection (for use in services)
export function getDataSource(): DataSource {
  if (!isInitialized || !AppDataSource.isInitialized) {
    throw new Error('Database not initialized. Call initializeDatabase() first.');
  }
  return AppDataSource;
}

// Export for migration commands
export default AppDataSource;
