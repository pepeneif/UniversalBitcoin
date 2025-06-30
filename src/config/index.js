/**
 * Universal Bitcoin - Main Configuration
 * 
 * Centralized configuration management for the Universal Bitcoin system.
 * Loads configuration from environment variables with secure defaults.
 * 
 * @author Universal Bitcoin Team
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Main configuration object
 */
const config = {
  // Environment
  environment: process.env.NODE_ENV || 'development',
  
  // Server configuration
  server: {
    port: parseInt(process.env.PORT, 10) || 3000,
    host: process.env.HOST || '0.0.0.0',
    bodyLimit: process.env.BODY_LIMIT || '10mb',
    timeout: parseInt(process.env.SERVER_TIMEOUT, 10) || 30000,
  },
  
  // CORS configuration
  cors: {
    allowedOrigins: process.env.CORS_ORIGINS 
      ? process.env.CORS_ORIGINS.split(',')
      : ['http://localhost:3000', 'http://localhost:3001'],
  },
  
  // Database configuration
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    name: process.env.DB_NAME || 'universal_btc',
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    ssl: process.env.DB_SSL === 'true',
    poolMin: parseInt(process.env.DB_POOL_MIN, 10) || 2,
    poolMax: parseInt(process.env.DB_POOL_MAX, 10) || 20,
    idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT, 10) || 30000,
    connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT, 10) || 2000,
  },
  
  // Redis configuration
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB, 10) || 0,
    maxRetriesPerRequest: 3,
    retryDelayOnFailover: 100,
    connectTimeout: 10000,
    lazyConnect: true,
  },
  
  // Security configuration
  security: {
    jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
    jwtExpiration: process.env.JWT_EXPIRATION || '1h',
    encryptionKey: process.env.ENCRYPTION_KEY || 'your-32-byte-encryption-key-here',
    saltRounds: parseInt(process.env.SALT_ROUNDS, 10) || 12,
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
    lockoutTime: parseInt(process.env.LOCKOUT_TIME, 10) || 900000, // 15 minutes
  },
  
  // Rate limiting configuration
  rateLimit: {
    global: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: parseInt(process.env.GLOBAL_RATE_LIMIT, 10) || 1000,
    },
    perIP: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: parseInt(process.env.IP_RATE_LIMIT, 10) || 100,
    },
    validation: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: parseInt(process.env.VALIDATION_RATE_LIMIT, 10) || 10,
    },
  },
  
  // Bitcoin configuration
  bitcoin: {
    network: process.env.BITCOIN_NETWORK || 'mainnet',
    rpcUrl: process.env.BITCOIN_RPC_URL,
    rpcUser: process.env.BITCOIN_RPC_USER,
    rpcPassword: process.env.BITCOIN_RPC_PASSWORD,
  },
  
  // Guardian Angels configuration
  guardians: {
    threshold: parseInt(process.env.GUARDIAN_THRESHOLD, 10) || 3,
    total: parseInt(process.env.GUARDIAN_TOTAL, 10) || 5,
    timeout: parseInt(process.env.GUARDIAN_TIMEOUT, 10) || 300000, // 5 minutes
    retryAttempts: parseInt(process.env.GUARDIAN_RETRY_ATTEMPTS, 10) || 3,
  },
  
  // Blockchain configurations
  blockchains: {
    ethereum: {
      rpcUrl: process.env.ETHEREUM_RPC_URL || 'https://mainnet.infura.io/v3/your-key',
      paymentAddress: process.env.ETHEREUM_PAYMENT_ADDRESS,
      contractAddress: process.env.ETHEREUM_CONTRACT_ADDRESS,
      minimumPayment: process.env.ETHEREUM_MIN_PAYMENT || '0.001', // ETH
      confirmations: parseInt(process.env.ETHEREUM_CONFIRMATIONS, 10) || 12,
      gasLimit: process.env.ETHEREUM_GAS_LIMIT || '100000',
    },
    solana: {
      rpcUrl: process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
      paymentAddress: process.env.SOLANA_PAYMENT_ADDRESS,
      minimumPayment: process.env.SOLANA_MIN_PAYMENT || '10000000', // 0.01 SOL in lamports
      confirmations: parseInt(process.env.SOLANA_CONFIRMATIONS, 10) || 32,
    },
    polygon: {
      rpcUrl: process.env.POLYGON_RPC_URL || 'https://polygon-rpc.com',
      paymentAddress: process.env.POLYGON_PAYMENT_ADDRESS,
      contractAddress: process.env.POLYGON_CONTRACT_ADDRESS,
      minimumPayment: process.env.POLYGON_MIN_PAYMENT || '0.1', // MATIC
      confirmations: parseInt(process.env.POLYGON_CONFIRMATIONS, 10) || 20,
    },
    arbitrum: {
      rpcUrl: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc',
      paymentAddress: process.env.ARBITRUM_PAYMENT_ADDRESS,
      contractAddress: process.env.ARBITRUM_CONTRACT_ADDRESS,
      minimumPayment: process.env.ARBITRUM_MIN_PAYMENT || '0.001', // ETH
      confirmations: parseInt(process.env.ARBITRUM_CONFIRMATIONS, 10) || 1,
    },
    bsc: {
      rpcUrl: process.env.BSC_RPC_URL || 'https://bsc-dataseed1.binance.org',
      paymentAddress: process.env.BSC_PAYMENT_ADDRESS,
      contractAddress: process.env.BSC_CONTRACT_ADDRESS,
      minimumPayment: process.env.BSC_MIN_PAYMENT || '0.01', // BNB
      confirmations: parseInt(process.env.BSC_CONFIRMATIONS, 10) || 15,
    },
  },
  
  // Monitoring and logging
  monitoring: {
    metricsPort: parseInt(process.env.METRICS_PORT, 10) || 9090,
    logLevel: process.env.LOG_LEVEL || 'info',
    logFormat: process.env.LOG_FORMAT || 'json',
    maxLogFiles: parseInt(process.env.MAX_LOG_FILES, 10) || 14,
    maxLogSize: process.env.MAX_LOG_SIZE || '20m',
  },
  
  // Webhook configuration
  webhooks: {
    secret: process.env.WEBHOOK_SECRET || 'your-webhook-secret',
    timeout: parseInt(process.env.WEBHOOK_TIMEOUT, 10) || 10000,
    retryAttempts: parseInt(process.env.WEBHOOK_RETRY_ATTEMPTS, 10) || 3,
    retryDelay: parseInt(process.env.WEBHOOK_RETRY_DELAY, 10) || 1000,
  },
  
  // Queue configuration
  queue: {
    concurrency: parseInt(process.env.QUEUE_CONCURRENCY, 10) || 5,
    maxJobAttempts: parseInt(process.env.QUEUE_MAX_ATTEMPTS, 10) || 3,
    jobTimeout: parseInt(process.env.QUEUE_JOB_TIMEOUT, 10) || 30000,
    cleanupInterval: parseInt(process.env.QUEUE_CLEANUP_INTERVAL, 10) || 3600000, // 1 hour
  },
  
  // Cache configuration
  cache: {
    ttl: {
      reserves: parseInt(process.env.CACHE_TTL_RESERVES, 10) || 30, // 30 seconds
      validations: parseInt(process.env.CACHE_TTL_VALIDATIONS, 10) || 3600, // 1 hour
      chainConfig: parseInt(process.env.CACHE_TTL_CHAIN_CONFIG, 10) || 300, // 5 minutes
      apiResponse: parseInt(process.env.CACHE_TTL_API_RESPONSE, 10) || 300, // 5 minutes
    },
  },
};

/**
 * Validate required configuration
 */
function validateConfig() {
  const required = [
    'JWT_SECRET',
    'ENCRYPTION_KEY',
    'DB_PASSWORD',
  ];
  
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0 && config.environment === 'production') {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // Validate encryption key length
  if (config.security.encryptionKey.length < 32) {
    throw new Error('ENCRYPTION_KEY must be at least 32 characters long');
  }
  
  // Validate Guardian configuration
  if (config.guardians.threshold > config.guardians.total) {
    throw new Error('Guardian threshold cannot be greater than total guardians');
  }
}

// Validate configuration on load
if (config.environment !== 'test') {
  validateConfig();
}

export default config;