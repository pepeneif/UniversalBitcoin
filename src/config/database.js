/**
 * Universal Bitcoin - Database Configuration
 * 
 * PostgreSQL and TimescaleDB connection management with security best practices.
 * Includes connection pooling, error handling, and migration support.
 * 
 * @author Universal Bitcoin Team
 */

import pkg from 'pg';
import config from './index.js';
import logger from '../utils/logger.util.js';

const { Pool } = pkg;

let pool;

/**
 * Database connection pool configuration
 */
const poolConfig = {
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.username,
  password: config.database.password,
  ssl: config.database.ssl ? { rejectUnauthorized: false } : false,
  
  // Connection pool settings
  min: config.database.poolMin,
  max: config.database.poolMax,
  idleTimeoutMillis: config.database.idleTimeoutMillis,
  connectionTimeoutMillis: config.database.connectionTimeoutMillis,
  
  // Additional security and performance settings
  statement_timeout: 30000, // 30 seconds
  query_timeout: 30000,
  application_name: 'universal-bitcoin',
};

/**
 * Connect to the database
 */
export async function connectDatabase() {
  try {
    pool = new Pool(poolConfig);
    
    // Test the connection
    const client = await pool.connect();
    await client.query('SELECT NOW()');
    client.release();
    
    logger.info('Database connection established successfully', {
      host: config.database.host,
      port: config.database.port,
      database: config.database.name,
      poolMin: config.database.poolMin,
      poolMax: config.database.poolMax
    });
    
    // Set up pool event handlers
    pool.on('connect', (client) => {
      logger.debug('New database client connected', {
        processID: client.processID,
        secretKey: '***' // Don't log actual secret
      });
    });
    
    pool.on('error', (err, client) => {
      logger.error('Database pool error', {
        error: err.message,
        stack: err.stack,
        processID: client?.processID
      });
    });
    
    pool.on('remove', (client) => {
      logger.debug('Database client removed from pool', {
        processID: client.processID
      });
    });
    
    return pool;
  } catch (error) {
    logger.error('Failed to connect to database', {
      error: error.message,
      stack: error.stack,
      host: config.database.host,
      port: config.database.port,
      database: config.database.name
    });
    throw error;
  }
}

/**
 * Get the database pool instance
 */
export function getPool() {
  if (!pool) {
    throw new Error('Database not connected. Call connectDatabase() first.');
  }
  return pool;
}

/**
 * Execute a database query with error handling and logging
 */
export async function query(text, params = []) {
  const start = Date.now();
  
  try {
    const client = await pool.connect();
    
    try {
      const result = await client.query(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Database query executed', {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration,
        rows: result.rowCount
      });
      
      return result;
    } finally {
      client.release();
    }
  } catch (error) {
    const duration = Date.now() - start;
    
    logger.error('Database query failed', {
      query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
      error: error.message,
      duration,
      params: params.length
    });
    
    throw error;
  }
}

/**
 * Execute a transaction with automatic rollback on error
 */
export async function transaction(callback) {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const result = await callback(client);
    
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    
    logger.error('Transaction rolled back', {
      error: error.message,
      stack: error.stack
    });
    
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Check database health
 */
export async function healthCheck() {
  try {
    const result = await query('SELECT 1 as health');
    return {
      status: 'healthy',
      connected: true,
      totalConnections: pool.totalCount,
      idleConnections: pool.idleCount,
      waitingConnections: pool.waitingCount
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      connected: false,
      error: error.message
    };
  }
}

/**
 * Close database connections gracefully
 */
export async function closeDatabase() {
  if (pool) {
    try {
      await pool.end();
      logger.info('Database connections closed successfully');
    } catch (error) {
      logger.error('Error closing database connections', {
        error: error.message
      });
    }
  }
}

/**
 * Database schema validation queries
 */
export const schemas = {
  /**
   * Check if required tables exist
   */
  async validateSchema() {
    const requiredTables = [
      'validations',
      'bitcoin_wallets',
      'chain_tokens',
      'audit_logs',
      'guardian_angels',
      'payment_monitoring'
    ];
    
    const result = await query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name = ANY($1)
    `, [requiredTables]);
    
    const existingTables = result.rows.map(row => row.table_name);
    const missingTables = requiredTables.filter(table => !existingTables.includes(table));
    
    return {
      valid: missingTables.length === 0,
      existingTables,
      missingTables
    };
  },
  
  /**
   * Check if TimescaleDB extension is enabled
   */
  async checkTimescaleDB() {
    try {
      const result = await query(`
        SELECT * FROM pg_extension WHERE extname = 'timescaledb'
      `);
      
      return result.rows.length > 0;
    } catch (error) {
      logger.warn('TimescaleDB extension check failed', {
        error: error.message
      });
      return false;
    }
  }
};

export default {
  connectDatabase,
  getPool,
  query,
  transaction,
  healthCheck,
  closeDatabase,
  schemas
};